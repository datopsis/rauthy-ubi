#!/usr/bin/env python3
"""Same native assertions on both CPUs. Never persist tokens or private material."""
import base64
from datetime import datetime, timedelta
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import socket
import ssl
import subprocess
import time
from urllib.parse import urlencode, parse_qs, urlsplit

import argon2
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import jwt
import requests

ARCH = os.environ['ARCHITECTURE']
IMAGE = os.environ['TEST_IMAGE']
WORK = Path('.test-work/functional').resolve()
REPORT = {}
CONTAINERS = []
NETWORK = 'rauthy-ci-' + secrets.token_hex(4)
BASE = 'https://localhost:8443'
ISSUER = BASE + '/auth/v1/'
CALLBACK = 'https://client.example.test/callback'


def run(*args, check=True):
    p = subprocess.run(args, text=True, capture_output=True)
    if check and p.returncode:
        # Docker logs and command arguments may contain credentials. Do not echo them.
        raise RuntimeError(f'{args[0]} {args[1]} failed ({p.returncode})')
    return (p.stdout + (p.stderr if args[:2] == ('docker', 'logs') else '')).strip()


def write(path, value, uid=10001):
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        run('sudo', 'chown', str(os.getuid()), str(path))
    path.write_text(json.dumps(value) if isinstance(value, (list, dict)) else value)
    run('sudo', 'chown', f'{uid}:{uid}', str(path))
    run('sudo', 'chmod', '600', str(path))


def check(name, fn):
    try:
        fn()
        REPORT[name] = 'PASS'
        print(name + ': PASS', flush=True)
    except Exception as error:
        REPORT[name] = 'FAIL: ' + type(error).__name__
        raise
    finally:
        Path(f'functional-{ARCH}.json').write_text(json.dumps(REPORT, indent=2) + '\n')


def eventually(fn, timeout=180):
    deadline = time.monotonic() + timeout
    while True:
        try:
            result = fn()
            if result:
                return result
        except (requests.RequestException, OSError, AssertionError):
            pass
        if time.monotonic() >= deadline:
            raise AssertionError('readiness deadline exceeded')
        time.sleep(2)


def pki():
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'ephemeral test CA')])
    now = datetime.utcnow()
    ca = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(days=1))
          .not_valid_after(now+timedelta(days=2)).add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
          .sign(key, hashes.SHA256()))

    def leaf(hosts, expired=False):
        leafkey = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cert = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hosts[0])]))
                .issuer_name(subject).public_key(leafkey.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now-timedelta(days=3)).not_valid_after(now+timedelta(days=-1 if expired else 1))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName(h) for h in hosts]), False)
                .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), False)
                .sign(key, hashes.SHA256()))
        return cert.public_bytes(serialization.Encoding.PEM).decode(), leafkey.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    return ca.public_bytes(serialization.Encoding.PEM).decode(), leaf


def http():
    session = requests.Session()
    session.trust_env = False
    session.verify = str(WORK/'ca.crt')
    return session


HTTP = http()


def request(method, url, **kwargs):
    return HTTP.request(method, url, timeout=10, allow_redirects=False, **kwargs)


def inspect(name):
    return json.loads(run('docker', 'inspect', name))[0]


def start(name='rauthy', secret_dir=None, pg_host='postgres'):
    full = NETWORK + '-' + name
    CONTAINERS.append(full)
    env = {'PUB_URL': 'localhost:8443', 'RP_ID': 'localhost', 'RP_ORIGIN': BASE,
           'PG_HOST': pg_host, 'PG_USER': 'rauthy', 'PG_DB_NAME': 'rauthy',
           'BOOTSTRAP_ADMIN_EMAIL': 'admin@example.test',
           # These hostile inherited settings MUST NOT override the production profile.
           'LISTEN_SCHEME': 'http_https', 'PG_TLS_NO_VERIFY': 'true', 'TLS_GENERATE_SELF_SIGNED': 'true'}
    args = ['docker', 'run', '-d', '--name', full, '--network', NETWORK, '--read-only',
            '--cap-drop=ALL', '--security-opt=no-new-privileges:true', '--pids-limit=256',
            '--memory=2g', '--cpus=2', '--tmpfs=/tmp:rw,noexec,nosuid,size=64m,uid=10001,gid=10001',
            '-v', f'{secret_dir or WORK/"secrets"}:/run/secrets:ro',
            '-v', f'{WORK/"bootstrap"}:/bootstrap:ro', '-v', f'{WORK/"data"}:/data:rw']
    if name == 'rauthy':
        args += ['-p', '127.0.0.1:8443:8443']
    for k, v in env.items():
        args += ['-e', f'{k}={v}']
    run(*args, IMAGE)
    return full


def ready():
    return request('GET', BASE+'/auth/v1/health').status_code == 200


def machine_token():
    response = request('POST', DISCOVERY['token_endpoint'], data={
        'grant_type': 'client_credentials', 'client_id': 'machine', 'client_secret': CLIENT_SECRET,
        'scope': 'openid profile groups'})
    assert response.status_code == 200
    return response.json()['access_token']


def verify(token, audience):
    header = jwt.get_unverified_header(token)
    assert header['alg'] == 'RS256'
    keys = request('GET', DISCOVERY['jwks_uri']).json()['keys']
    key = next(k for k in keys if k['kid'] == header['kid'])
    claims = jwt.decode(token, jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(key)),
                        algorithms=['RS256'], audience=audience, issuer=ISSUER,
                        options={'require': ['iss', 'aud', 'exp', 'iat', 'sub']})
    assert 0 < claims['exp'] - time.time() <= 125
    return claims


def pkce():
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')
    state, nonce = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
    params = dict(client_id='public-pkce', response_type='code', redirect_uri=CALLBACK,
                  scope='openid profile groups', state=state, nonce=nonce,
                  code_challenge=challenge, code_challenge_method='S256')
    r = request('GET', DISCOVERY['authorization_endpoint']+'?'+urlencode(params))
    assert r.status_code == 200
    csrf = re.search(r'<template id="tpl_csrf_token">(.*?)</template>', r.text)[1]
    headers = {'x-csrf-token': csrf, 'Origin': BASE}
    r = request('POST', BASE+'/auth/v1/pow', headers=headers)
    assert r.status_code == 200
    work = r.text
    difficulty = int(work[2:4])
    assert 0 < difficulty <= 26
    deadline = time.monotonic()+120
    counter = 0
    while True:
        solved = work+str(counter)
        if int.from_bytes(hashlib.sha256(solved.encode()).digest(), 'big') >> (256-difficulty) == 0:
            break
        counter += 1
        if counter % 10000 == 0:
            assert time.monotonic() < deadline
    r = request('POST', DISCOVERY['authorization_endpoint'], headers=headers, json={
        **{k: v for k, v in params.items() if k not in ('scope', 'response_type')},
        'scopes': ['openid', 'profile', 'groups'], 'email': 'alice@example.test',
        'password': USER_PASSWORD, 'pow': solved})
    assert r.status_code == 202
    values = parse_qs(urlsplit(r.headers['Location']).query)
    assert values['state'] == [state]
    r = request('POST', DISCOVERY['token_endpoint'], data={'grant_type': 'authorization_code',
        'client_id': 'public-pkce', 'redirect_uri': CALLBACK, 'code': values['code'][0], 'code_verifier': verifier})
    assert r.status_code == 200
    tokens = r.json()
    assert verify(tokens['access_token'], 'public-pkce')['groups'] == ['lake-readers']
    # ID-token nonce is independently checked after signature verification.
    assert verify(tokens['id_token'], 'public-pkce')['nonce'] == nonce


def tls_negative():
    for port in (8443, 8100, 8200):
        target = '127.0.0.1' if port == 8443 else inspect(SERVER)['NetworkSettings']['Networks'][NETWORK]['IPAddress']
        with socket.create_connection((target, port), timeout=5) as conn:
            conn.sendall(b'GET / HTTP/1.0\r\n\r\n')
            try:
                reply = conn.recv(1024)
            except ConnectionResetError:
                reply = b''
            assert not reply.startswith(b'HTTP/'), 'plaintext listener or redirect'
        for cafile, hostname in [(WORK/'wrong-ca.crt', 'localhost'), (WORK/'ca.crt', 'wrong.example.test')]:
            context = ssl.create_default_context(cafile=str(cafile))
            try:
                with socket.create_connection((target, port), timeout=5) as conn:
                    with context.wrap_socket(conn, server_hostname=hostname):
                        raise AssertionError('invalid TLS peer accepted')
            except ssl.SSLCertVerificationError:
                pass
        context = ssl.create_default_context(cafile=str(WORK/'ca.crt'))
        with socket.create_connection((target, port), timeout=5) as conn:
            with context.wrap_socket(conn, server_hostname='localhost'):
                pass


def hardening():
    obj = inspect(SERVER)
    assert obj['Config']['User'] == '10001:10001'
    assert obj['HostConfig']['ReadonlyRootfs']
    assert obj['HostConfig']['CapDrop'] == ['ALL']
    assert 'no-new-privileges:true' in obj['HostConfig']['SecurityOpt']
    pid = str(obj['State']['Pid'])
    status = run('sudo', 'cat', '/proc/'+pid+'/status')
    assert re.search(r'^Uid:\s+10001\s+10001\s+10001\s+10001$', status, re.M)
    assert re.search(r'^CapEff:\s+0+$', status, re.M)
    assert re.search(r'^NoNewPrivs:\s+1$', status, re.M)
    ports = set()
    for table in ('tcp', 'tcp6'):
        for row in run('sudo', 'cat', f'/proc/{pid}/net/{table}').splitlines()[1:]:
            fields = row.split()
            if fields[3] == '0A' and not fields[1].startswith('0B00007F:'):
                ports.add(int(fields[1].split(':')[1], 16))
    assert ports == {8443, 8100, 8200}, ports
    assert {m['Destination'] for m in obj['Mounts'] if m['RW']} == {'/data', '/tmp'}


def persistence():
    before = verify(machine_token(), 'machine')
    keys = request('GET', DISCOVERY['jwks_uri']).json()
    run('docker', 'restart', '-t', '40', SERVER)
    eventually(ready)
    after = verify(machine_token(), 'machine')
    assert before['sub'] == after['sub']
    assert keys == request('GET', DISCOVERY['jwks_uri']).json()
    pkce()


def postgres_negative():
    # Each new process must connect to PG; no warmed connection pool can mask failure.
    run('docker', 'stop', '-t', '40', SERVER)
    for case in ('ca', 'hostname'):
        dest = WORK/('secrets-'+case)
        run('sudo', 'cp', '-a', str(WORK/'secrets'), str(dest))
        if case == 'ca':
            write(dest/'pg-ca.crt', WRONG_CA)
        bad = start('bad-pg-'+case, dest, 'wrong-postgres' if case == 'hostname' else 'postgres')
        time.sleep(15)
        ip = inspect(bad)['NetworkSettings']['Networks'][NETWORK].get('IPAddress')
        if ip:
            try:
                with socket.create_connection((ip, 8443), timeout=3):
                    raise AssertionError('started despite invalid database TLS')
            except (ConnectionRefusedError, TimeoutError):
                pass
        logs = run('docker', 'logs', bad)
        assert re.search(r'certificate|UnknownIssuer|NotValidForName|invalid peer', logs, re.I)
        run('docker', 'rm', '-f', bad)
    run('docker', 'start', SERVER)
    eventually(ready)


def missing_inputs():
    run('docker', 'stop', '-t', '40', SERVER)
    for file in sorted((WORK/'secrets').iterdir()):
        hidden = file.with_suffix(file.suffix+'.hidden')
        run('sudo', 'mv', str(file), str(hidden))
        try:
            name = start('missing-'+file.name)
            eventually(lambda: not inspect(name)['State']['Running'], 20)
            assert inspect(name)['State']['ExitCode'] != 0
            run('docker', 'rm', '-f', name)
        finally:
            run('sudo', 'mv', str(hidden), str(file))
    run('docker', 'start', SERVER)
    eventually(ready)


def expired_certificate():
    run('docker', 'stop', '-t', '40', SERVER)
    cert, key = LEAF(['localhost'], expired=True)
    old_cert = run('sudo', 'cat', str(WORK/'secrets/server.crt'))
    old_key = run('sudo', 'cat', str(WORK/'secrets/server.key'))
    write(WORK/'secrets/server.crt', cert)
    write(WORK/'secrets/server.key', key)
    try:
        run('docker', 'start', SERVER)
        def refused():
            try:
                request('GET', BASE+'/auth/v1/health')
            except requests.exceptions.SSLError as error:
                assert 'expired' in str(error).lower()
                return True
            return False
        eventually(refused)
    finally:
        run('docker', 'stop', '-t', '40', SERVER)
        write(WORK/'secrets/server.crt', old_cert+'\n')
        write(WORK/'secrets/server.key', old_key+'\n')
        run('docker', 'start', SERVER)
        eventually(ready)


try:
    WORK.mkdir(parents=True)
    for directory in ('data', 'pg-data', 'secrets', 'bootstrap', 'pg-tls'):
        (WORK/directory).mkdir()
    CA, LEAF = pki()
    WRONG_CA, _ = pki()
    (WORK/'ca.crt').write_text(CA)
    (WORK/'wrong-ca.crt').write_text(WRONG_CA)
    PG_PASSWORD, CLIENT_SECRET, USER_PASSWORD = [secrets.token_hex(32) for _ in range(3)]
    cert, key = LEAF(['localhost'])
    for name, value in {'server.crt': cert, 'server.key': key, 'cluster.crt': cert, 'cluster.key': key, 'ca.crt': CA, 'pg-ca.crt': CA,
                        'pg-password': PG_PASSWORD, 'raft-secret': secrets.token_hex(32),
                        'api-secret': secrets.token_hex(32), 'encryption-key-active': 'ci',
                        'encryption-keys': 'ci/'+base64.b64encode(secrets.token_bytes(32)).decode(),
                        'admin-password-argon2id': argon2.PasswordHasher().hash(secrets.token_hex(32))}.items():
        write(WORK/'secrets'/name, value)
    cert, key = LEAF(['postgres'])
    write(WORK/'pg-tls/server.crt', cert, 26)
    write(WORK/'pg-tls/server.key', key, 26)
    write(WORK/'pg-tls/password', PG_PASSWORD, 26)
    write(WORK/'bootstrap/groups.json', [{'name': 'lake-readers'}])
    write(WORK/'bootstrap/users.json', [{'email': 'alice@example.test', 'password': {'Plain': USER_PASSWORD},
          'roles': ['user'], 'groups': ['lake-readers'], 'enabled': True, 'email_verified': True}])
    clients = []
    for client in ('machine', 'public-pkce'):
        clients.append(dict(id=client, name=client, secret={'Plain': CLIENT_SECRET} if client == 'machine' else None,
            redirect_uris=[CALLBACK], enabled=True,
            flows_enabled=['client_credentials'] if client == 'machine' else ['authorization_code'],
            access_token_alg='RS256', id_token_alg='RS256', auth_code_lifetime=60, access_token_lifetime=120,
            scopes=['openid', 'profile', 'groups'], default_scopes=['openid', 'profile', 'groups'],
            challenges=['S256'], force_mfa=False))
    write(WORK/'bootstrap/clients.json', clients)
    run('sudo', 'chown', '-R', '10001:10001', str(WORK/'data'))
    run('sudo', 'chown', '-R', '26:0', str(WORK/'pg-data'))
    run('docker', 'network', 'create', NETWORK)
    pg = NETWORK+'-postgres'
    CONTAINERS.append(pg)
    run('docker', 'run', '-d', '--name', pg, '--network', NETWORK, '--network-alias', 'postgres',
        '--network-alias', 'wrong-postgres', '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges:true',
        '--tmpfs=/tmp:rw,noexec,nosuid,size=128m,uid=26,gid=0',
        '-v', f'{WORK/"pg-data"}:/var/lib/pgsql:rw', '-v', f'{WORK/"pg-tls"}:/tls:ro',
        '-e', 'POSTGRES_USER=rauthy', '-e', 'POSTGRES_DB=rauthy', '-e', 'POSTGRES_PASSWORD_FILE=/tls/password',
        '-e', 'POSTGRESQL_TLS_CERT_FILE=/tls/server.crt', '-e', 'POSTGRESQL_TLS_KEY_FILE=/tls/server.key', 'postgresql-ubi:test')
    eventually(lambda: 'ready to accept connections' in run('docker', 'logs', pg))
    SERVER = start()
    check('HTTPS readiness', lambda: eventually(ready))
    def bootstrap_admin():
        count = run('docker', 'exec', pg, 'psql', '-U', 'rauthy', '-d', 'rauthy', '-Atc',
                    "SELECT count(*) FROM users WHERE email='admin@example.test' AND roles LIKE '%admin%'")
        assert count == '1'
    check('declarative administrator bootstrap persisted in PostgreSQL', bootstrap_admin)
    def discovery():
        global DISCOVERY
        r = request('GET', BASE+'/.well-known/openid-configuration')
        assert r.status_code == 200
        DISCOVERY = r.json()
        assert DISCOVERY['issuer'] == ISSUER
        assert request('GET', DISCOVERY['jwks_uri']).json()['keys']
    check('OIDC discovery and JWKS over verified TLS', discovery)
    check('confidential client credentials, iss aud exp and JWKS signature', lambda: verify(machine_token(), 'machine'))
    check('public S256 PKCE and groups in signed access token', pkce)
    check('plaintext, wrong CA and wrong hostname refused; all listeners TLS', tls_negative)
    check('UID, read-only root, capabilities, no-new-privileges and writable mounts', hardening)
    check('PostgreSQL restart persistence', persistence)
    check('PostgreSQL verify-full semantics: wrong CA and hostname refused', postgres_negative)
    check('missing TLS and required secrets fail closed', missing_inputs)
    check('expired server certificate refused with restored positive control', expired_certificate)
finally:
    # Never upload raw service logs, bootstrap material, keys or tokens.
    for container in CONTAINERS:
        run('docker', 'rm', '-f', container, check=False)
    run('docker', 'network', 'rm', NETWORK, check=False)
    run('sudo', 'rm', '-rf', str(WORK), check=False)
