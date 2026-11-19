#!/usr/bin/env python3
"""Authenticate the MDS snapshot before build consumption or lock maintenance.

Python stdlib plus OpenSSL (already locked in build_packages). No JWT library or
handwritten cryptography. Unsupported signing profiles fail closed.
"""
import argparse
import base64
import datetime as dt
import difflib
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
import urllib.request

REPO = Path(__file__).resolve().parents[1]
TRUST = REPO / 'artifacts/fido-mds'


def openssl(*args):
    result = subprocess.run(['openssl', *map(str, args)], capture_output=True, check=False)
    if result.returncode:
        raise ValueError('OpenSSL verification failed: ' + result.stderr.decode(errors='replace'))
    return result.stdout


def download(url):
    if not url.startswith('https://'):
        raise ValueError('HTTPS required')
    with urllib.request.urlopen(url, timeout=120) as response:
        if not response.url.startswith('https://'):
            raise ValueError('HTTPS redirect required')
        data = response.read(32 * 1024 * 1024 + 1)
    if len(data) > 32 * 1024 * 1024:
        raise ValueError('download too large')
    return data


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON member: ' + key)
        result[key] = value
    return result


def unbase64url(value):
    if not re.fullmatch(rb'[A-Za-z0-9_-]+', value):
        raise ValueError('invalid compact JWS encoding')
    decoded = base64.urlsafe_b64decode(value + b'=' * (-len(value) % 4))
    if base64.urlsafe_b64encode(decoded).rstrip(b'=') != value:
        raise ValueError('noncanonical compact JWS encoding')
    return decoded


def fetch_crls(directory, trust=TRUST):
    config = json.loads((trust / 'trust.json').read_text())
    directory.mkdir(parents=True, exist_ok=True)
    # Fixed reviewed endpoints, never an untrusted JWT/certificate-provided URL.
    for index, url in enumerate(config['crl_urls']):
        (directory / f'{index}.der').write_bytes(download(url))


def verify(blob, pinned, crl_directory, trust=TRUST, now=None):
    now = now or dt.datetime.now(dt.timezone.utc)
    config = json.loads((trust / 'trust.json').read_text())
    root = trust / 'root.pem'
    der = openssl('x509', '-in', root, '-outform', 'DER')
    if hashlib.sha256(der).hexdigest() != config['root_der_sha256']:
        raise ValueError('root pin mismatch')
    parts = blob.split(b'.')
    if len(parts) != 3:
        raise ValueError('expected compact JWS')
    header = json.loads(unbase64url(parts[0]), object_pairs_hook=unique_object)
    # RS256 only: explicit algorithm/key binding; no none, HS*, x5u or crit fallback.
    if header.get('alg') != 'RS256' or set(header) - {'alg', 'typ', 'x5c'}:
        raise ValueError('unsupported JWS header/algorithm')
    chain = header.get('x5c')
    if not isinstance(chain, list) or not 1 <= len(chain) <= 5:
        raise ValueError('x5c chain required')
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        certs = []
        for index, encoded in enumerate(chain):
            cert = work / f'{index}.pem'
            cert.write_text('-----BEGIN CERTIFICATE-----\n' +
                            base64.b64encode(base64.b64decode(encoded, validate=True)).decode() +
                            '\n-----END CERTIFICATE-----\n')
            certs.append(cert)
        untrusted = work / 'untrusted.pem'
        untrusted.write_bytes(b''.join(c.read_bytes() for c in certs[1:]))
        crls = work / 'crls.pem'
        crls.write_bytes(b''.join(
            openssl('crl', '-inform', 'DER', '-in', crl_directory / f'{i}.der', '-outform', 'PEM')
            for i in range(len(config['crl_urls']))))
        # RFC5280 path, signatures, constraints, key usages, validity and CRLs.
        # Disable system trust entirely. Trust only the pinned self-signed R46.
        command = ['verify', '-trusted', root, '-no-CAfile', '-no-CApath', '-no-CAstore',
                   '-x509_strict', '-auth_level', '2', '-check_ss_sig',
                   '-verify_hostname', config['signing_hostname'],
                   '-attime', str(int(now.timestamp())), '-crl_check_all', '-CRLfile', crls]
        if len(certs) > 1:
            command += ['-untrusted', untrusted]
        openssl(*command, certs[0])
        text = openssl('x509', '-in', certs[0], '-noout', '-ext', 'basicConstraints,keyUsage').decode()
        if 'CA:FALSE' not in text or 'Digital Signature' not in text:
            raise ValueError('leaf must permit digital signatures and not be a CA')
        key = work / 'public.pem'
        key.write_bytes(openssl('x509', '-in', certs[0], '-pubkey', '-noout'))
        # rsa rejects EC keys; dgst uses PKCS#1 v1.5 explicitly for RS256.
        openssl('rsa', '-pubin', '-in', key, '-noout')
        signature = work / 'signature'
        signature.write_bytes(unbase64url(parts[2]))
        message = work / 'message'
        message.write_bytes(parts[0] + b'.' + parts[1])
        openssl('dgst', '-sha256', '-verify', key, '-signature', signature,
                '-sigopt', 'rsa_padding_mode:pkcs1', message)
    payload = json.loads(unbase64url(parts[1]), object_pairs_hook=unique_object)
    serial = payload['no']
    if type(serial) is not int or serial < 1:
        raise ValueError('invalid blob serial')
    if serial < pinned['blob_number']:
        raise ValueError('blob serial rollback')
    date = payload['nextUpdate']
    if not isinstance(date, str) or not re.fullmatch(r'\d{4}-\d{2}-\d{2}', date):
        raise ValueError('invalid nextUpdate')
    # Treat the advertised date as the refresh deadline, at UTC midnight.
    if dt.date.fromisoformat(date) <= now.date():
        raise ValueError('stale nextUpdate')
    evidence = dict(pinned, blob_number=serial, next_update=date,
                    sha256=hashlib.sha256(blob).hexdigest())
    if serial == pinned['blob_number'] and evidence != pinned:
        raise ValueError('same serial has different bytes or nextUpdate')
    return evidence


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['verify', 'refresh', 'report'])
    parser.add_argument('--lock', type=Path, default=REPO / 'artifacts/locks/amd64.json')
    parser.add_argument('--blob', type=Path)
    parser.add_argument('--crl-dir', type=Path, required=True)
    parser.add_argument('--fetch-crls', action='store_true')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    locks = {p: json.loads(p.read_text()) for p in sorted((REPO / 'artifacts/locks').glob('*.json'))}
    pinned = json.loads(args.lock.read_text())['downloads']['fido-mds']
    if args.fetch_crls:
        fetch_crls(args.crl_dir)
    blob = args.blob.read_bytes() if args.blob else download(pinned['url'])
    evidence = verify(blob, pinned, args.crl_dir)
    if args.mode == 'verify' and evidence != pinned:
        raise ValueError('feed differs from lock')
    patch = []
    for path, lock in locks.items():
        old = lock['downloads']['fido-mds']
        if old != pinned:
            raise ValueError('architecture MDS pins disagree')
        lock['downloads']['fido-mds'] = evidence
        updated = json.dumps(lock, indent=2) + '\n'
        if old != evidence:
            patch.extend(difflib.unified_diff(path.read_text().splitlines(True), updated.splitlines(True),
                                             fromfile=str(path.relative_to(REPO)),
                                             tofile=str(path.relative_to(REPO))))
    config = json.loads((TRUST / 'trust.json').read_text())
    crl_evidence = []
    for i, url in enumerate(config['crl_urls']):
        file = args.crl_dir / f'{i}.der'
        dates = openssl('crl', '-inform', 'DER', '-in', file,
                        '-noout', '-lastupdate', '-nextupdate').decode().strip()
        crl_evidence.append({'url': url, 'sha256': hashlib.sha256(file.read_bytes()).hexdigest(),
                             'validity': dates})
    report = {'previous_serial': pinned['blob_number'], 'feed': evidence,
              'root_der_sha256': json.loads((TRUST / 'trust.json').read_text())['root_der_sha256'],
              'verified_at': dt.datetime.now(dt.timezone.utc).isoformat(),
              'verification': 'RS256; pinned R46 RFC5280 chain; signing hostname; validity; full signing-path CRLs; serial; nextUpdate',
              'crls': crl_evidence,
              'patch': ''.join(patch)}
    # All checks, including cross-architecture consistency, precede any lock write.
    if args.mode == 'refresh':
        for path, lock in locks.items():
            path.write_text(json.dumps(lock, indent=2) + '\n')
    if args.output:
        args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
