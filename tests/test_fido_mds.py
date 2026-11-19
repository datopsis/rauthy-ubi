"""Synthetic PKI/JWS fixtures; throwaway private keys exist only in a temp directory."""
import base64
import datetime as dt
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location('fido_mds', Path('scripts/fido_mds.py'))
MDS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MDS)


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=')


class MetadataTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.tmp.cleanup)
        cls.work = Path(cls.tmp.name)
        cls.now = dt.datetime.now(dt.timezone.utc)
        cls.trust = cls.work / 'trust'
        cls.trust.mkdir()
        cls.crls = cls.work / 'crls'
        cls.crls.mkdir()

        def run(*args):
            return subprocess.run(['openssl', *map(str, args)], cwd=cls.work,
                                  check=True, capture_output=True).stdout
        cls.run_ssl = staticmethod(run)
        for name in ('root', 'intermediate', 'leaf', 'expired', 'wrong'):
            run('req', '-new', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=' + name,
                '-keyout', name + '.key', '-out', name + '.csr')
        run('req', '-x509', '-key', 'root.key', '-in', 'root.csr', '-days', '30',
            '-addext', 'basicConstraints=critical,CA:true',
            '-addext', 'keyUsage=critical,keyCertSign,cRLSign', '-out', 'root.pem')
        for ca in ('root', 'intermediate'):
            (cls.work / (ca + '.index')).touch()
            (cls.work / (ca + '.serial')).write_text('1000\n')
            (cls.work / (ca + '.cnf')).write_text(f'''
[ca]
default_ca=issuer
[issuer]
database={ca}.index
serial={ca}.serial
new_certs_dir=.
certificate={ca}.pem
private_key={ca}.key
default_md=sha256
default_days=10
default_crl_days=5
policy=policy
[policy]
commonName=supplied
[intermediate]
basicConstraints=critical,CA:true,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
[leaf]
subjectAltName=DNS:mds.example.test
basicConstraints=critical,CA:false
keyUsage=critical,digitalSignature
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
''')
        run('ca', '-batch', '-config', 'root.cnf', '-extensions', 'intermediate',
            '-in', 'intermediate.csr', '-out', 'intermediate.pem', '-notext')
        run('ca', '-batch', '-config', 'intermediate.cnf', '-extensions', 'leaf',
            '-in', 'leaf.csr', '-out', 'leaf.pem', '-notext')
        run('ca', '-batch', '-config', 'intermediate.cnf', '-extensions', 'leaf',
            '-in', 'expired.csr', '-out', 'expired.pem', '-notext',
            '-startdate', '20200101000000Z', '-enddate', '20210101000000Z')
        for i, ca in enumerate(('intermediate', 'root')):
            run('ca', '-gencrl', '-config', ca + '.cnf', '-out', ca + '.crl')
            (cls.crls / f'{i}.der').write_bytes(run('crl', '-in', ca + '.crl', '-outform', 'DER'))
        (cls.trust / 'root.pem').write_bytes((cls.work / 'root.pem').read_bytes())
        cls.root_hash = hashlib.sha256(run('x509', '-in', 'root.pem', '-outform', 'DER')).hexdigest()
        cls.config = {'root_der_sha256': cls.root_hash, 'signing_hostname': 'mds.example.test', 'crl_urls': ['https://example.test/leaf',
                                                                 'https://example.test/root']}
        (cls.trust / 'trust.json').write_text(json.dumps(cls.config))
        cls.now = dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=1)
        cls.pinned = {'blob_number': 1, 'sha256': '0' * 64, 'next_update': '2000-01-01'}

    def token(self, leaf='leaf', serial=2, date=None, alg='RS256', key=None):
        chain = [base64.b64encode(self.run_ssl('x509', '-in', n + '.pem', '-outform', 'DER')).decode()
                 for n in (leaf, 'intermediate')]
        header = b64(json.dumps({'alg': alg, 'x5c': chain}).encode())
        payload = b64(json.dumps({'no': serial, 'nextUpdate': date or
                                 (self.now.date() + dt.timedelta(days=2)).isoformat()}).encode())
        message = header + b'.' + payload
        (self.work / 'message').write_bytes(message)
        signature = self.run_ssl('dgst', '-sha256', '-sign', (key or leaf) + '.key', 'message')
        return message + b'.' + b64(signature)

    def verify(self, blob, **kw):
        return MDS.verify(blob, self.pinned, self.crls, self.trust, now=kw.get('now', self.now))

    def test_valid_chain_accepted(self):
        self.assertEqual(self.verify(self.token())['blob_number'], 2)

    def test_wrong_root_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            trust = Path(tmp)
            self.run_ssl('req', '-x509', '-key', 'wrong.key', '-in', 'wrong.csr',
                         '-days', '30', '-out', str(trust / 'root.pem'))
            config = dict(self.config, root_der_sha256=hashlib.sha256(
                self.run_ssl('x509', '-in', str(trust / 'root.pem'), '-outform', 'DER')).hexdigest())
            (trust / 'trust.json').write_text(json.dumps(config))
            with self.assertRaisesRegex(ValueError, 'OpenSSL'):
                MDS.verify(self.token(), self.pinned, self.crls, trust, now=self.now)

    def test_tampered_payload_rejected(self):
        parts = self.token().split(b'.')
        parts[1] = b64(b'{"no":9000,"nextUpdate":"2099-01-01"}')
        with self.assertRaisesRegex(ValueError, 'OpenSSL'):
            self.verify(b'.'.join(parts))

    def test_bad_signature_rejected(self):
        with self.assertRaisesRegex(ValueError, 'OpenSSL'):
            self.verify(self.token(key='wrong'))

    def test_expired_certificate_rejected(self):
        with self.assertRaisesRegex(ValueError, 'expired'):
            self.verify(self.token(leaf='expired'))

    def test_rollback_rejected(self):
        with self.assertRaisesRegex(ValueError, 'rollback'):
            MDS.verify(self.token(serial=2), dict(self.pinned, blob_number=3), self.crls,
                       self.trust, now=self.now)

    def test_stale_or_invalid_update_rejected(self):
        for date in (self.now.date().isoformat(), 'not-a-date', '2099-02-30'):
            with self.subTest(date=date), self.assertRaises(ValueError):
                self.verify(self.token(date=date))

    def test_algorithm_confusion_rejected(self):
        for alg in ('none', 'HS256', 'ES256', 'RS512'):
            with self.subTest(alg=alg), self.assertRaisesRegex(ValueError, 'algorithm'):
                self.verify(self.token(alg=alg))

    def test_same_serial_requires_identical_snapshot(self):
        token = self.token()
        pin = self.verify(token)
        self.assertEqual(MDS.verify(token, pin, self.crls, self.trust, now=self.now), pin)
        with self.assertRaisesRegex(ValueError, 'same serial'):
            MDS.verify(self.token(date='2099-01-01'), pin, self.crls, self.trust, now=self.now)

    def test_root_pin_rejected(self):
        with mock.patch.object(MDS.hashlib, 'sha256') as digest:
            digest.return_value.hexdigest.return_value = 'wrong'
            with self.assertRaisesRegex(ValueError, 'root pin'):
                self.verify(self.token())

    def test_wrong_signing_hostname_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            trust = Path(tmp)
            (trust / 'root.pem').write_bytes((self.trust / 'root.pem').read_bytes())
            (trust / 'trust.json').write_text(json.dumps(dict(self.config, signing_hostname='wrong.example.test')))
            with self.assertRaisesRegex(ValueError, 'hostname mismatch'):
                MDS.verify(self.token(), self.pinned, self.crls, trust, now=self.now)

    def test_tampered_crl_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            crls = Path(tmp)
            data = (self.crls / '0.der').read_bytes()
            (crls / '0.der').write_bytes(data[:-1] + bytes([data[-1] ^ 1]))
            (crls / '1.der').write_bytes((self.crls / '1.der').read_bytes())
            with self.assertRaisesRegex(ValueError, 'CRL signature failure'):
                MDS.verify(self.token(), self.pinned, crls, self.trust, now=self.now)

    def test_missing_or_stale_crl_rejected(self):
        with tempfile.TemporaryDirectory() as tmp, self.assertRaises(ValueError):
            MDS.verify(self.token(), self.pinned, Path(tmp), self.trust, now=self.now)
        with self.assertRaisesRegex(ValueError, 'CRL has expired'):
            self.verify(self.token(), now=self.now + dt.timedelta(days=6))

    def test_revoked_certificate_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            crls = Path(tmp)
            self.run_ssl('ca', '-config', 'intermediate.cnf', '-revoke', 'leaf.pem')
            self.run_ssl('ca', '-config', 'intermediate.cnf', '-gencrl', '-out', 'revoked.crl')
            (crls / '0.der').write_bytes(self.run_ssl('crl', '-in', 'revoked.crl', '-outform', 'DER'))
            (crls / '1.der').write_bytes((self.crls / '1.der').read_bytes())
            with self.assertRaisesRegex(ValueError, 'revoked'):
                MDS.verify(self.token(), self.pinned, crls, self.trust, now=self.now)
