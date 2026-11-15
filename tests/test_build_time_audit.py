"""Build-time audit: attribution, separation from the image gate, and fail-closed inputs."""
import copy
import importlib.util
from pathlib import Path
import unittest


def module(name, file):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).parents[1]/'scripts'/file)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


AUDIT = module('build_time_audit', 'build-time-audit.py')
TRACKING = module('build_time_tracking', 'build-time-tracking.py')
FILLER_CARGO = [{'Name': f'crate{i}', 'Version': '1.0.0'} for i in range(500)]
FILLER_NPM = [{'Name': f'pkg{i}', 'Version': '1.0.0'} for i in range(100)]


def package(name, kind='lib'):
    return {'id': name, 'name': name, 'version': '1.0.0', 'targets': [{'kind': [kind]}]}


def edge(child, kind=None):
    return {'pkg': child, 'dep_kinds': [{'kind': kind, 'target': None}]}


def metadata(root):
    graph = {root: [edge('linked'), edge('swagger'), edge('derive'), edge('tester', 'dev')],
             'swagger': [edge('zip', 'build')], 'derive': [edge('syn')], 'zip': [edge('flate')],
             'linked': [], 'syn': [], 'flate': [], 'tester': []}
    packages = [package(n, 'proc-macro' if n == 'derive' else 'lib') for n in graph]
    return {'packages': packages, 'workspace_members': [root],
            'resolve': {'nodes': [{'id': n, 'deps': d} for n, d in graph.items()]}}


def vulnerability(name, severity='HIGH', identifier=None):
    return {'VulnerabilityID': identifier or f'CVE-{name}', 'PkgName': name, 'InstalledVersion': '1.0.0',
            'FixedVersion': '2.0.0', 'Severity': severity}


def image_report(extra=()):
    return {'Results': [{'Type': 'rustbinary', 'Packages': FILLER_CARGO + [{'Name': n, 'Version': '1.0.0'}
                                                                          for n in extra]},
                        {'Type': 'node-pkg', 'Packages': FILLER_NPM}]}


class BuildTimeAuditTests(unittest.TestCase):
    def setUp(self):
        names = ['linked', 'swagger', 'derive', 'zip', 'syn', 'flate', 'tester', 'windows', 'wasm-only']
        self.lock = {'Results': [
            {'Type': 'cargo', 'Packages': FILLER_CARGO + [{'Name': n, 'Version': '1.0.0'} for n in names],
             'Vulnerabilities': [vulnerability(n) for n in ('linked', 'zip', 'syn', 'tester', 'windows')]
             + [vulnerability('flate', 'MEDIUM')]},
            {'Type': 'npm', 'Packages': FILLER_NPM + [{'Name': '@esbuild/darwin-arm64', 'Version': '1.0.0'}],
             'Vulnerabilities': [vulnerability('@esbuild/darwin-arm64', 'CRITICAL')]}]}
        self.images = {'amd64': image_report(['linked']), 'arm64': image_report(['linked'])}
        self.metadata = {('amd64', 'rauthy', 'server'): metadata('rauthy'),
                         ('arm64', 'rauthy', 'server'): metadata('rauthy'),
                         ('wasm32', 'rauthy-wasm-modules', 'wasm'): metadata('rauthy-wasm-modules')}
        self.package_lock = {'packages': {'node_modules/@esbuild/darwin-arm64': {
            'version': '1.0.0', 'dev': True, 'os': ['darwin'], 'cpu': ['arm64']}}}

    def run_audit(self):
        return AUDIT.audit(self.lock, self.images, self.metadata, self.package_lock)

    def test_shipped_findings_stay_with_the_image_gate(self):
        summary = self.run_audit()
        self.assertNotIn('linked', {f['package'] for f in summary['build_time_only']})
        self.assertEqual(summary['shipped_high_critical_covered_by_image_gate'], 1)

    def test_only_high_and_critical_are_reported(self):
        self.assertNotIn('flate', {f['package'] for f in self.run_audit()['build_time_only']})

    def test_build_steps_are_attributed(self):
        rows = {f['package']: f for f in self.run_audit()['build_time_only']}
        self.assertEqual(rows['@esbuild/darwin-arm64']['severity'], 'CRITICAL')
        self.assertIn('build-dependency of swagger', ' '.join(rows['zip']['build_steps']))
        self.assertIn('[amd64, arm64]', ' '.join(rows['zip']['build_steps']))
        self.assertIn('proc-macro derive', ' '.join(rows['syn']['build_steps']))
        self.assertIn('dev-dependency of rauthy', ' '.join(rows['tester']['build_steps']))
        self.assertIn('not compiled', rows['windows']['build_steps'][0])
        self.assertIn('os=darwin', rows['@esbuild/darwin-arm64']['build_steps'][0])
        self.assertEqual(rows['zip']['fixed_version'], '2.0.0')

    def test_fingerprint_ignores_order_and_tracks_changes(self):
        first = self.run_audit()['fingerprint']
        self.lock['Results'][0]['Vulnerabilities'].reverse()
        self.assertEqual(self.run_audit()['fingerprint'], first)
        self.lock['Results'][0]['Vulnerabilities'].append(vulnerability('swagger', 'HIGH', 'CVE-new'))
        self.assertNotEqual(self.run_audit()['fingerprint'], first)

    def test_missing_scan_coverage_fails_closed(self):
        for index, trivy_type in [(0, 'cargo'), (1, 'npm')]:
            lock = copy.deepcopy(self.lock)
            lock['Results'][index]['Packages'] = []
            with self.assertRaises(AUDIT.AuditError, msg=trivy_type):
                AUDIT.audit(lock, self.images, self.metadata, self.package_lock)
        self.images['arm64'] = {'Results': []}
        with self.assertRaises(AUDIT.AuditError):
            self.run_audit()

    def test_missing_workspace_root_fails_closed(self):
        del self.metadata[('wasm32', 'rauthy-wasm-modules', 'wasm')]
        self.metadata[('wasm32', 'rauthy-wasm-modules', 'wasm')] = metadata('renamed')
        with self.assertRaises(AUDIT.AuditError):
            self.run_audit()

    def test_tracking_comments_only_when_the_set_changes(self):
        marker = '<!-- build-time-audit fingerprint={} -->'
        old, new = 'a' * 64, 'b' * 64
        self.assertEqual(TRACKING.decide(None, [], new), 'create')
        self.assertEqual(TRACKING.decide(7, [marker.format(old), marker.format(new)], new), 'unchanged')
        self.assertEqual(TRACKING.decide(7, [marker.format(new), marker.format(old)], new), 'comment')
        self.assertEqual(TRACKING.decide(7, ['no marker'], new), 'comment')


if __name__ == '__main__':
    unittest.main()
