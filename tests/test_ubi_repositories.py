"""Exercise native RPM ordering and fail-closed repoquery outcomes."""
import subprocess
import sys
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from ubi_repositories import UbiRepositories, REPOSITORIES, compare_evr, parse_evr  # noqa: E402


class RPMVersionTests(unittest.TestCase):
    def test_native_epoch_release_and_numeric_ordering(self):
        for left, right, expected in [
            ('2.37.4-28.el9_9', '2.37.4-28.el9_9.1', -1),
            ('0:2.37.4-28.el9_9.1', '2.37.4-28.el9_9', 1),
            ('2.37.4-28.el9_9', '0:2.37.4-28.el9_9', 0),
            ('1:1.0-1', '0:99.0-99', 1),
            ('1.0-10', '1.0-9', 1),
            ('1.0~rc1-1', '1.0-1', -1),
            ('1.0^git1-1', '1.0-1', 1),
        ]:
            with self.subTest(left=left, right=right):
                self.assertEqual(compare_evr(left, right), expected)

    def test_rejects_ambiguous_or_missing_versions(self):
        for version in ('', '1.0', '>=1.0-1', 'x:1-1', '1-1 || 2-1', '1-1.aarch64 /tmp/x'):
            with self.subTest(version=version), self.assertRaises(ValueError):
                parse_evr(version)


class RepositoryQueryTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.config = ''.join(
            f'[{repo}]\nenabled=1\ngpgcheck=1\nbaseurl=https://cdn-ubi.redhat.com/content/public/'
            f'ubi/dist/ubi9/9/$basearch/{repo[6:-5]}/os\n'
            for repo in sorted(REPOSITORIES))
        (self.root / 'ubi.repo').write_text(self.config)

    def repositories(self, arch='amd64'):
        repos = UbiRepositories(self.root, arch)
        self.addCleanup(repos.close)
        return repos

    def test_available_equal_and_later_block_older_and_absent_defer(self):
        for version, release, expected in [('1.0', '2', True), ('1.0', '3', True), ('1.0', '1', False)]:
            repos = self.repositories()
            result = subprocess.CompletedProcess([], 0,
                stdout=f'example\t0\t{version}\t{release}\tx86_64\tubi-9-baseos-rpms\n')
            # Mock the network query only; compare with real librpm.
            with patch('ubi_repositories.subprocess.run', return_value=result):
                candidates = repos.query('example')
            self.assertEqual(candidates[0]['evr'], f'0:{version}-{release}')
            self.assertEqual(repos.available('example', ['1.0-2'])[0], expected)
        with patch('ubi_repositories.subprocess.run', return_value=subprocess.CompletedProcess([], 0, stdout='')):
            self.assertEqual(self.repositories().available('absent', ['1.0-2']), (False, []))

    def test_query_errors_timeouts_and_bad_output_never_defer(self):
        for error in (subprocess.CalledProcessError(1, 'dnf'), subprocess.TimeoutExpired('dnf', 120)):
            repos = self.repositories()
            with patch('ubi_repositories.subprocess.run', side_effect=error), self.assertRaises(type(error)):
                repos.available('example', ['1.0-2'])
        for output in ('garbage', 'example\t0\t1.0\t2\taarch64\tubi-9-baseos-rpms',
                       'example\t0\t1.0\t2\tx86_64\tother'):
            with patch('ubi_repositories.subprocess.run', return_value=subprocess.CompletedProcess([], 0, stdout=output)):
                with self.assertRaises(ValueError):
                    self.repositories().available('example', ['1.0-2'])

    def test_missing_disabled_or_foreign_repo_blocks(self):
        for config in ('', self.config.replace('enabled=1', 'enabled=0', 1),
                       self.config.replace('https://cdn-ubi.redhat.com', 'https://example.invalid')):
            (self.root / 'ubi.repo').write_text(config)
            with self.assertRaises(ValueError):
                self.repositories().available('example', ['1.0-2'])

    def test_native_architecture_refresh_and_no_skip_are_enforced(self):
        with patch('ubi_repositories.subprocess.run', return_value=subprocess.CompletedProcess([], 0, stdout='')) as run:
            self.repositories('arm64').available('example', ['1.0-2'])
        args = run.call_args.args[0]
        self.assertIn('--archlist=aarch64,noarch', args)
        self.assertIn('--refresh', args)
        self.assertIn('--setopt=*.skip_if_unavailable=False', args)
        self.assertEqual(run.call_args.kwargs['timeout'], 120)

    def test_all_vendor_alternatives_must_parse_even_when_package_absent(self):
        with self.assertRaises(ValueError):
            self.repositories().available('example', ['1.0-2', 'invalid'])


if __name__ == '__main__':
    unittest.main()
