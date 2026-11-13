"""Artifact trust boundaries: invalid locks and substituted bytes must fail."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location('artifacts', Path(__file__).parents[1]/'scripts/artifacts.py')
ARTIFACTS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ARTIFACTS)


class ArtifactTests(unittest.TestCase):
    def setUp(self):
        self.lock = json.loads(Path('artifacts/locks/amd64.json').read_text())

    def test_foreign_architecture_or_repository_is_rejected(self):
        for section in ('packages', 'build_packages'):
            for key, value in [('architecture', 'aarch64'), ('repository', 'third-party')]:
                lock = copy.deepcopy(self.lock)
                lock[section][0][key] = value
                with self.assertRaises(AssertionError):
                    ARTIFACTS.validate(lock)

    def test_unpinned_base_or_artifact_is_rejected(self):
        for key, value in [('sha256', ''), ('url', 'http://example.test/insecure'), ('filename', '../escape')]:
            lock = copy.deepcopy(self.lock)
            lock['downloads']['source'][key] = value
            with self.assertRaises(AssertionError):
                ARTIFACTS.validate(lock)
        self.lock['base_images']['runtime']['reference'] = 'ubi9:latest'
        with self.assertRaises(AssertionError):
            ARTIFACTS.validate(self.lock)

    def test_cached_corruption_is_not_trusted(self):
        item = self.lock['downloads']['source']
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory/item['filename']).write_bytes(b'substituted content')
            with self.assertRaises(AssertionError):
                ARTIFACTS.acquire(item, directory)
