#!/usr/bin/env python3
"""Query fresh native UBI metadata; only a successful negative result defers."""
from __future__ import annotations

import configparser
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

REPOSITORIES = {'ubi-9-baseos-rpms', 'ubi-9-appstream-rpms', 'ubi-9-codeready-builder-rpms'}
ARCHITECTURES = {'amd64': 'x86_64', 'arm64': 'aarch64'}
EVR = re.compile(r'(?:(\d+):)?([A-Za-z0-9][A-Za-z0-9._+~^]*)-([A-Za-z0-9][A-Za-z0-9._+~^]*)')


def parse_evr(value: str) -> tuple[str, str, str]:
    match = EVR.fullmatch(value)
    if not match:
        raise ValueError(f'invalid RPM epoch:version-release: {value!r}')
    epoch, version, release = match.groups()
    return epoch or '0', version, release


def compare_evr(left: str, right: str) -> int:
    # Use the distribution's librpm, including its epoch, tilde and caret rules.
    # The system interpreter also works when the caller runs in a tooling venv.
    labels = [parse_evr(left), parse_evr(right)]
    result = subprocess.run(
        ['/usr/bin/python3', '-c',
         'import json,rpm,sys; a,b=json.load(sys.stdin); print(rpm.labelCompare(tuple(a),tuple(b)))'],
        input=json.dumps(labels), text=True, capture_output=True, check=True, timeout=10,
    )
    comparison = int(result.stdout.strip())
    if comparison not in (-1, 0, 1):
        raise ValueError('invalid librpm comparison result')
    return comparison


class UbiRepositories:
    def __init__(self, directory: Path, architecture: str):
        self.architecture = ARCHITECTURES[architecture]
        self.directory = directory
        self.cache = tempfile.TemporaryDirectory(prefix='ubi-gate-')
        self.results = {}
        self.evidence = {}
        self.error = None
        try:
            files = sorted(directory.glob('*.repo'))
            if not files:
                raise ValueError('missing pinned UBI repository files')
            config = configparser.ConfigParser(interpolation=None)
            for path in files:
                config.read_string(path.read_text())
            enabled = {section for section in config.sections()
                       if config.getboolean(section, 'enabled', fallback=True)}
            if enabled != REPOSITORIES:
                raise ValueError(f'missing or unexpected enabled UBI repositories: {sorted(enabled)}')
            for section in enabled:
                options = config[section]
                component = section.removeprefix('ubi-9-').removesuffix('-rpms')
                expected = ('https://cdn-ubi.redhat.com/content/public/ubi/dist/ubi9/9/'
                            f'$basearch/{component}/os')
                if options.get('baseurl', '').rstrip('/') != expected:
                    raise ValueError(f'unexpected repository URL: {section}')
                if not options.getboolean('gpgcheck') or options.get('mirrorlist') or options.get('metalink'):
                    raise ValueError(f'invalid repository verification/configuration: {section}')
            self.evidence = {
                'files': {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in files},
                'repositories': sorted(enabled),
                'architecture': self.architecture,
            }
        except Exception as error:
            self.error = error

    def close(self):
        self.cache.cleanup()

    def query(self, name: str) -> list[dict]:
        if self.error:
            raise ValueError(f'UBI repository configuration failed: {self.error}')
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9+_.-]*', name):
            raise ValueError('invalid RPM package name')
        if name not in self.results:
            try:
                result = subprocess.run([
                    'dnf', '-q', '--noplugins', '--refresh', '--releasever=9',
                    f'--setopt=reposdir={self.directory}', f'--setopt=cachedir={self.cache.name}',
                    '--setopt=skip_if_unavailable=False', '--setopt=*.skip_if_unavailable=False',
                    '--setopt=*.sslverify=True', '--setopt=*.metadata_expire=0',
                    '--setopt=*.timeout=30', '--setopt=*.retries=1',
                    'repoquery', '--available', f'--archlist={self.architecture},noarch',
                    '--qf', '%{name}\t%{epoch}\t%{version}\t%{release}\t%{arch}\t%{repoid}', name,
                ], text=True, capture_output=True, check=True, timeout=120)
                candidates = []
                for line in result.stdout.splitlines():
                    package, epoch, version, release, arch, repository = line.split('\t')
                    if package != name or arch not in (self.architecture, 'noarch') or repository not in REPOSITORIES:
                        raise ValueError(f'unexpected repoquery record: {line!r}')
                    evr = f'{epoch}:{version}-{release}'
                    parse_evr(evr)
                    candidates.append({'evr': evr, 'architecture': arch, 'repository': repository})
                self.results[name] = candidates
            except Exception as error:
                self.results[name] = error
        result = self.results[name]
        if isinstance(result, Exception):
            raise result
        return result

    def available(self, name: str, versions: list[str]) -> tuple[bool, list[dict]]:
        if not versions:
            raise ValueError('scanner marks fixed without a fixed version')
        # Validate every alternative before allowing any deferral.
        for version in versions:
            parse_evr(version)
        candidates = self.query(name)
        comparisons = [compare_evr(candidate['evr'], version)
                       for candidate in candidates for version in versions]
        return any(value >= 0 for value in comparisons), candidates
