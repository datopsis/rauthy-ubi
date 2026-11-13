#!/usr/bin/env python3
"""Acquire only checksum-pinned inputs; validate before any build."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import tarfile
import urllib.request


def validate(lock):
    assert lock['architecture'] in ('amd64', 'arm64')
    assert re.fullmatch(r'[0-9a-f]{40}', lock['upstream']['commit'])
    for base in lock['base_images'].values():
        assert re.search(r'@sha256:[0-9a-f]{64}$', base['reference'])
    for item in [*lock['downloads'].values(), *lock['packages'], *lock['build_packages']]:
        assert item['url'].startswith('https://')
        assert re.fullmatch(r'[0-9a-f]{64}', item['sha256'])
        assert Path(item['filename']).name == item['filename']
    for section in ('packages', 'build_packages'):
        assert lock[section]
        assert len({p['nevra'] for p in lock[section]}) == len(lock[section])
    for p in [*lock['packages'], *lock['build_packages']]:
        assert p['architecture'] in (lock['rpm_architecture'], 'noarch')
        assert p['nevra'] == f"{p['name']}-{p['epoch']}:{p['version']}-{p['release']}.{p['architecture']}"
        assert p['repository'] in ('ubi-9-baseos-rpms', 'ubi-9-appstream-rpms', 'ubi-9-codeready-builder-rpms')


def acquire(item, directory):
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / item['filename']
    if not target.exists():
        with urllib.request.urlopen(item['url'], timeout=120) as source, target.open('wb') as dest:
            while chunk := source.read(1024 * 1024):
                dest.write(chunk)
    with target.open('rb') as source:
        assert hashlib.file_digest(source, 'sha256').hexdigest() == item['sha256'], target


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', choices=['validate-lock', 'acquire'])
    parser.add_argument('lock', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    lock = json.loads(args.lock.read_text())
    validate(lock)
    if args.mode == 'acquire':
        for item in lock['downloads'].values():
            acquire(item, args.output)
        with tarfile.open(args.output / lock['downloads']['source']['filename']) as archive:
            prefix = 'rauthy-' + lock['upstream']['commit'] + '/'
            for name, digest in lock['upstream']['lockfiles'].items():
                content = archive.extractfile(prefix + name).read()
                assert hashlib.sha256(content).hexdigest() == digest, name
        for item in lock['packages']:
            acquire(item, args.output / 'rpms')
        for item in lock['build_packages']:
            acquire(item, args.output / 'build-rpms')
        (args.output / 'BUILD-NEVRAS').write_text(''.join(sorted(p['nevra'] + '\n' for p in lock['build_packages'])))
        (args.output / 'SHA256SUMS').write_text(''.join(
            f"{p['sha256']}  rpms/{p['filename']}\n" for p in lock['packages']) + ''.join(
            f"{p['sha256']}  {p['filename']}\n" for p in lock['downloads'].values()) + ''.join(
            f"{p['sha256']}  build-rpms/{p['filename']}\n" for p in lock['build_packages']))
        (args.output / 'NEVRAS').write_text(''.join(sorted(p['nevra'] + '\n' for p in [*lock['packages']])))


if __name__ == '__main__':
    main()
