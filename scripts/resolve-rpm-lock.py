#!/usr/bin/env python3
"""Explicit lock refresh from downloaded native UBI RPM closure (never during builds)."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument('architecture', choices=['amd64', 'arm64'])
parser.add_argument('rpm_directory', type=Path)
parser.add_argument('--reposdir', required=True)
parser.add_argument('--section', choices=['packages', 'build_packages'], default='packages')
args = parser.parse_args()
machine = {'amd64': 'x86_64', 'arm64': 'aarch64'}[args.architecture]
query = subprocess.check_output(['dnf', '-q', '--noplugins', '--releasever=9', f'--forcearch={machine}',
    f'--setopt=reposdir={args.reposdir}', 'repoquery', '--available',
    '--qf', '%{name}|%{epoch}|%{version}|%{release}|%{arch}|%{repoid}|%{location}'], text=True)
records = {}
for line in query.splitlines():
    name, epoch, version, release, arch, repository, location = line.split('|')
    component = repository.removeprefix('ubi-9-').removesuffix('-rpms')
    assert component in ('baseos', 'appstream', 'codeready-builder')
    item = dict(name=name, epoch=int(epoch), version=version, release=release, architecture=arch,
        nevra=f'{name}-{epoch}:{version}-{release}.{arch}', filename=Path(location).name,
        repository=repository, url=f'https://cdn-ubi.redhat.com/content/public/ubi/dist/ubi9/9/{machine}/{component}/os/{location}')
    records[item['filename']] = item
packages = []
for path in sorted(args.rpm_directory.glob('*.rpm')):
    item = records[path.name]
    item.update(sha256=hashlib.file_digest(path.open('rb'), 'sha256').hexdigest(), size=path.stat().st_size)
    packages.append(item)
assert packages
lock_path = Path(f'artifacts/locks/{args.architecture}.json')
lock = json.loads(lock_path.read_text())
lock[args.section] = packages
lock_path.write_text(json.dumps(lock, indent=2)+'\n')
