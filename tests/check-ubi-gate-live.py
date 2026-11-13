#!/usr/bin/env python3
"""Native CI probes against live metadata; never modify actual scanner reports."""
import argparse
import importlib.util
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from ubi_repositories import REPOSITORIES, UbiRepositories, parse_evr  # noqa: E402

spec = importlib.util.spec_from_file_location('gate', ROOT / 'scripts/vulnerability-gate.py')
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--architecture', required=True)
    parser.add_argument('--reposdir', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    lock = json.loads((ROOT / f'artifacts/locks/{args.architecture}.json').read_text())
    repositories = UbiRepositories(args.reposdir, args.architecture)
    evidence = []
    try:
        packages = [p for p in lock['packages'] if p['repository'] in REPOSITORIES][:10]
        if len(packages) != 10:
            raise ValueError('insufficient locked UBI RPMs for native query probes')
        for package in packages:
            name = package['name']
            candidates = repositories.query(name)
            if not candidates:
                raise ValueError(f'live probe cannot find locked UBI package: {name}')
            available = candidates[0]['evr']
            # A deliberately synthetic future epoch tests a successful negative
            # query, without pretending a real advisory is unavailable today.
            epoch = max(int(parse_evr(p['evr'])[0]) for p in candidates) + 1
            unavailable = f'{epoch}:1.0-1'
            for version, expected in ((available, 'blocked'), (unavailable, 'deferred')):
                purl = f'pkg:rpm/redhat/{name}@{package["version"]}-{package["release"]}?arch={package["architecture"]}'
                trivy = {'SchemaVersion': 2, 'Results': [{'Class': 'os-pkgs', 'Type': 'redhat',
                    'Vulnerabilities': [{'VulnerabilityID': 'synthetic-policy-probe', 'Severity': 'HIGH',
                        'PkgName': name, 'PkgIdentifier': {'PURL': purl}, 'FixedVersion': version}]}]}
                grype = {'descriptor': {}, 'matches': [{'artifact': {'type': 'rpm', 'name': name, 'purl': purl},
                    'vulnerability': {'id': 'synthetic-policy-probe', 'severity': 'High',
                                      'fix': {'state': 'fixed', 'versions': [version]}}}]}
                result = gate.summarize(trivy, grype, repositories, args.architecture)
                decisions = [finding['state'] for finding in result['findings']]
                if decisions != [expected, expected]:
                    raise ValueError(f'live policy probe failed: {name} {version}: {result}')
                evidence.append({'package': name, 'synthetic_fixed_version': version,
                                 'trivy': decisions[0], 'grype': decisions[1]})
        args.output.write_text(json.dumps({'architecture': args.architecture, 'synthetic_probes': evidence}, indent=2) + '\n')
        print(f'{args.architecture}: {len(evidence)} live repository probes passed for both scanner formats')
    finally:
        repositories.close()


if __name__ == '__main__':
    main()
