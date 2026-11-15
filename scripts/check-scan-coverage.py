#!/usr/bin/env python3
"""A missing ecosystem is a scan error, never a clean result.

Trivy's image mode reports RPMs as `redhat`, cargo-auditable binaries as `rustbinary`
and installed package.json manifests as `node-pkg`; lockfile types are filesystem-only.
"""
import json
import os
from pathlib import Path

MINIMUM = {'rpm': 30, 'cargo': 500, 'npm': 100}
arch = os.environ['ARCHITECTURE']
spdx = json.loads(Path(f'rauthy-{arch}.spdx.json').read_text())
purls = [ref['referenceLocator'] for p in spdx['packages'] for ref in p.get('externalRefs', [])
         if ref['referenceType'] == 'purl']
counts = {}
for ecosystem, minimum in MINIMUM.items():
    count = sum(p.startswith(f'pkg:{ecosystem}/') for p in purls)
    counts[f'syft {ecosystem}'] = count
    assert count >= minimum, f'SBOM missing {ecosystem} inventory ({count})'
trivy = json.loads(Path(f'trivy-all-{arch}.json').read_text())
results = trivy.get('Results') or []
for trivy_type, ecosystem, target in [('redhat', 'rpm', None), ('rustbinary', 'cargo', 'usr/local/bin/rauthy'),
                                      ('node-pkg', 'npm', None)]:
    matching = [r for r in results if r.get('Type') == trivy_type
                and (target is None or r.get('Target', '').lstrip('/') == target)]
    count = sum(len(r.get('Packages') or []) for r in matching)
    counts[f'trivy {trivy_type}'] = count
    assert count >= MINIMUM[ecosystem], f'Trivy missing {trivy_type} inventory ({count}); found {sorted({r.get("Type") for r in results})}'
print(json.dumps(counts, indent=2))
print('RPM, Cargo and npm inventory coverage: PASS')
