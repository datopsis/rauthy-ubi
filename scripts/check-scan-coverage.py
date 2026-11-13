#!/usr/bin/env python3
"""A missing ecosystem is a scan error, never a clean result."""
import json
import os
from pathlib import Path
arch = os.environ['ARCHITECTURE']
spdx = json.loads(Path(f'rauthy-{arch}.spdx.json').read_text())
purls = [ref['referenceLocator'] for p in spdx['packages'] for ref in p.get('externalRefs', [])
         if ref['referenceType'] == 'purl']
for ecosystem, minimum in [('rpm', 30), ('cargo', 500), ('npm', 100)]:
    count = sum(p.startswith(f'pkg:{ecosystem}/') for p in purls)
    assert count >= minimum, f'SBOM missing {ecosystem} inventory ({count})'
trivy = json.loads(Path(f'trivy-all-{arch}.json').read_text())
types = {r.get('Type') for r in trivy['Results']}
assert {'redhat', 'cargo', 'npm'} <= types, f'Trivy missing ecosystem: {types}'
print('RPM, Cargo and npm inventory coverage: PASS')
