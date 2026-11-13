#!/usr/bin/env python3
import hashlib
import json
import os
from pathlib import Path
import subprocess
arch = os.environ['ARCHITECTURE']
obj = json.loads(subprocess.check_output(['docker', 'image', 'inspect', os.environ['TEST_IMAGE']]))[0]
revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
lock = hashlib.sha256(Path(f'artifacts/locks/{arch}.json').read_bytes()).hexdigest()
assert obj['Architecture'] == arch
assert obj['Config']['Labels']['org.opencontainers.image.revision'] == revision
assert obj['Config']['Labels']['io.datopsis.artifact-lock.sha256'] == lock
pg = json.loads(subprocess.check_output(['docker', 'image', 'inspect', 'postgresql-ubi:test']))[0]
assert pg['Architecture'] == arch
assert pg['Config']['Labels']['org.opencontainers.image.revision'] == Path('artifacts/postgresql.commit').read_text().strip()
pg_lock = hashlib.sha256(Path(f'.test-work/postgresql/artifacts/locks/{arch}.json').read_bytes()).hexdigest()
assert pg['Config']['Labels']['io.datopsis.artifact-lock.sha256'] == pg_lock
Path(f'provenance-{arch}.json').write_text(json.dumps(dict(architecture=arch, revision=revision,
    lock_sha256=lock, image_id=obj['Id'], size_bytes=obj['Size'], postgres_revision=Path('artifacts/postgresql.commit').read_text().strip()), indent=2)+'\n')
