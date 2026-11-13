#!/usr/bin/env python3
"""Reject CRLF in tracked text; never normalize silently in CI."""
from pathlib import Path
import subprocess
import sys
paths = sys.argv[1:] or subprocess.check_output(['git', 'ls-files', '-z']).decode().split('\0')
bad = [p for p in paths if p and Path(p).is_file() and b'\r\n' in Path(p).read_bytes()]
if bad:
    raise SystemExit('CRLF forbidden: ' + ', '.join(bad))
