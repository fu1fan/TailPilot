#!/usr/bin/env python3
"""SHA256 of sorted relative paths and bytes in the supplied GOROOT."""
import hashlib
from pathlib import Path
import sys
root=Path(sys.argv[1]).resolve()
h=hashlib.sha256()
for p in sorted(root.rglob('*')):
    if p.is_symlink():
        raise SystemExit('toolchain symlinks are not accepted')
    if p.is_file():
        h.update(str(p.relative_to(root)).encode()+b'\0')
        h.update(hashlib.sha256(p.read_bytes()).digest())
print(h.hexdigest())
