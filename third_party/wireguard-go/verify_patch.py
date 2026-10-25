#!/usr/bin/env python3
"""Offline verification of the exact upstream tree and this local patch."""
import hashlib
from pathlib import Path
import shutil
import subprocess
import tempfile

root = Path(__file__).resolve().parent
metadata = {"PATCH.md", "PATCH.diff", "UPSTREAM.sha256", "verify_patch.py"}

def hashes(path):
    return {str(p.relative_to(path)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in path.rglob("*") if p.is_file()}

expected = {}
for line in (root / "UPSTREAM.sha256").read_text().splitlines():
    digest, name = line.split("  ", 1)
    expected[name] = digest
with tempfile.TemporaryDirectory(prefix="wireguard-patch-check-") as tmp:
    tree = Path(tmp) / "tree"
    shutil.copytree(root, tree, ignore=shutil.ignore_patterns(*metadata))
    patched = hashes(tree)
    subprocess.run(["git", "apply", "--reverse", str(root / "PATCH.diff")],
                   cwd=tree, check=True)
    assert hashes(tree) == expected, "reverse patch does not match fixed upstream manifest"
    subprocess.run(["git", "apply", str(root / "PATCH.diff")], cwd=tree, check=True)
    assert hashes(tree) == patched, "forward patch does not reproduce local source"
print(f"PASS: {len(expected)} upstream files verified; reverse/forward patch reproduces local source")
