#!/usr/bin/env python3
"""Offline, canonical release transport; hashes are integrity, not approval."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import sys
import tarfile


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def pairs(items):
    result = {}
    for k, v in items:
        require(k not in result, 'duplicate manifest key')
        result[k] = v
    return result


def validate(data):
    m = json.loads(data['manifest.json'], object_pairs_hook=pairs)
    require(m['sourceDirty'] is False and m['repeatBuild'] == 'PASS', 'dirty/unreproduced release')
    require(re.fullmatch('[0-9a-f]{40}', m['patchHEAD']) and
            m['releaseID'] == '1.102.3-unified.u1-' + m['patchHEAD'], 'releaseID mismatch')
    metadata = {'releaseID','upstreamTag','tagObject','peeledCommit','patchHEAD',
                'wireguardBase','wireguardPatchSHA256','go','toolchainTreeSHA256',
                'CGO_ENABLED','GOOS','GOAMD64','GOARM64','architectures','tags','ldflags',
                'trimpath','buildvcs','sourceDirty','schemaVersion','moduleManifestSHA256',
                'repeatBuild','officialHashComparison','stateCompatibility','buildTimeUTC','files'}
    require(metadata <= m.keys(), 'incomplete build metadata')
    require(m['GOOS'] == 'linux' and m['CGO_ENABLED'] == '0' and m['go'] == 'go1.26.6'
            and m['schemaVersion'] in (1, 2) and m['trimpath'] is True and m['buildvcs'] is False
            and m['architectures'] in (['amd64'], ['amd64', 'arm64-build-only']), 'unsupported build metadata')
    required = {'release-ready', 'source/patched-source.tar', 'source/patch-head.txt',
                'source/PATCH.diff', 'source/modules.json', 'source/base.txt', 'source/series',
                'source/unified.patch', 'source/wireguard-base.txt', 'source/UPSTREAM.sha256', 'source/LICENSE', 'config/schema.json',
                'config/idcfast.json', 'config/residential.json', 'TEST-REPORT.md',
                'RELEASE-NOTES.md', 'evidence-index.json', 'deploy/plan.py', 'deploy/native.py'}
    required.update('linux-amd64/' + b for b in ('tailscaled', 'tailscale', 'route-reconcile'))
    for arch in m['architectures']:
        for binary in ('tailscaled','tailscale','route-reconcile'):
            name = 'linux-' + arch.removesuffix('-build-only') + '/' + binary
            required.update((name, name + '.buildinfo'))
    files = m['files']
    require(isinstance(files, dict) and required <= files.keys(), 'incomplete manifest')
    if m['schemaVersion'] == 2:
        require('config/schema-v2.json' in files, 'missing v2 schema')
        require(data['config/schema.json'] == data['config/schema-v2.json'], 'v2 schema copies differ')
    require(set(data) == set(files) | {'manifest.json', 'SHA256SUMS'}, 'unlisted/missing release files')
    for name, digest in files.items():
        require(name not in ('manifest.json', 'SHA256SUMS') and sha(data[name]) == digest, 'release hash mismatch')
    require(data['source/patch-head.txt'].decode().strip() == m['patchHEAD'], 'source HEAD mismatch')
    require(m['moduleManifestSHA256'] == files['source/modules.json'] and
            m['wireguardPatchSHA256'] == files['source/PATCH.diff'], 'metadata hash mismatch')
    sums = dict(files, **{'manifest.json': sha(data['manifest.json'])})
    expected = ''.join(f'{v}  {k}\n' for k, v in sorted(sums.items())).encode()
    require(data['SHA256SUMS'] == expected, 'SHA256SUMS mismatch')
    return m


def safe_name(name):
    require(bool(re.fullmatch(r'[A-Za-z0-9_./-]+', name)) and
            not name.startswith('/') and all(x not in ('', '.', '..') for x in name.split('/')), 'unsafe release member')


def directory(root):
    root = Path(root)
    require(root.is_dir() and not root.is_symlink(), 'invalid release directory')
    data = {}
    for p in sorted(root.rglob('*')):
        require(not p.is_symlink(), 'symlink release member')
        name = p.relative_to(root).as_posix()
        safe_name(name)
        if p.is_dir():
            continue
        require(p.is_file(), 'nonregular release member')
        data[name] = p.read_bytes()
    validate(data)
    return data


def archive(data):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode='w', format=tarfile.USTAR_FORMAT) as tar:
        for name, content in sorted(data.items()):
            info = tarfile.TarInfo(name)
            info.size = len(content)
            info.mode = 0o755 if name.endswith('.sh') or name.split('/')[-1] in ('tailscaled', 'tailscale', 'route-reconcile') else 0o644
            tar.addfile(info, io.BytesIO(content))
    return out.getvalue()


def verify(path):
    raw = Path(path).read_bytes()
    data = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as tar:
        for item in tar:
            safe_name(item.name)
            require(item.isfile() and item.name not in data, 'nonregular/duplicate tar member')
            data[item.name] = tar.extractfile(item).read()
    validate(data)
    require(raw == archive(data), 'noncanonical or damaged tar')
    # Never extract attacker-selected paths onto the filesystem.
    return sha(raw)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--release-dir')
    ap.add_argument('--output')
    ap.add_argument('--verify', metavar='TAR')
    a = ap.parse_args()
    if a.verify:
        require(not a.release_dir and not a.output, 'verify accepts only TAR')
        print(verify(a.verify)); return
    require(a.release_dir and a.output, 'release-dir and output required')
    root = Path(a.release_dir).resolve()
    out = Path(a.output).absolute()
    require(root not in out.resolve().parents, 'output must be outside release')
    data = directory(root)
    raw = archive(data)
    require(directory(root) == data, 'release changed during bundling')
    with out.open('xb') as f:
        f.write(raw)
    print(sha(raw) + '  ' + str(out))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError, tarfile.TarError):
        sys.exit('bundle: invalid/incomplete release or local IO failure (contents redacted)')
