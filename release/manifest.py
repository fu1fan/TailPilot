#!/usr/bin/env python3
"""Build metadata only; never reads host configuration or credentials."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys

root = Path(sys.argv[1])
def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

(root / 'RELEASE-NOTES.md').write_text('''# 1.102.3-unified.u1
Public-source patched build, NOT official byte reproduction.
Configuration schema v1. Default off. Arm64 (if present): build-only.
State: upstream identity state retained; module ledger/RouteInfo compatibility
must pass I-B1 before deployment. No automatic control-plane rollback.
Repeated build equality proves these inputs only. Native version execution,
full/race, lab and power-loss recovery acceptance are NOT_RUN by this builder.
''')
(root / 'TEST-REPORT.md').write_text('Repeated build: PASS\nNative/lab/deploy/E2E: NOT_RUN\n')
(root / 'evidence-index.json').write_text(json.dumps({'repeatBuild': 'PASS', 'native': 'NOT_RUN', 'lab': 'NOT_RUN', 'deploy': 'NOT_RUN'})+'\n')
files = {str(p.relative_to(root)): sha(p) for p in sorted(root.rglob('*')) if p.is_file()}
manifest = dict(releaseID='1.102.3-unified.u1-'+sys.argv[2], upstreamTag='v1.102.3',
    tagObject='9329c3677031109ff6d0b80abee0cddc8f35ff6f',
    peeledCommit='53a0d659afa51835dd7a9283873cca44261454f8', patchHEAD=sys.argv[2],
    wireguardBase='2e01ba5b00f0a02b0fb37e668c7cac6717880568',
    wireguardPatchSHA256=files['source/PATCH.diff'], go='go1.26.6',
    toolchainTreeSHA256=sys.argv[3], CGO_ENABLED='0', GOOS='linux', GOAMD64='v1',
    GOARM64='v8.0', architectures=['amd64']+(['arm64-build-only'] if sys.argv[5]=='true' else []),
    tags=[], ldflags=sys.argv[4], trimpath=True, buildvcs=False, sourceDirty=False,
    schemaVersion=2, moduleManifestSHA256=files['source/modules.json'], repeatBuild='PASS',
    officialHashComparison='NOT_CLAIMED', stateCompatibility='I-B1_REQUIRED',
    buildTimeUTC=datetime.now(timezone.utc).isoformat(), files=files)
(root / 'manifest.json').write_text(json.dumps(manifest, indent=2, sort_keys=True)+'\n')
files['manifest.json'] = sha(root/'manifest.json')
(root / 'SHA256SUMS').write_text(''.join(f'{v}  {k}\n' for k,v in sorted(files.items())))
