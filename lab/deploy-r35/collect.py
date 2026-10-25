#!/usr/bin/env python3
"""Verify the R35 VM results and export only non-secret evidence.

Private state backups and unredacted command output remain inside the VM.
"""
import base64
import hashlib
import json
from pathlib import Path
import shutil
import socket
import subprocess
import sys
assert socket.gethostname()=='unified-lab-01'
root=Path('/root/r35');e=root/'evidence';export=root/'export'
assert not export.exists();export.mkdir(mode=0o700)
def read(p):return json.loads(Path(p).read_text())
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def save(p,v):Path(p).write_text(json.dumps(v,sort_keys=True,indent=2)+'\n')
def copy(p,d):
    d.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(p,d)
flow=e/'r35-upgrade6-flow'
for name in ('policy-cycle-result.json','failure-result.json','reverse-result.json'):
    assert read(flow/name)['passed'] is True
assert read(flow/'failure-result.json')['directions']==['enable','disable']
p=read(e/'upgrade6-plan.json');d=Path('/var/lib/tailscale-unified-deploy')/p['deploymentID']
assert read(d/'journal.json')['phase']=='rolled-back'
old=Path(p['native']['cli']);status=json.loads(subprocess.check_output([str(old),'status','--json']))
assert status['Self']['ID']==p['stableID'] and status['BackendState']=='Running'
policy=json.loads(subprocess.check_output([str(old),'debug','unified-policy','status','--json']))
assert policy['applied'] and policy['runtimeReady'] and not any(policy['enabledModules'].values())
proof=read(e/'upgrade-rehearsal6-plan.fallback.json')
assert proof['passed'] is True and proof['oldDaemonSHA256']==sha(p['native']['daemon'])
# Independently compare every non-policy FileStore key/value against the migration
# input. No key material or state contents leave this private VM.
sys.path.insert(0,str(root/'deploy'));import compatibility
migration=[]
for jf in d.glob('compatibility-*.json'):
    j=read(jf);assert j['phase']=='complete'
    raw=jf.with_suffix('.before').read_bytes()
    assert hashlib.sha256(raw).hexdigest()==j['beforeSHA256']
    after,changes=compatibility.migrate(raw)
    assert hashlib.sha256(after).hexdigest()==j['afterSHA256'] and changes==j['changes']
    original=json.loads(raw);translated=json.loads(after);changed={v['key'] for v in changes}
    assert set(original)==set(translated)
    assert all(original[k]==translated[k] for k in original if k not in changed)
    migration.append(dict(journal=jf.name,changedKeys=len(changed),preservedKeys=len(original)-len(changed),passed=True))
assert migration
sources=['deploy/native.py','deploy/plan.py','deploy/make-plan.py','deploy/policy.py','deploy/compatibility.py','deploy/prod/batch.py','deploy/reverse.sh']
source_hashes={s:sha(root/s) for s in sources}
for name in ('native.py','plan.py','compatibility.py'):
    assert sha(d/name)==source_hashes['deploy/'+name]
for sub in d.glob('policy-*'):
    if not sub.is_dir():continue
    assert read(sub/'result.json')['phase']=='complete'
    assert sha(sub/'policy.py')==source_hashes['deploy/policy.py']
summary=dict(status='PASS',scope='isolated dev QEMU Linux real systemd/TUN and pinned release binaries; no production E2E',
             stableID=p['stableID'],routes=read(flow/'reverse-result.json')['routes'],
             releaseSHA256=p['releaseSHA256'],oldDaemonSHA256=sha(p['native']['daemon']),
             newDaemonSHA256=read(d/'journal.json')['daemonSHA256'],migration=migration,sourceSHA256=source_hashes,
             checks=['committed-v1-bootstrap','upgrade-rehearsal','upgrade-v2-commit','enable-disable',
                     'enabled-and-disabled-daemon-restart','enable-and-disable-worker-failure-restart-recovery','committed-reverse-v1'],
             boundaries=['local VM commit attestation is explicitly lab-only','not physical power loss','no production forwarding/control-plane/long-duration proof'])
save(export/'summary.json',summary)
for f in e.rglob('*.json'):
    copy(f,export/'observations'/f.relative_to(e))
# Command outputs can contain prefs/identity material: export digests only.
with (export/'commands-redacted.jsonl').open('w') as out:
    for line in (e/'commands.jsonl').read_text().splitlines():
        r=json.loads(line)
        for k in ('stdout','stderr'):
            r[k+'SHA256']=hashlib.sha256(r.pop(k,'').encode()).hexdigest()
        out.write(json.dumps(r,sort_keys=True)+'\n')
for txn in d.parent.glob('r35-*'):
    for name in ('journal.json','failure.json','policy-intent.json','policy-local.json','policy-rollback.json','payload-evidence.json'):
        f=txn/name
        if f.exists():copy(f,export/'transactions'/txn.name/name)
    for f in txn.glob('compatibility-*.json'):copy(f,export/'transactions'/txn.name/f.name)
    for op in txn.glob('policy-*'):
        if op.is_dir():
            for name in ('result.json','status-before.json','status-after.json'):
                f=op/name
                if f.exists():copy(f,export/'transactions'/txn.name/op.name/name)
print(json.dumps(summary,sort_keys=True))
