#!/usr/bin/env python3
"""R35 isolated VM driver. Never run on a real tailnet/production host.

Bootstrap/rehearsal/formal commits use explicitly LAB-ONLY local acceptance.
No production external E2E acceptance is claimed or fabricated by this runner.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time

os.umask(0o077)
assert socket.gethostname() == 'unified-lab-01'
ROOT=Path('/root/r35')
OUT=ROOT/'evidence'; OUT.mkdir(exist_ok=True)

def digest(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def read(p): return json.loads(Path(p).read_text())
def save(p,v):
    Path(p).write_text(json.dumps(v,sort_keys=True,indent=2)+'\n'); Path(p).chmod(0o600)
def run(args):
    r=subprocess.run([str(a) for a in args],capture_output=True,text=True,timeout=240)
    with (OUT/'commands.jsonl').open('a') as f:
        f.write(json.dumps(dict(argv=[str(a) for a in args],code=r.returncode,stdout=r.stdout,stderr=r.stderr))+'\n')
    if r.returncode: raise RuntimeError('command failed: '+str(args[0])+' '+r.stderr[-1500:])
    return r.stdout

def wait(path, phase):
    end=time.monotonic()+100
    while time.monotonic()<end:
        if path.exists() and read(path).get('phase')==phase:return read(path)
        if path.exists() and read(path).get('phase') in ('rollback-failed','rolled-back') and phase!='rolled-back':raise RuntimeError('transaction recovered/failed before expected phase')
        time.sleep(.5)
    raise RuntimeError('timeout: '+str(path)+' expected '+phase+' got '+str(read(path) if path.exists() else None))

def transaction(kind, release, deploy, fallback=None):
    kind += os.environ.get('R35_ATTEMPT', '')
    ident='r35-'+kind
    manifest=read(release/'manifest.json')
    cli='/usr/bin/tailscale'
    # Effective CLI follows the installed release.
    exe=run(['readlink','-f','/proc/'+run(['systemctl','show','tailscaled','-p','MainPID','--value']).strip()+'/exe']).strip()
    if exe.startswith('/usr/local/lib/'):cli=str(Path(exe).with_name('tailscale'))
    status=json.loads(run([cli,'status','--json']))
    assert status['BackendState']=='Running'
    oob=OUT/(kind+'-oob.json'); planfile=OUT/(kind+'-plan.json'); approval=OUT/(kind+'-approval.json')
    save(oob,dict(kind='oob',deploymentID=ident,host=socket.gethostname(),stableID=status['Self']['ID'],
                  releaseSHA256=digest(release/'manifest.json'),independent=True,rootRecovery=True,passed=True,
                  expiresUnix=int(time.time())+7200,scope='isolated VM loopback SSH via dev; lab only'))
    args=['python3',deploy/'make-plan.py','--release-dir',release,'--configuration',os.environ.get('R35_CONFIG',str(release/'config/idcfast.json')),
          '--deployment-id',ident,'--exclusions-peers','/root/ex-peers.json','--exclusions-domains','/root/ex-domains.json',
          '--oob-evidence',oob,'--backup-inventory','/root/inventory.json','--output',planfile,'--deadline-seconds','900']
    if fallback:args+=['--fallback-evidence',fallback]
    run(args)
    p=read(planfile)
    proof=dict(deploymentID=ident,host=p['host'],approvedPlanSHA256=digest(planfile),expiresUnix=int(time.time())+7200,
               serialWindowExclusive=True,excludePeers=p['excludePeers'],excludeDomains=p['excludeDomains'],
               rehearsal=not bool(fallback))
    save(approval,proof)
    def phase(action, extra=()):
        cmd=['python3',deploy/'native.py','--phase',action,'--plan',planfile,'--approval',approval,'--approved',digest(planfile),*extra]
        if action=='rehearse':cmd+=['--rehearsal']
        return run(cmd)
    journal=Path('/var/lib/tailscale-unified-deploy')/ident/'journal.json'
    if not fallback:
        phase('rehearse'); wait(journal,'rolled-back')
        deadline=time.monotonic()+10
        while time.monotonic()<deadline and not (Path(p['native']['fallbackEvidence']).exists() and read(journal).get('rehearsalEvidenceSHA256')):
            if (journal.parent/'failure.json').exists():break
            time.sleep(.1)
        assert Path(p['native']['fallbackEvidence']).exists() and read(journal).get('rehearsalEvidenceSHA256'), 'rollback without rehearsal proof is not PASS'
        phase('cleanup')
        save(OUT/(kind+'-result.json'),dict(passed=True,phase=read(journal)['phase'],scope='real native rehearsal'))
        return p['native']['fallbackEvidence']
    for action in ('preflight','backup','stage','arm','switch'):phase(action)
    wait(journal,'switched');phase('verify')
    local=read(journal.parent/'policy-local.json')
    evidence={k:p[k] for k in ('deploymentID','host','stableID','releaseSHA256','configurationSHA256')}
    evidence.update(kind='external-e2e',passed=True,expiresUnix=int(time.time())+7200,
                    generation=local['acceptedFence']['Generation'],deadlineUnix=read(journal)['wallDeadline'],
                    scope='LAB ONLY: local VM identity/policy; does not attest production E2E')
    save(p['externalEvidence'],evidence)
    proof['acceptanceSHA256']=digest(p['externalEvidence']);save(approval,proof)
    phase('commit',['--acceptance-sha256',proof['acceptanceSHA256']])
    # Deliberately retain committed recovery guard to test automatic upgrade handling.
    save(OUT/(kind+'-result.json'),dict(passed=True,phase=read(journal)['phase'],scope=evidence['scope']))
    return str(planfile)

if __name__=='__main__':
    action=sys.argv[1]
    if action=='bootstrap':
        r=Path('/root/r35-old19');fb=transaction('old-rehearsal',r,r/'deploy')
        transaction('old-committed',r,r/'deploy',fb)
    elif action=='upgrade-rehearsal':
        transaction('upgrade-rehearsal',Path('/root/r35-final'),ROOT/'deploy')
    elif action=='upgrade':
        fb=read(OUT/(os.environ.get('R35_REHEARSAL','upgrade-rehearsal')+'-plan.json'))['native']['fallbackEvidence']
        transaction('upgrade',Path('/root/r35-final'),ROOT/'deploy',fb)
