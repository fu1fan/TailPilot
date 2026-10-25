#!/usr/bin/env python3
"""Provider-neutral VM test skeleton; outputs data, never executes a payload."""
import json
from pathlib import Path
import re
import sys
import uuid

CASES = {
 **{'I-P'+format(n,'03b'): ['both directions TCP/UDP/QUIC; new and existing sessions',
    'hard deny send/probe/authenticated receive; <=30s convergence or FAIL',
    'strict/allowed ordering, failure/recovery hysteresis; cold/warm relay bootstrap'] for n in range(8)},
 'I-PDEF':['unmatched C2 continuous traffic; official/OSS/unified-off baseline'],
 'I-D1':['A/AAAA, cross-domain CNAME, apex/wildcard, unrelated CDN; exit IP'],
 'I-D2':['HTTPS/SVCB hints/mandatory/alias; DNSSEC AD and validation boundary'],
 'I-D3':['preexisting positive/negative cache; record TTL expiry'],
 'I-D4':['independent alias, DoH and literal IP: explicit negative boundaries'],
 'I-L1':['lease refresh/expiry/shared/manual/control owner; advertised versus approved diff'],
 'I-L2':['TCP/quiet TCP/QUIC, activity unavailable, grace and bounded hard retention'],
 'I-V1':['two switches four combinations, reload/reboot/migration, protect manual v6/default'],
 'I-X1':['all 16 module combinations; concurrent profile/domain changes'],
 'I-X2':['first DNS/local advertise/control approval/client route propagation timeline'],
 'I-X3':['both connectors assigned same domain; consistent and inconsistent policies'],
 'I-M1':['1vCPU/913MiB, 20k lease/40k flow, 2h churn; +64MiB/+5pp/zero OOM'],
 'I-B1':['timer expiry, SSH lost, corrupt binary, state compatibility, reboot/power loss',
          'StableID preserved; boot guard recovers before patched service; no network dependency'],
}
ROLES = [('network','management'),('network','data'),('vm','R'),('vm','I'),
         ('vm','C1'),('vm','C2'),('vm','relay'),('vm','derp900'),('vm','derp901'),
         ('vm','authoritative-dns'),('vm','dns-cache')]

def fail(): raise ValueError('invalid scope/input')
def inventory(path,run):
 p=Path(path)
 if p.is_symlink() or p.stat().st_size>1024*1024: fail()
 d=json.loads(p.read_text())
 if d.get('runID')!=run or d.get('schema')!=1: fail()
 items=d['resources']
 if len(items)!=len(ROLES): fail()
 for item,(kind,role) in zip(items,ROLES):
  if set(item)!={'kind','role','name','created'}: fail()
  if item['kind']!=kind or item['role']!=role or item['name']!=run+'-'+role or type(item['created']) is not bool: fail()
 return d

def main():
 action,run,path,case,connector,version=sys.argv[1:]
 if action=='create-topology' and not run: run='lab-'+uuid.uuid4().hex
 if not re.fullmatch(r'lab-[0-9a-f]{32}',run): fail()
 out={'schema':1,'runID':run,'mode':'dry-run','executable':False,'action':action,'result':'NOT_RUN'}
 if action=='create-topology':
  if path or case or connector or version: fail()
  out.update(resources=[dict(kind=k,role=r,name=run+'-'+r,created=False) for k,r in ROLES],
    constraints=['host never joins tailnet; no host default-route/firewall flush',
      'dedicated test tailnet; both VM connectors; C1 selected/C2 unmatched',
      'independent management NIC never receives fault injection',
      'original C1/C2 1.102.3 and 1.104.1 tested separately; pin image SHA',
      'test domain controlled by Lead; example.invalid is only a fixture',
      'Lead injects credentials through protected console/stdin or tmpfs 0600 file',
      'never credentials in argv, image, environment dump, source, shell trace or evidence'],
    creationOrder='listed order; record provider ID/ownership after EACH successful creation',
    baseline=['host route/rule/firewall hashes','image hashes','server release manifest SHA'])
 else:
  inv=inventory(path,run)
  if action=='run-case':
   if case not in CASES or connector not in ('R','I') or version not in ('1.102.3','1.104.1'): fail()
   out.update(case=case,connector=connector,clientVersion=version,checks=CASES[case],
     steps=['restore isolated case snapshot','verify baseline and exclusions','keep C2 continuous probe',
       'inject failures only on owned VM data NIC','record generation-bound send/receive evidence',
       'remove injection and restore snapshot','evaluate assertions; NOT_RUN is never PASS'],
     faults=['direct UDP','relay UDP','one/all DERP TCP','DNS upstream','VM disk-full/clock/reboot'],
     evidence=['config/release/image hashes','redacted DNS wire','bidirectional application outcomes',
       'advertised/enabled/client routes separately','path counters and accepted/applied fence',
       'local process/resources','first packet timeline','C2 baseline comparison'])
  elif action=='collect':
   if case or connector or version: fail()
   out.update(allowlist=['case-report.json','versions.json','hashes.json','redacted-path-summary.json',
     'redacted-dns-summary.json','resource-summary.json','rollback-timeline.json'],
     forbidden=['raw state/prefs','private keys','auth keys','tokens','unredacted packet captures'],
     instructions=['keep raw private artifacts on VM, mode 0600, retention deadline',
       'hash redacted evidence and record NOT_RUN/PASS/FAIL per case; do not infer PASS from file existence'])
  elif action=='destroy-topology':
   if case or connector or version: fail()
   out['reverseDeletionPlan']=[x for x in reversed(inv['resources']) if x['created']]
   out['guards']=['provider identity and runID ownership recheck before each removal',
     'never wildcard delete; never clear host firewall/default route',
     'persist progress after each deletion; retain failed resources for retry',
     'compare host baseline after teardown; preserve evidence even when cleanup fails']
  else: fail()
 print(json.dumps(out,indent=2))

if __name__=='__main__':
 try: main()
 except (ValueError,OSError,KeyError,TypeError):
  print('lab: invalid scope, case or inventory (contents redacted)',file=sys.stderr); sys.exit(1)
