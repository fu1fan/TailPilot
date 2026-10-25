#!/usr/bin/env python3
"""Strict public plan parser and local durable file operations. No shell evaluation."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import tempfile
import time

HEX = re.compile(r'[0-9a-f]{64}\Z')
ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,95}\Z')

def fail(message):
    raise ValueError(message)

def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def pairs(items):
    d = {}
    for k,v in items:
        if k in d: fail('duplicate JSON key')
        d[k] = v
    return d

def read(path):
    p=Path(path)
    if p.is_symlink() or p.stat().st_size > 1024*1024: fail('invalid plan/evidence file')
    return json.loads(p.read_text(), object_pairs_hook=pairs)

def atomic(path, data):
    path=Path(path)
    fd, tmp=tempfile.mkstemp(prefix='.journal-', dir=path.parent)
    try:
        with os.fdopen(fd,'w') as f:
            os.fchmod(f.fileno(),0o600)
            json.dump(data,f,sort_keys=True); f.write('\n'); f.flush(); os.fsync(f.fileno())
        os.replace(tmp,path)
        dfd=os.open(path.parent,os.O_RDONLY)
        try: os.fsync(dfd)
        finally: os.close(dfd)
    finally:
        if os.path.exists(tmp): os.unlink(tmp)

def load(path):
    return validate(read(path))

def validate(p):
    keys={'deploymentID','host','stableID','releaseID','releaseDirectory','releaseSHA256',
          'deadlineSeconds','oobEvidence','oobSHA256','externalEvidence','externalSHA256',
          'backupFiles','expectedBefore','originalExecStart','environmentFiles',
          'configuration','configurationSHA256','excludePeers','excludeDomains',
          'cohort','predecessorEvidence','autoUpdateCheck','autoUpdateApply','aptHeld'}
    if set(p) not in (keys, keys | {'native'}): fail('missing/unknown plan fields')
    if 'native' in p: native_contract(p)
    for k in ('deploymentID','host','stableID','releaseID'):
        if not isinstance(p[k],str) or not ID.fullmatch(p[k]): fail('invalid identity')
    for k in ('releaseSHA256','configurationSHA256','oobSHA256','externalSHA256'):
        if k == 'externalSHA256' and 'native' in p and p[k] is None: continue
        if not isinstance(p[k],str) or not HEX.fullmatch(p[k]): fail('invalid hash')
    for k in ('releaseDirectory','configuration','oobEvidence','externalEvidence'):
        v=p[k]
        if not isinstance(v,str) or not v.startswith('/') or '..' in Path(v).parts or '\n' in v: fail('invalid absolute path')
    if type(p['deadlineSeconds']) is not int or not 60 <= p['deadlineSeconds'] <= 1800: fail('invalid deadline')
    for k in ('autoUpdateCheck','autoUpdateApply','aptHeld'):
        if type(p[k]) is not bool: fail('invalid original update policy')
    if p['cohort'] not in ('first','second'): fail('invalid cohort')
    if p['cohort']=='second' and not HEX.fullmatch(p['predecessorEvidence']): fail('second host requires first terminal evidence hash')
    for k in ('excludePeers','excludeDomains','environmentFiles'):
        if not isinstance(p[k],list) or not all(isinstance(v,str) and v and '\n' not in v for v in p[k]): fail('invalid exclusions/environment')
    if not p['excludePeers'] or not p['excludeDomains']: fail('management/Codex exclusions required')
    line=p['originalExecStart']
    if not isinstance(line,str) or not line.startswith('ExecStart=' + p.get('native', {}).get('daemon', '/usr/sbin/tailscaled') + ' ') or '\n' in line or '\r' in line: fail('reviewed apt ExecStart required')
    # Inputs are source files; all must be enumerated, hashed and regular files.
    required={'daemon','cli','unit','dropins','config','prefs','state','routeinfo','ledger','routes','control','updates'}
    if not isinstance(p['backupFiles'],dict) or set(p['backupFiles'])!=required: fail('incomplete backup categories')
    paths=[]
    for category, entries in p['backupFiles'].items():
        if not isinstance(entries,list) or not entries: fail('empty backup category')
        paths.extend(entries)
    paths.extend(p['environmentFiles'])
    if not isinstance(p['expectedBefore'],dict) or set(paths)!=set(p['expectedBefore']): fail('backup/hash coverage mismatch')
    for f,h in p['expectedBefore'].items():
        if not isinstance(f,str) or not f.startswith('/') or '..' in Path(f).parts or '\n' in f: fail('invalid backup path')
        if h!='ABSENT' and (not isinstance(h,str) or not HEX.fullmatch(h)): fail('invalid before hash')
    return p

def native_contract(p):
    n = p['native']
    keys = {'socket','tailscaleIPs','daemon','cli','unit','dropins','stateFiles',
            'unitCatSHA256','environmentFilesShow','minFreeBytes','minAvailableMemoryBytes',
            'fallbackEvidence','predecessorEvidenceFile'}
    if not isinstance(n, dict) or set(n) not in (keys, keys | {'previousDeployment'}): fail('incomplete native contract')
    for k in ('socket','daemon','cli','unit','fallbackEvidence','predecessorEvidenceFile'):
        value = n[k]
        if not isinstance(value,str) or not re.fullmatch(r'/[A-Za-z0-9_./-]+',value) or '..' in Path(value).parts:
            fail('unsafe native path')
    if 'previousDeployment' in n:
        if not isinstance(n['previousDeployment'], str) or not ID.fullmatch(n['previousDeployment']): fail('invalid predecessor')
        parent = Path(n['daemon']).parent
        if parent.parent != Path('/usr/local/lib/tailscale-unified') or not ID.fullmatch(parent.name) or n['daemon'] != str(parent/'tailscaled') or n['cli'] != str(parent/'tailscale'): fail('unsupported custom layout')
        if n['previousDeployment'] == p['deploymentID'] or parent.name == p['releaseID']: fail('upgrade requires new transaction and release')
    elif n['daemon'] != '/usr/sbin/tailscaled' or n['cli'] != '/usr/bin/tailscale': fail('only apt layout supported')
    for k in ('dropins','stateFiles','tailscaleIPs'):
        if not isinstance(n[k],list) or not all(isinstance(v,str) and v for v in n[k]): fail('native list')
    if not n['stateFiles'] or not n['tailscaleIPs']: fail('missing native state/identity')
    if not HEX.fullmatch(n['unitCatSHA256']): fail('native unit hash')
    if not isinstance(n['environmentFilesShow'],str): fail('native environment inventory')
    for k in ('minFreeBytes','minAvailableMemoryBytes'):
        if type(n[k]) is not int or n[k] < 64*1024*1024: fail('native resource floor')

def before(p):
    for path, expected in p['expectedBefore'].items():
        f=Path(path)
        if expected=='ABSENT':
            if f.exists() or f.is_symlink(): fail('expected absent file changed')
        elif f.is_symlink() or not f.is_file() or digest(f)!=expected:
            fail('expected-before conflict')

def evidence(path, expected, p, kind):
    if digest(path)!=expected: fail('evidence hash mismatch')
    e=read(path)
    if e.get('deploymentID')!=p['deploymentID'] or e.get('stableID')!=p['stableID'] or e.get('kind')!=kind or e.get('passed') is not True:
        fail('evidence binding mismatch')
    if e.get('releaseSHA256')!=p['releaseSHA256']: fail('evidence release mismatch')
    if kind=='external-e2e' and (not isinstance(e.get('generation'),int) or e.get('configurationSHA256')!=p['configurationSHA256']): fail('external config binding mismatch')
    if kind=='oob' and (e.get('independent') is not True or e.get('rootRecovery') is not True): fail('OOB proof incomplete')
    if not isinstance(e.get('expiresUnix'),int) or e['expiresUnix'] <= time.time(): fail('expired evidence')

def validate_schema(value, schema):
    """Validate the complete keyword subset used by the pinned policy schema."""
    supported = {'$schema', '$id', 'title', 'type', 'properties', 'required',
                 'additionalProperties', 'const', 'enum', 'default', 'minimum',
                 'maximum', 'minLength', 'maxLength', 'pattern', 'items',
                 'maxItems', 'uniqueItems'}
    if set(schema) - supported: fail('unsupported policy schema keyword')
    types = {'object': dict, 'array': list, 'string': str, 'integer': int, 'boolean': bool}
    if type(value) is not types[schema['type']]: fail('invalid policy field type')
    if 'const' in schema and value != schema['const']: fail('policy schema version mismatch')
    if 'enum' in schema and value not in schema['enum']: fail('invalid policy enum')
    if isinstance(value, dict):
        props = schema['properties']
        if set(value) - set(props) or set(schema.get('required', [])) - set(value):
            fail('missing/unknown policy fields')
        for k, v in value.items(): validate_schema(v, props[k])
    elif isinstance(value, list):
        if len(value) > schema.get('maxItems', len(value)): fail('policy array too long')
        if schema.get('uniqueItems') and len({json.dumps(v, sort_keys=True) for v in value}) != len(value):
            fail('duplicate policy array value')
        for v in value: validate_schema(v, schema['items'])
    elif isinstance(value, str):
        if not schema.get('minLength', 0) <= len(value) <= schema.get('maxLength', len(value)):
            fail('invalid policy string length')
        if 'pattern' in schema and not re.search(schema['pattern'], value): fail('invalid policy pattern')
    elif type(value) is int:
        if not schema.get('minimum', value) <= value <= schema.get('maximum', value):
            fail('policy integer out of range')

def policy_schema_path():
    here = Path(__file__).resolve().parent.parent
    schema = here/'featurepolicy/schema-v2.json'
    if not schema.exists(): schema = here/'config/schema-v2.json'
    if not schema.exists(): schema = Path(__file__).with_name('schema-v2.json')
    return schema

def all_off_config(c):
    validate_schema(c, read(policy_schema_path()))
    if c.get('enabled') is not False: fail('first rollout must be globally disabled')
    for module in ('app_connector_ttl', 'auto_ipv6', 'dns_ipv4_only', 'path_policy'):
        if c.get(module, {}).get('enabled', False) is not False: fail('module must be off')
    if c.get('path_policy', {}).get('rules') or c.get('dns_ipv4_only', {}).get('targets'):
        fail('first rollout cannot contain targets')

def predecessor_alloff(c):
    """Validate v1 predecessor policy without activating or rewriting it."""
    if c.get('schema_version') == 1:
        if 'app_connector_ttl' in c: fail('mixed predecessor policy schema')
        c = dict(c, schema_version=2)
        if 'lease' in c: c['app_connector_ttl'] = c.pop('lease')
    all_off_config(c)


def package(p):
    root=Path(p['releaseDirectory'])
    if digest(root/'manifest.json')!=p['releaseSHA256']: fail('release manifest mismatch')
    m=read(root/'manifest.json')
    if m.get('releaseID')!=p['releaseID'] or m.get('repeatBuild')!='PASS' or m.get('sourceDirty') is not False: fail('release not reproducible')
    for name,h in m['files'].items():
        f=Path(name)
        if f.is_absolute() or '..' in f.parts: fail('unsafe release member')
        target=root/f
        if target.is_symlink() or not target.is_file() or digest(target)!=h: fail('release file mismatch')
    for name in ('linux-amd64/tailscaled','linux-amd64/tailscale','linux-amd64/route-reconcile'):
        if name not in m['files']: fail('release binary not covered')
    if m.get('schemaVersion') != 2: fail('v2 rollout requires a v2 release')
    c=read(p['configuration'])
    if digest(p['configuration'])!=p['configurationSHA256']: fail('configuration hash mismatch')
    all_off_config(c)
    return m

def main():
    command=sys.argv[1]; p=load(sys.argv[2])
    if command=='validate':
        print(json.dumps({'mode':'dry-run','deploymentID':p['deploymentID'],'host':p['host'],
            'stage':'/usr/local/lib/tailscale-unified/'+p['releaseID'],
            'phases':['preflight','backup','stage','arm','switch','verify','commit','rollback','cleanup'],
            'gates':['expected-before','OOB','local-timer','boot-recovery','external-E2E','serial-cohort'],
            'hostReads':False,'hostWrites':False},sort_keys=True)); return
    if command=='get':
        value=p[sys.argv[3]]
        if isinstance(value,bool): print(str(value).lower())
        elif isinstance(value,(dict,list)): print(json.dumps(value))
        else: print(value)
        return
    if command=='before': before(p); return
    if command=='package': package(p); return
    if command=='oob': evidence(p['oobEvidence'],p['oobSHA256'],p,'oob'); return
    if command=='external': evidence(p['externalEvidence'],p['externalSHA256'],p,'external-e2e'); return
    if command=='backup':
        before(p)
        dest=Path(sys.argv[3]); dest.mkdir(mode=0o700)
        records={}
        for n,(name,h) in enumerate(sorted(p['expectedBefore'].items())):
            if h=='ABSENT': records[name]={'sha256':'ABSENT'}; continue
            f=Path(name); s=f.stat(); target=dest/str(n)
            # O_NOFOLLOW closes source symlink substitution; before/after hashes
            # catch changed contents. Stop daemon before the final state backup.
            fd=os.open(f,os.O_RDONLY|os.O_NOFOLLOW)
            with os.fdopen(fd,'rb') as src, open(target,'xb') as out:
                os.fchmod(out.fileno(),0o600); shutil.copyfileobj(src,out); out.flush(); os.fsync(out.fileno())
            if digest(target)!=h: fail('source changed during backup')
            records[name]={'sha256':h,'file':str(n),'uid':s.st_uid,'gid':s.st_gid,'mode':stat.S_IMODE(s.st_mode)}
        atomic(dest/'manifest.json',records); return
    if command=='journal':
        directory=Path(sys.argv[3]); phase=sys.argv[4]; jf=directory/'journal.json'
        # Same lock across IDs/phases. Caller must additionally serialize real
        # host mutations; this helper only makes journal transitions durable.
        with open(directory.parent/'transaction.lock','a') as lock:
            os.chmod(lock.name,0o600)
            fcntl.flock(lock,fcntl.LOCK_EX)
            old=read(jf) if jf.exists() else {'phase':'new','deadline':0,'deploymentID':p['deploymentID']}
            allowed={'preflight':['new'],'backup':['preflight'],'stage':['backup'],'armed':['stage'],
                     'switching':['armed'],'switched':['switching'],'verified':['switched'],
                     'committed':['verified'],'rolling-back':['armed','switching','switched','verified','rolling-back','rollback-failed'],
                     'rolled-back':['rolling-back'],'rollback-failed':['rolling-back'],
                     'cleaned':['committed','rolled-back','cleaned']}
            if old['phase']==phase: return
            if phase=='rolling-back' and old['phase'] in ('committed','rolled-back','cleaned'): return
            if old['phase'] not in allowed.get(phase,[]): fail('invalid journal transition')
            if phase in ('switching','verified','committed') and time.time()>=old['deadline']: fail('deadline expired')
            if phase=='armed': old['deadline']=int(time.time())+p['deadlineSeconds']
            old['phase']=phase; old['updated']=int(time.time()); atomic(jf,old); return
    if command=='phase':
        f=Path(sys.argv[3])/'journal.json'; print(read(f)['phase'] if f.exists() else 'new'); return
    if command=='dropin':
        target='/usr/local/lib/tailscale-unified/'+p['releaseID']+'/tailscaled'
        # Preserve all arguments byte-for-byte, including $FLAGS, socket, state,
        # port and EnvironmentFile references inherited from the original unit.
        print('[Service]\nExecStart=\n'+p['originalExecStart'].replace('/usr/sbin/tailscaled',target,1)); return
    fail('unknown helper operation')

if __name__=='__main__':
    try: main()
    except (ValueError, OSError, KeyError, TypeError, json.JSONDecodeError):
        print('deploy: invalid input, conflict, or local operation failed (contents redacted)',file=sys.stderr)
        sys.exit(1)
