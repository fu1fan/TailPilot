"""Offline v2 -> v1 disabled policy-LKG migration. Never restore identity/routes.

Only FileStore JSON is supported; unknown stores/layouts fail closed. Every other
key/value is preserved exactly, with durable before/after backups and whole-file
CAS while systemd reports no daemon. An interrupted migration is idempotent.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import stat
import native
import plan


def sha(raw): return hashlib.sha256(raw).hexdigest()
def decode(raw): return json.loads(raw, object_pairs_hook=plan.pairs)
def encode(value): return json.dumps(value, separators=(',', ':'), ensure_ascii=True).encode()


def field(raw, wanted):
    """Return exact RawMessage bytes (Go checksum is not canonical JSON)."""
    text=raw.decode(); dec=json.JSONDecoder(object_pairs_hook=plan.pairs)
    i=text.index('{')+1
    while True:
        while text[i].isspace() or text[i]==',':i+=1
        if text[i]=='}':raise ValueError('missing checksum payload')
        key,i=dec.raw_decode(text,i)
        while text[i].isspace():i+=1
        native.require(text[i]==':','invalid JSON object')
        i+=1
        while text[i].isspace():i+=1
        begin=i;_,i=dec.raw_decode(text,i)
        if key==wanted:return text[begin:i].encode()


def migrate(raw):
    state=decode(raw)
    native.require(isinstance(state,dict) and all(isinstance(k,str) and isinstance(v,str) for k,v in state.items()), 'unsupported FileStore')
    values={k:base64.b64decode(v,validate=True) for k,v in state.items()}
    changes=[]
    for key,value in values.items():
        if key.endswith('||_unifiedHandoffV1'):
            native.require(value==b'complete','pending owner handoff; finish with v2 daemon')
        if key.endswith('||_appConnectorTTLV2'):
            env=decode(value);payload=field(value,'Payload');j=decode(payload)
            native.require(list(hashlib.sha256(payload).digest())==env['SHA256'] and
                           j['Schema']==2 and j['Complete'] is True and j['Handoff'] is True,
                           'pending/corrupt TTL handoff; finish with v2 daemon')
        if not key.endswith('||_unifiedPolicyV1'):continue
        record=decode(value);config=record['Config']
        native.require(record['SchemaVersion']==1 and sha(field(value,'Config'))==record['Hash'], 'invalid policy LKG checksum')
        if config.get('schema_version')==1:continue
        plan.all_off_config(config)
        v1=dict(config);v1['schema_version']=1
        if 'app_connector_ttl' in v1:v1['lease']=v1.pop('app_connector_ttl')
        record['Config']=v1;record['Hash']=sha(encode(v1))
        converted=encode(record)
        native.require(sha(field(converted,'Config'))==record['Hash'],'converted checksum mismatch')
        state[key]=base64.b64encode(converted).decode()
        changes.append(dict(key=key,before=sha(value),after=sha(converted)))
    return (encode(state)+b'\n' if changes else raw), changes


def restore_v1(t):
    if not t.n.get('previousDeployment'):return
    config=t.h.path(str(Path(t.n['daemon']).with_name('policy.json')))
    if plan.read(config).get('schema_version')!=1:return
    native.require(t.h.ctl('show',native.UNIT,'--property=MainPID','--value').strip()=='0', 'daemon must be stopped for compatibility migration')
    for index,name in enumerate(t.n['stateFiles']):
        path=t.h.path(name)
        native.require(not path.is_symlink() and path.is_file(),'regular FileStore required')
        raw=path.read_bytes();converted,changes=migrate(raw)
        jf=t.d/('compatibility-'+str(index)+'.json')
        if not changes:
            if jf.exists():
                j=plan.read(jf)
                if j['phase']!='complete':
                    native.require(sha(raw)==j['afterSHA256'],'compatibility recovery CAS conflict')
                    j['phase']='complete';plan.atomic(jf,j)
            continue
        backup=t.d/('compatibility-'+str(index)+'.before')
        if jf.exists():
            j=plan.read(jf)
            native.require(j['phase']=='pending' and j['beforeSHA256']==sha(raw) and j['afterSHA256']==sha(converted), 'compatibility journal conflict')
            native.require(plan.digest(backup)==j['beforeSHA256'],'compatibility backup drift')
        else:
            t.install(backup,raw)
            untouched=lambda data: {k:v for k,v in decode(data).items() if k not in {c['key'] for c in changes}}
            native.require(untouched(raw)==untouched(converted),'unexpected non-policy state delta')
            j=dict(phase='pending',stateFile=name,beforeSHA256=sha(raw),afterSHA256=sha(converted),changes=changes,
                   preservedSHA256=sha(encode(untouched(raw))))
            plan.atomic(jf,j)
        native.require(plan.digest(path)==j['beforeSHA256'],'state changed during compatibility migration')
        metadata=path.stat()
        mode=stat.S_IMODE(metadata.st_mode)
        native.require(path.stat().st_uid==0 and mode & 0o077==0,'private root FileStore required')
        t.install(path,converted,mode)
        os.chown(path,metadata.st_uid,metadata.st_gid)
        j['phase']='complete';plan.atomic(jf,j)
