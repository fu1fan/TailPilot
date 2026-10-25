#!/usr/bin/env python3
"""Real binaries/Unix LocalAPI; offline synthetic Control history, no mock transport.
Requires an isolated network namespace with loopback up. Leaves evidence, not services.
Exit 2 after partial gate: DNS packet relearn and six-write SIGKILL are not implemented.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import select
import shutil
import subprocess
import time
import urllib.request

p = argparse.ArgumentParser()
p.add_argument('--bin', required=True, type=Path)
p.add_argument('--out', required=True, type=Path)
a = p.parse_args()
bin = a.bin.resolve()
root = a.out.resolve()
root.mkdir(mode=0o700, parents=True, exist_ok=False)
os.umask(0o077)
state, sock, policy = root/'state.json', root/'tailscaled.sock', root/'policy.json'
processes = []
logs = []
commands = (root/'commands.jsonl').open('w')
count = 0
phase = "startup"
gates = {}

def save(name, obj):
    (root/name).write_text(json.dumps(obj, indent=2)+'\n')

def snapshot(name):
    raw = state.read_bytes()
    (root/(name+'.state')).write_bytes(raw)
    store = json.loads(raw)
    journals = {k:json.loads(base64.b64decode(v)) for k,v in store.items()
                if '||' in k and k.rsplit('||',1)[1] in
                ('_routeInfo', '_appConnectorTTLV2', '_unifiedRouteLedgerV1')}
    save(name+'.json', {'sha256':hashlib.sha256(raw).hexdigest(), 'journals':journals})

def command(args, timeout=45):
    global count
    count += 1
    commands.write(json.dumps(args)+'\n'); commands.flush()
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        for suffix, data in [('stdout', e.stdout), ('stderr', e.stderr)]:
            (root/f'{count:03d}.{suffix}').write_bytes(data if isinstance(data, bytes) else (data or '').encode())
        save(f'{count:03d}.result.json', {'phase':phase, 'timeout':timeout, 'command':args})
        raise
    save(f'{count:03d}.result.json', {'phase':phase, 'returncode':r.returncode, 'command':args})
    (root/f'{count:03d}.stdout').write_text(r.stdout)
    (root/f'{count:03d}.stderr').write_text(r.stderr)
    if r.returncode:
        raise RuntimeError((args, r.returncode, r.stderr))
    return json.loads(r.stdout) if r.stdout.strip().startswith(('{','[')) else r.stdout

def cli(*args):
    return command([str(bin/'tailscale'), '--socket='+str(sock), *args])

def start(args, name, env=None, stdout=None):
    log = (root/name).open('a'); logs.append(log)
    commands.write(json.dumps(args)+'\n'); commands.flush()
    proc = subprocess.Popen(args, stdout=stdout or log, stderr=log, env=env, text=True)
    processes.append(proc)
    return proc

def stop(proc, kill=False):
    if proc.poll() is None:
        proc.kill() if kill else proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill(); proc.wait(); raise

def daemon():
    # PrivateNetwork has only loopback, which netmon deliberately does not
    # count as Internet connectivity. Otherwise LocalBackend pauses control.
    env = dict(os.environ, TS_UNIFIED_POLICY_FILE=str(policy), TS_NO_LOGS_NO_SUPPORT='true',
               TS_ASSUME_NETWORK_UP_FOR_TEST='true')
    save('daemon-environment.json', {k:env[k] for k in
         ('TS_UNIFIED_POLICY_FILE', 'TS_NO_LOGS_NO_SUPPORT', 'TS_ASSUME_NETWORK_UP_FOR_TEST')})
    return start([str(bin/'tailscaled'), '--tun=userspace-networking', '--state='+str(state),
                  '--socket='+str(sock), '--port=0', '--statedir='+str(root/'daemon')], 'daemon.log', env)

def running():
    deadline = time.monotonic()+30
    while time.monotonic()<deadline:
        try:
            s = cli('status', '--json')
            if s['BackendState']=='Running':
                return s
        except (RuntimeError, FileNotFoundError):
            pass
        time.sleep(.5)
    raise RuntimeError('daemon did not enter Running')

def takeover_ready(name):
    """Accepted config plus a lifecycle-writer read, not Running alone."""
    deadline = time.monotonic()+30
    expected = {'root':True, 'lease':True, 'auto_ipv6':False,
                'dns_ipv4_only':False, 'path_policy':False}
    while True:
        status = cli('debug', 'unified-policy', 'status', '--json')
        save(name+'-status.json', status)
        if (status.get('enabledModules') == expected and status.get('runtimeReady')
                and not status.get('degraded')
                and status.get('source_sha256') == hashlib.sha256(policy.read_bytes()).hexdigest()):
            plan = settled_preview('appc-route-adopt')
            save(name+'-runtime.json', plan)
            # connectorAction rejects missing consumers and stale ownerSnapshot.
            # Status.applied is a broader flag; it is not TTL readiness evidence.
            if (plan['Fence'] == status['acceptedFence']
                    and plan['Roots'] == ['*.example.test']
                    and plan['Control'] == ['198.51.100.0/24']):
                return plan
        if time.monotonic() >= deadline:
            raise RuntimeError('takeover runtime not ready; see '+name+'-status/runtime.json')
        time.sleep(.5)

def enable_takeover():
    save('policy.json', {'schema_version':2, 'enabled':True,
                        'app_connector_ttl':{'enabled':True}})
    deadline = time.monotonic()+30
    while True:
        try:
            reviewed = cli('debug', 'unified-policy', 'preview', '--json')
            break
        except RuntimeError as e:
            # Login/prefs publication can race this read-only inspection.
            # Re-read the requested bytes/fence; never retry an execute here.
            if 'policy_inputs_changed_retry' not in str(e) or time.monotonic() >= deadline:
                raise
            time.sleep(.5)
    save('policy-preview.json', reviewed)
    assert reviewed['schemaValid'] and reviewed['runtimeReady'], 'policy preview not ready'
    status = cli('debug', 'unified-policy', 'status', '--json')
    save('policy-before-reload.json', status)
    # A periodic file reload may already have accepted these bytes. Reload still
    # uses the currently observed generation; a CAS conflict fails closed.
    response = cli('debug', 'unified-policy', 'reload',
                   '--expect-generation='+str(status['acceptedFence']['Generation']),
                   '--expect-sha256='+reviewed['requested_sha256'])
    save('policy-reload.json', response)
    assert response['accepted'], 'policy reload not accepted'
    return takeover_ready('takeover-before-seed')

def seed_control_history(store, key, prefixes):
    """Offline synthetic unclaimed provenance, never an ownership/lease grant.

    A completed takeover restores Unclaimed from its journal, not _routeInfo.
    Preserve its fence, ledger, leases and receipts byte-for-byte as JSON values.
    Only rewrite the checksum envelope for the explicitly injected provenance.
    """
    journal_key = key+'||_appConnectorTTLV2'
    raw = base64.b64decode(store[journal_key]).decode()
    envelope = json.loads(raw)
    start = raw.index(':', raw.index('"Payload"'))+1
    start += len(raw[start:])-len(raw[start:].lstrip())
    journal, end = json.JSONDecoder().raw_decode(raw[start:])
    assert list(hashlib.sha256(raw[start:start+end].encode()).digest()) == envelope['SHA256'], 'journal checksum'

    assert journal['Schema'] == 2 and journal['Complete'] and not journal['Handoff']
    assert not journal['Transition']['After'].get('Leases'), 'nonempty fixture leases'
    history = {'Control':prefixes,
               'Domains':{}, 'Wildcards':['example.test']}
    journal['Unclaimed'] = history
    payload = json.dumps(journal, separators=(',', ':'), ensure_ascii=True)
    # Go json.RawMessage hashes the exact embedded bytes; do not reformat it.
    encoded = ('{"Payload":'+payload+',"SHA256":'+
               json.dumps(list(hashlib.sha256(payload.encode()).digest()))+'}').encode()
    store[journal_key] = base64.b64encode(encoded).decode()
    store[key+'||_routeInfo'] = base64.b64encode(json.dumps(history).encode()).decode()
    return {'kind':'synthetic Control-only unclaimed provenance',
            'count':len(prefixes), 'journal_key':journal_key,
            'changed_fields':['prefs.AdvertiseRoutes', 'journal.Unclaimed', '_routeInfo'],
            'ownership_or_leases_granted':False}

def preview(kind, *args):
    deadline = time.monotonic()+30
    while True:
        try:
            response = cli('debug', kind, '--source=r27-synthetic-control', *args)
        except RuntimeError:
            if time.monotonic()>deadline: raise
            time.sleep(.5)
            continue
        # DebugActionJSON returns featurepolicy.Inspection, not the plan itself.
        # command() has already retained the complete wire response in NNN.stdout.
        if not isinstance(response, dict) or not isinstance(response.get('clear_preview'), dict):
            raise ValueError(f'{kind}: expected object at response.clear_preview')
        return response['clear_preview']

def execute(kind, plan, *args):
    return cli('debug', kind, '--source=r27-synthetic-control', '--execute',
               '--expect-sha256='+plan['SnapshotHash'],
               '--expect-generation='+str(plan['Fence']['Generation']),
               '--expect-source-id='+str(plan['SourceID']), *args)

def settled_preview(kind, *args):
    """Wait for startup/prefs publications to stop changing the reviewed CAS.

    Only read-only previews repeat. Execute remains single-attempt and uses the
    exact last preview; any subsequent change still fails the daemon's CAS.
    """
    deadline = time.monotonic()+30
    previous, since = None, time.monotonic()
    while True:
        plan = preview(kind, *args)
        now = time.monotonic()
        if plan['SnapshotHash'] != previous:
            previous, since = plan['SnapshotHash'], now
        elif now-since >= 2:
            return plan
        if now >= deadline:
            raise RuntimeError(kind+': preview did not settle')
        time.sleep(.5)

try:
    if not Path('/proc/self/ns/net').exists():
        raise RuntimeError('Linux isolated network namespace required; CLI 810 not run')
    assert os.readlink('/proc/self/ns/net') != os.readlink('/proc/1/ns/net'), 'isolated network namespace required'
    save('binaries.json', {n:hashlib.sha256((bin/n).read_bytes()).hexdigest() for n in ('control','tailscale','tailscaled')})
    save('policy.json', {'schema_version':2, 'enabled':False})
    c = start([str(bin/'control'), '--bind=127.0.0.1', '--appc-fixture'], 'control.log', stdout=subprocess.PIPE)
    assert select.select([c.stdout], [], [], 10)[0], 'control startup timeout'
    info = json.loads(c.stdout.readline()); save('control.json', info)
    assert info['controlURL'].startswith('http://127.0.0.1:')
    with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(info['controlURL']+'/healthz', timeout=5) as response:
        assert response.read()==b'ok\n'
    d = daemon()
    for _ in range(100):
        if sock.exists(): break
        if d.poll() is not None: raise RuntimeError('daemon exited')
        time.sleep(.1)
    phase = 'login'
    cli('up', '--login-server='+info['controlURL'], '--accept-dns=false',
        '--advertise-connector', '--hostname=r27-isolated', '--timeout=20s')
    before = running(); save('running-before.json', before)
    gates['login'] = 'PASS'
    phase = 'enable-takeover'
    cli('set', '--advertise-routes=203.0.113.0/24', '--advertise-exit-node=true')
    enable_takeover()
    gates['takeover_ready'] = 'PASS'
    phase = 'seed-history'
    stop(d)
    shutil.copyfile(state, root/'before-seed.state')
    store = json.loads(state.read_text())
    keys = [k for k in store if k.startswith('profile-') and '||' not in k]
    assert len(keys)==1, keys
    key = keys[0]
    prefs = json.loads(base64.b64decode(store[key]))
    prefixes = [f'192.0.{i//250+1}.{i%250+1}/32' for i in range(810)]
    retain = ['203.0.113.0/24','198.51.100.0/24','0.0.0.0/0','::/0']
    assert set(prefs['AdvertiseRoutes']) == set(retain), 'baseline retention routes missing'
    prefs['AdvertiseRoutes'] = prefixes+retain
    def put(k,v): store[k] = base64.b64encode(json.dumps(v).encode()).decode()
    put(key,prefs)
    save('seed-history.json', seed_control_history(store, key, prefixes))
    state.write_text(json.dumps(store))
    shutil.copyfile(state, root/'seeded.state')
    evidence = hashlib.sha256((root/'seeded.state').read_bytes()).hexdigest()
    phase = 'adopt'
    d = daemon(); running()
    initial = takeover_ready('takeover-after-seed'); save('adopt-initial.json', initial)
    gates['takeover_after_seed'] = 'PASS'
    manifest = {'SchemaVersion':1,'ProfileID':initial['Fence']['ProfileID'],
                'LegacySourceID':initial['LegacySourceID'],'Source':'r27-synthetic-control','Entries':[]}
    for i, prefix in enumerate(prefixes):
        manifest['Entries'].append({'Reference':{'AssignedRoot':'*.example.test','Domain':f'd{i}.example.test','IP':prefix[:-3]},
          'Reviewed':True,'ReviewedBy':'isolated-fixture-generator','Evidence':'synthetic seeded.state; never production evidence','EvidenceSHA256':evidence})
    save('manifest.json',manifest)
    save('claims.json',[e['Reference'] for e in manifest['Entries']])
    args = ['--manifest='+str(root/'manifest.json'), '--claims='+str(root/'claims.json')]
    plan = settled_preview('appc-route-adopt', *args); save('adopt-preview.json',plan)
    save('adopt-eligibility.json', {'eligible':sum(bool(e['Eligible']) for e in plan['Entries']),
         'reasons':{reason:sum(e['Reason']==reason for e in plan['Entries'])
                    for reason in {e['Reason'] for e in plan['Entries']}}})
    assert len([e for e in plan['Entries'] if e['Eligible']])==810, 'not exactly 810 eligible'
    assert {e['Prefix'] for e in plan['Entries'] if e['Eligible']} == set(prefixes)
    save('adopt-execute.json', execute('appc-route-adopt',plan,*args))
    snapshot('after-adopt')
    gates['adopt810'] = 'PASS'
    phase = 'reset'
    plan = settled_preview('appc-route-reset'); save('reset-preview.json',plan)
    assert set(plan['Withdraw'])==set(prefixes), 'Withdraw != exact 810 fixture prefixes'
    assert set(retain)<=set(plan['Retain']), 'manual/static/exit retention missing'
    save('reset-execute.json',execute('appc-route-reset',plan))
    after = cli('debug','prefs'); save('prefs-after-reset.json',after)
    assert set(after['AdvertiseRoutes'])==set(retain), 'reset changed retained routes'
    snapshot('after-reset')
    gates['reset810_retain'] = 'PASS'
    phase = 'post-commit-restart'
    stop(d, kill=True)
    d = daemon(); restarted = running(); save('running-restarted.json',restarted)
    takeover_ready('takeover-after-restart')
    assert restarted['Self']['ID']==before['Self']['ID'], 'identity changed'
    assert set(cli('debug','prefs')['AdvertiseRoutes'])==set(retain)
    snapshot('after-restart')
    gates['post_commit_SIGKILL_restart'] = 'PASS'
    save('result.json', {'result':'PARTIAL', 'gates':gates, 'cli810':'PASS', 'post_commit_SIGKILL_restart':'PASS',
        'blocked':['real DNS packet relearn','profile switch / takeover enable-disable OS matrix','six persistent-write SIGKILL barriers'],
        'history':'offline synthetic Control injection; real daemon, real CLI and Unix LocalAPI'})
    raise SystemExit(2)
except Exception as e:
    save('result.json', {'result':'BLOCKED','cli810':'BLOCKED','phase':phase,'gates':gates,'error':str(e)})
    raise
finally:
    for proc in reversed(processes): stop(proc)
    for log in logs: log.close()
    if (root/'daemon.log').exists():
        lines = (root/'daemon.log').read_text(errors='replace').splitlines()
        save('lifecycle-diagnostics.json', {term:[line for line in lines if term in line]
             for term in ('configuration requires lifecycle transaction', 'stale policy fence',
                          'stale backend fence', 'consumer unavailable')})
    commands.close()
