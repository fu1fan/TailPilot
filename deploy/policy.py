#!/usr/bin/env python3
"""Durable, explicitly approved TTL-only policy handoff for committed releases.

A published intent is rolled forward, never undone by replaying state/routes.
The daemon remains the sole ownership writer and recovers its own journal.
"""
import hashlib
import json
from pathlib import Path
import time
import native
import plan


def status(t):
    return json.loads(t.cli('debug', 'unified-policy', 'status', '--json'))


def validate_config(config, enable):
    plan.validate_schema(config, plan.read(plan.policy_schema_path()))
    native.require(config.get('machine') in ('idcfast', 'residential'), 'idcfast/residential policy required')
    if enable:
        native.require(config.get('enabled') is True and config.get('app_connector_ttl', {}).get('enabled') is True,
                       'TTL enable configuration required')
        for key in ('auto_ipv6', 'dns_ipv4_only', 'path_policy'):
            native.require(not config.get(key, {}).get('enabled', False), 'unrelated module enabled')
        native.require(not config.get('path_policy', {}).get('rules') and not config.get('dns_ipv4_only', {}).get('targets'), 'unrelated rules')
    else:
        plan.all_off_config(config)


def consumer_ready(t, s):
    # The sealed v2 release does not advance the broad status.applied flag for
    # TTL. Use its lifecycle-authority read, as in the R33 native acceptance.
    try:
        result = json.loads(t.cli('debug', 'appc-route-adopt', '--source', 'deployment-policy-readiness'))
        preview = result['clear_preview']
        ready = (preview['Fence'] == s['acceptedFence'] and type(preview['SourceID']) is int and preview['SourceID'] > 0)
        if ready:
            s['ttlConsumerFence'] = preview['Fence']
            s['ttlSourceID'] = preview['SourceID']
        return ready
    except (ValueError, KeyError, TypeError):
        return False


def active(t, s, expected, enable):
    modules = s.get('enabledModules', {})
    return (s.get('schemaValid') and s.get('runtimeReady') and not s.get('degraded') and
            s.get('source_sha256') == expected and bool(modules.get('lease')) == enable and
            bool(modules.get('root')) == enable and
            not any(v for k, v in modules.items() if k not in ('root', 'lease')) and
            (consumer_ready(t, s) if enable else s.get('applied')))


def installed(t):
    native.require(plan.digest(t.drop) == t.journal()['candidateSHA256'], 'release no longer installed')
    pid = t.h.ctl('show', native.UNIT, '--property=MainPID', '--value').strip()
    native.require(pid.isdigit() and int(pid) > 0, 'daemon unavailable')
    native.require(plan.digest(t.h.path('/proc/'+pid+'/exe')) == t.journal()['daemonSHA256'], 'running release mismatch')


def start(t, candidate, operation, expected, generation, approval):
    native.require(t.journal()['phase'] == 'committed' and t.journal()['approved'] == t.approved, 'policy requires committed deployment')
    installed(t)
    native.require(plan.ID.fullmatch(operation), 'unique policy operation ID required')
    native.private(candidate)
    raw = Path(candidate).read_bytes()
    config = plan.read(candidate)
    enable = config.get('enabled') is True
    validate_config(config, enable)
    desired = hashlib.sha256(raw).hexdigest()
    native.require(approval == {'operation': operation, 'beforeSHA256': expected,
                               'generation': generation, 'configurationSHA256': desired}, 'policy approval mismatch')
    policy = t.stage / 'policy.json'
    native.require(plan.digest(policy) == expected, 'policy file CAS conflict')
    s = status(t)
    native.require(s.get('source_sha256') == expected and s.get('acceptedFence', {}).get('Generation') == generation and
                   active(t, s, expected, bool(s.get('enabledModules', {}).get('lease'))), 'live policy CAS conflict')
    native.require(not any(v for k, v in s.get('enabledModules', {}).items() if k not in ('root', 'lease')), 'unrelated active module')
    jf = t.d / 'policy-intent.json'
    if jf.exists():
        native.require(plan.read(jf)['phase'] == 'complete', 'policy recovery pending')
    saved = t.d / ('policy-' + operation)
    native.require(not saved.exists(), 'policy operation already used')
    saved.mkdir(mode=0o700)
    t.install(saved/'before.json', policy.read_bytes())
    t.install(saved/'candidate.json', raw)
    # Private evidence only; no state is ever restored by this adapter.
    for i, name in enumerate(t.n['stateFiles']):
        t.install(saved/('state-backup-'+str(i)), t.h.path(name).read_bytes())
    t.install(saved/'status-before.json', json.dumps(s))
    t.install(saved/'approval.json', json.dumps(approval))
    t.install(t.d/'policy.py', Path(__file__).read_bytes())
    # Existing native payload may predate this adapter; install separately, leaving
    # original release-recovery payload and its pinned evidence untouched.
    for name in ('native.py', 'plan.py'):
        t.install(saved/name, Path(__file__).with_name(name).read_bytes())
    t.install(saved/'schema-v2.json', plan.policy_schema_path().read_bytes())
    t.install(saved/'policy.py', Path(__file__).read_bytes())
    unit = t.prefix + '-policy'
    command = '/usr/bin/python3 ' + str(saved/'policy.py') + ' ' + str(t.d)
    service = '[Unit]\nAfter=tailscaled.service\n[Service]\nType=oneshot\nTimeoutStartSec=90\nExecStart=' + command + '\n'
    timer = '[Unit]\nDescription=Durable TTL handoff recovery\n[Timer]\nOnBootSec=5s\nOnUnitInactiveSec=10s\n[Install]\nWantedBy=timers.target\n'
    for suffix, data in (('.service', service), ('.timer', timer)):
        t.install(t.h.path('/etc/systemd/system/'+unit+suffix), data)
    t.h.ctl('daemon-reload')
    t.h.ctl('enable', '--now', unit+'.timer')
    # Intent precedes any live file write; reboot/timer can finish after caller exit.
    plan.atomic(jf, dict(phase='pending', operation=operation, before=expected, desired=desired,
                        generation=generation, fence=s['acceptedFence'], bootID=t.h.now()[2], invocation=t.h.ctl('show', native.UNIT, '--property=InvocationID', '--value').strip(), enable=enable, deploymentID=t.p['deploymentID'],
                        planSHA256=t.approved, saved=str(saved)))
    t.h.ctl('start', unit+'.timer')
    t.h.ctl('start', '--no-block', unit+'.service')


def recover(t):
    jf = t.d/'policy-intent.json'
    j = plan.read(jf)
    native.require(j['planSHA256'] == t.approved and j['deploymentID'] == t.p['deploymentID'], 'policy intent binding')
    if j['phase'] == 'complete':
        t.h.ctl('stop', t.prefix+'-policy.timer')
        return
    native.require(t.journal()['phase'] == 'committed', 'release changed during policy handoff')
    installed(t)
    saved = t.d / ('policy-' + j['operation'])
    native.require(str(saved) == j['saved'], 'policy backup path')
    candidate = saved/'candidate.json'
    native.require(plan.digest(candidate) == j['desired'], 'policy candidate drift')
    validate_config(plan.read(candidate), j['enable'])
    policy = t.stage/'policy.json'
    current = plan.digest(policy)
    native.require(current in (j['before'], j['desired']), 'foreign policy edit; recovery refused')
    t.identity()
    s = status(t)
    native.require(s.get('acceptedFence', {}).get('ProfileID') == j['fence']['ProfileID'], 'profile changed during policy handoff')
    if current == j['before']:
        native.require(s.get('source_sha256') == j['before'] and
                       (s.get('acceptedFence') == j['fence'] or ((t.h.now()[2] != j['bootID'] or t.h.ctl('show', native.UNIT, '--property=InvocationID', '--value').strip() != j['invocation']) and s.get('acceptedFence', {}).get('ProfileID') == j['fence']['ProfileID'] and active(t, s, j['before'], bool(s.get('enabledModules', {}).get('lease'))))), 'pre-publication fence changed; recovery refused')
        t.install(policy, candidate.read_bytes())
    # The file watcher may already have consumed the exact candidate. Never
    # interpret a CAS rejection as success; require lifecycle readiness readback below.
    if s.get('source_sha256') != j['desired']:
        restarted = t.h.now()[2] != j['bootID'] or t.h.ctl('show', native.UNIT, '--property=InvocationID', '--value').strip() != j['invocation']
        native.require(s.get('source_sha256') == j['before'] and
                       (s['acceptedFence'] == j['fence'] or restarted), 'foreign accepted policy/fence')
        try:
            t.cli('debug', 'unified-policy', 'reload', '--expect-sha256='+j['desired'],
                  '--expect-generation='+str(s['acceptedFence']['Generation']))
        except ValueError:
            pass
    end = time.monotonic()+30
    while time.monotonic() < end:
        s = status(t)
        if active(t, s, j['desired'], j['enable']):
            t.identity()
            native.require(plan.digest(policy) == j['desired'], 'policy changed during acceptance')
            t.install(saved/'status-after.json', json.dumps(s))
            j.update(phase='complete', acceptedFence=s['acceptedFence'])
            plan.atomic(jf, j)
            plan.atomic(saved/'result.json', j)
            t.h.ctl('stop', t.prefix+'-policy.timer')
            return
        t.h.sleep(.25)
    if not j.get('recoveryRestart'):
        # Restart the same pinned daemon once to replay its existing durable
        # ownership intent; never launch a second writer or rewind state.
        j['recoveryRestart'] = True
        plan.atomic(jf, j)
        t.h.ctl('restart', native.UNIT)
    raise ValueError('handoff pending; durable timer will retry readback; retain journal and OOB')


if __name__ == '__main__':
    import os
    import sys
    try:
        native.require(sys.platform == 'linux' and os.geteuid() == 0, 'Linux root required')
        d = Path(sys.argv[1])
        native.require(d.parent == Path(native.BASE) and plan.ID.fullmatch(d.name), 'transaction path')
        native.private(d/'plan.json')
        p = plan.load(d/'plan.json')
        t = native.Transaction(p, plan.digest(d/'plan.json'))
        with t.lock():
            recover(t)
    except Exception:
        sys.exit('policy recovery refused/pending; retain private journal and OOB')
