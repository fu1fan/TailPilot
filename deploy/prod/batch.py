#!/usr/bin/env python3
"""R34 production batches. Offline by default; no credentials/control API client."""
import argparse
import contextlib
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import time

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import plan

CHECKS = ('oob', 'tailnetSSH', 'appConnectorEgress', 'dns', 'derp', 'relay',
          'codex', 'deepseek', 'routeCounts', 'longConnection')
ACTIONS = {
 '00-readonly': ('review', 'release', 'probe', 'plan'),
 '10-alloff': ('review', 'rehearse', 'start', 'verify', 'commit', 'cleanup'),
 '20-takeover': ('review', 'config', 'adopt', 'reset', 'reset-rollback', 'enable'),
 '30-acceptance': ('review', 'check'),
 '90-rollback': ('review', 'disable', 'release', 'reverse'),
}


def require(ok, why):
    if not ok:
        raise ValueError(why)


def sha(path):
    require(Path(path).is_file() and not Path(path).is_symlink(), 'regular file required')
    return plan.digest(path)


def write_new(path, value):
    data = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as out:
        out.write(data); out.flush(); os.fsync(out.fileno())
    return hashlib.sha256(data).hexdigest()


def private(path):
    for item in (Path(path), *Path(path).parents):
        s = item.lstat()
        require(not item.is_symlink() and s.st_uid == 0 and not s.st_mode & 0o022,
                'execute requires root-owned non-writable paths')
    require(Path(path).is_file() and not Path(path).stat().st_mode & 0o077,
            'private approval/evidence required')


def run(argv, timeout=120, data=None):
    # Never inherit SSH agents, shell startup, credentials or print child stderr.
    r = subprocess.run(argv, input=data, capture_output=True, timeout=timeout,
                       env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C',
                            'PYTHONDONTWRITEBYTECODE': '1'})
    require(r.returncode == 0, 'command failed; STOP, preserve transaction and OOB')
    return r.stdout.decode()


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    return mod


def release_check(directory, expected):
    require(isinstance(expected, str) and plan.HEX.fullmatch(expected), 'release SHA256 required')
    require(sha(Path(directory) / 'manifest.json') == expected, 'release manifest mismatch')
    b = module('prod_bundle', HERE.parent.parent / 'release/bundle.py')
    data = b.directory(directory)
    m = json.loads(data['manifest.json'])
    require(m['schemaVersion'] == 2, 'schema v2 required')
    require(data['config/schema-v2.json'] == plan.policy_schema_path().read_bytes(),
            'schema differs from reviewed executor')
    for name in ('tailscale', 'tailscaled', 'route-reconcile'):
        raw = data['linux-amd64/' + name]
        require(raw[:5] == b'\x7fELF\x02' and raw[18:20] == b'\x3e\x00', 'amd64 ELF required')
    return m


def load_target(a):
    require(a.target, 'explicit reviewed target file required; no production defaults')
    t = plan.read(a.target)
    require(set(t) == {'machine', 'host', 'stableID', 'oobHost', 'releaseSHA256'} and
            t['machine'] == 'idcfast', 'only idcfast target supported; residential prohibited')
    require(all(isinstance(v, str) and v for v in t.values()), 'invalid target fields')
    require(plan.ID.fullmatch(t['host']) and plan.ID.fullmatch(t['stableID']), 'invalid target identity')
    import ipaddress
    ipaddress.ip_address(t['oobHost'])
    require(plan.HEX.fullmatch(t['releaseSHA256']) and
            a.release_sha256 == t['releaseSHA256'], 'target release mismatch')
    a.target_data = t


def bindings(a):
    require(a.plan and a.plan_sha256 and a.release_sha256 and a.oob_sha256,
            'explicit plan / plan-sha256 / release-sha256 / oob-sha256 required')
    p = plan.load(a.plan)
    require(sha(a.plan) == a.plan_sha256 and p['host'] == a.target_data['host'] and p['stableID'] == a.target_data['stableID'],
            'plan hash or target mismatch; residential prohibited')
    require(a.release_sha256 == p['releaseSHA256'] == a.target_data['releaseSHA256'], 'release binding mismatch')
    require(p['cohort'] == 'first', 'only idcfast first cohort supported')
    require(a.oob_sha256 == p['oobSHA256'] == sha(p['oobEvidence']), 'OOB hash mismatch')
    require('native' in p, 'native contract required')
    return p


def authorize(a, p):
    require(a.approval, 'approval required')
    private(a.target); private(a.plan); private(a.approval); private(p['oobEvidence'])
    proof = plan.read(a.approval)
    require(proof.get('approvedPlanSHA256') == a.plan_sha256 and
            proof.get('deploymentID') == p['deploymentID'] and proof.get('host') == p['host'] and
            proof.get('expiresUnix', 0) > time.time() and proof.get('serialWindowExclusive') is True,
            'approval binding/expiry/window mismatch')
    require(proof.get('targetSHA256') == sha(a.target), 'target approval mismatch')
    require(a.batch + ':' + a.action in proof.get('prodActions', []), 'action not approved')
    require(proof.get('oobSHA256') == a.oob_sha256 and proof.get('releaseSHA256') == p['releaseSHA256'],
            'approval OOB/release mismatch')
    plan.evidence(p['oobEvidence'], a.oob_sha256, p, 'oob')
    require(plan.read(p['oobEvidence']).get('host') == p['host'], 'OOB host mismatch')
    for key in ('excludePeers', 'excludeDomains'):
        require(proof.get(key) == p[key], 'approval exclusions mismatch')
    require(proof.get('windowStartUnix', float('inf')) <= time.time() <
            proof.get('windowEndUnix', 0), 'outside approved window')
    return proof


def local_target(p):
    require(sys.platform == 'linux' and os.geteuid() == 0 and platform.node() == p['host'],
            'execute only inside target Linux root OOB session')
    status = json.loads(run([p['native']['cli'], '--socket=' + p['native']['socket'], 'status', '--json']))
    require(status['BackendState'] == 'Running' and status['Self']['ID'] == p['stableID'],
            'live StableID/Running mismatch')


@contextlib.contextmanager
def lock():
    # Supplement native machine-global lock; never wait behind another batch.
    path = Path('/run/lock/unified-prod-batch.lock')
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        require(os.fstat(fd).st_uid == 0, 'foreign batch lock')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)


def native_args(a, p, phase):
    cmd = ['/bin/bash', str(HERE.parent / (phase + '.sh')), '--execute', '--plan', a.plan,
           '--deployment-id', p['deploymentID'], '--host', p['host'], '--stable-id', p['stableID'],
           '--release-sha256', p['releaseSHA256'], '--approved-plan-sha256', a.plan_sha256,
           '--approval', a.approval]
    if phase == 'rehearse': cmd += ['--rehearsal']
    if phase == 'commit':
        require(a.acceptance_sha256, 'fresh acceptance hash required')
        cmd += ['--acceptance-sha256', a.acceptance_sha256]
    return cmd


def journal(p):
    return plan.read(Path('/var/lib/tailscale-unified-deploy') / p['deploymentID'] / 'journal.json')


def acceptance(e, p, j, generation):
    require(j.get('phase') == 'verified' and time.time() < j['wallDeadline'],
            'acceptance requires verified pending transaction before deadline')
    for key in ('deploymentID', 'host', 'stableID', 'releaseSHA256', 'configurationSHA256'):
        require(e.get(key) == p[key], 'acceptance binding mismatch')
    require(e.get('kind') == 'external-e2e' and e.get('passed') is True and
            e.get('expiresUnix', 0) > time.time() and e.get('observedUnix', 0) >= j['wallDeadline'] - p['deadlineSeconds'] and
            e.get('observedUnix', float('inf')) <= time.time() and
            e.get('deadlineUnix') == j['wallDeadline'] and e.get('generation') == generation,
            'acceptance stale/failed/deadline/fence mismatch')
    require(set(e.get('checks', {})) == set(CHECKS), 'incomplete acceptance matrix')
    for name in CHECKS:
        item = e['checks'][name]
        require(item.get('passed') is True and item.get('observer') and item.get('evidenceSHA256') and
                plan.HEX.fullmatch(item['evidenceSHA256']) and item.get('measurement'),
                'acceptance check failed or evidence missing')
    counts = e['checks']['routeCounts'].get('counts', {})
    require(set(counts) == {'advertisedBefore', 'advertisedAfter', 'enabledBefore', 'enabledAfter'},
            'separate advertised/enabled counts required')
    require(all(type(v) is int and v >= 0 for v in counts.values()) and
            counts['advertisedBefore'] == counts['advertisedAfter'] and
            counts['enabledBefore'] == counts['enabledAfter'], 'unexplained all-off route delta')


def cli(p):
    return ['/usr/local/lib/tailscale-unified/' + p['releaseID'] + '/tailscale',
            '--socket=' + p['native']['socket']]


def live_policy(p):
    value = json.loads(run(cli(p) + ['debug', 'unified-policy', 'status', '--json']))
    require(value.get('schemaValid') is True and value.get('runtimeReady') is True and
            value.get('applied') is True, 'policy not applied/ready')
    return value


def alloff(a, p):
    if a.action == 'commit':
        private(p['externalEvidence'])
        require(sha(p['externalEvidence']) == a.acceptance_sha256, 'acceptance hash mismatch')
        acceptance(plan.read(p['externalEvidence']), p, journal(p),
                   live_policy(p)['acceptedFence']['Generation'])
    phases = ('preflight', 'backup', 'stage', 'arm', 'switch') if a.action == 'start' else (a.action,)
    for phase in phases:
        run(native_args(a, p, phase), timeout=240)
    if a.action in ('start', 'rehearse'):
        print('QUEUED ONLY: inspect journal via OOB. No automatic wait/retry/commit.')


def preview(a, p):
    require(a.source and len(a.source) <= 200, 'audit source required')
    verb = 'appc-route-adopt' if a.action == 'adopt' else 'appc-route-reset'
    cmd = cli(p) + ['debug', verb, '--source', a.source]
    if a.action != 'adopt':
        require(not a.manifest and not a.claims, 'claims/manifest only valid for adopt')
    if a.action == 'adopt':
        if a.manifest: cmd += ['--manifest', a.manifest]
        if a.claims: cmd += ['--claims', a.claims]
    return cmd


def route_binding(v, a):
    require(type(a.expect_generation) is int and a.expect_generation >= 0 and
            isinstance(a.expect_sha256, str) and plan.HEX.fullmatch(a.expect_sha256), 'invalid CAS parameters')
    require(v.get('Source') == a.source and v.get('SnapshotHash') == a.expect_sha256 and
            v['Fence']['Generation'] == a.expect_generation and v.get('SourceID') == a.expect_source_id and
            type(a.expect_source_id) is int and a.expect_source_id > 0, 'preview CAS binding mismatch')


def takeover(a, p, approval=None):
    if a.execute:
        for path in (a.claims, a.manifest):
            if path: private(path)
    cmd = preview(a, p)
    result = json.loads(run(cmd))
    v = result['clear_preview']
    if a.output:
        require(a.write_output, 'evidence output requires --write-output')
        write_new(a.output, result)
    # This interface is non-secret provenance, not debug prefs or identity state.
    print(json.dumps(v, sort_keys=True))
    if not a.execute: return
    route_binding(v, a)
    approved = approval.get('takeover', {})
    require(approved == {'source': a.source, 'hash': a.expect_sha256,
                        'generation': a.expect_generation, 'sourceID': a.expect_source_id,
                        'manifestSHA256': sha(a.manifest) if a.manifest else None,
                        'claimsSHA256': sha(a.claims) if a.claims else None}, 'takeover approval mismatch')
    if a.action == 'adopt':
        require(a.claims, 'no safe claims: preview only; Lead must select references')
        selected = plan.read(a.claims)
        eligible = [e['Reference'] for e in v['Entries'] if e['Eligible'] is True]
        require(isinstance(selected, list) and selected and all(c in eligible for c in selected),
                'claims empty/unknown/ineligible; preview only')
        require(len({json.dumps(c, sort_keys=True) for c in selected}) == len(selected), 'duplicate claims')
    cmd = cmd + ['--rollback' if a.action == 'reset-rollback' else '--execute',
            '--expect-sha256', a.expect_sha256, '--expect-generation', str(a.expect_generation),
            '--expect-source-id', str(a.expect_source_id)]
    run(cmd)
    print('APPLIED; STOP for fresh preview and real DNS relearn observations. No synthetic DNS evidence.')


def config_value(a):
    c = plan.read(a.configuration) if a.configuration else {
        'schema_version': 2, 'machine': 'idcfast', 'enabled': True,
        'app_connector_ttl': {'enabled': True}}
    plan.validate_schema(c, plan.read(plan.policy_schema_path()))
    require(c.get('machine') == 'idcfast' and c.get('enabled') is True and
            c.get('app_connector_ttl', {}).get('enabled') is True, 'TTL-only idcfast v2 required')
    for key in ('auto_ipv6', 'dns_ipv4_only', 'path_policy'):
        require(not c.get(key, {}).get('enabled', False), 'other modules must remain off')
    require(not c.get('dns_ipv4_only', {}).get('targets') and not c.get('path_policy', {}).get('rules'),
            'no unrelated targets/rules')
    return c


def change_policy(a, p, approved):
    require(a.configuration and a.operation and a.expect_sha256 and a.expect_generation is not None,
            'policy configuration/operation/hash/generation required')
    native = module('native', HERE.parent / 'native.py')
    sys.modules['native'] = native
    policy = module('policy_adapter', HERE.parent / 'policy.py')
    config = plan.read(a.configuration)
    policy.validate_config(config, a.action == 'enable')
    transaction = native.Transaction(p, a.plan_sha256)
    with transaction.lock():
        policy.start(transaction, a.configuration, a.operation, a.expect_sha256,
                     a.expect_generation, approved.get('policy'))
    print('QUEUED: inspect policy-intent.json; complete and lifecycle readiness required before next action.')


def readonly(a):
    if a.action == 'release':
        require(a.release_dir and a.release_sha256, 'release-dir/hash required')
        m = release_check(a.release_dir, a.release_sha256)
        print(json.dumps({'releaseID': m['releaseID'], 'manifestSHA256': a.release_sha256, 'schemaVersion': 2}))
    elif a.action == 'probe':
        require(a.connect_readonly and not a.execute, 'probe requires --connect-readonly (not execute)')
        require(a.oob_key and a.known_hosts and a.remote_cli and a.socket, 'key path/known-hosts/remote-cli/socket required')
        for value in (a.oob_key, a.known_hosts, a.remote_cli, a.socket):
            require(Path(value).is_absolute(), 'absolute paths required')
        # -F /dev/null disables user ProxyCommand/Match exec; identities/host key pinned.
        args = ['/usr/bin/ssh', '-F', '/dev/null', '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
                '-o', 'IdentityAgent=none', '-o', 'StrictHostKeyChecking=yes', '-o', 'UpdateHostKeys=no',
                '-o', 'ConnectTimeout=10', '-o', 'ConnectionAttempts=1', '-o', 'ClearAllForwardings=yes',
                '-o', 'UserKnownHostsFile=' + a.known_hosts, '-i', a.oob_key, 'root@' + a.target_data['oobHost'],
                '/usr/bin/python3 -']
        # Inputs are JSON constants inside code, never shell-interpolated remote arguments.
        require(a.release_dir and a.release_sha256, 'probe needs verified local release-dir/hash')
        manifest = release_check(a.release_dir, a.release_sha256)
        data = ('PARAMS=' + repr({'cli': a.remote_cli, 'socket': a.socket,
                'releaseID': manifest['releaseID'],
                'daemonSHA256': manifest['files']['linux-amd64/tailscaled']}) + '\n').encode()
        data += (HERE / 'probe.py').read_bytes()
        result = json.loads(run(args, timeout=60, data=data))
        require(result['host'] == a.target_data['host'] and result['stableID'] == a.target_data['stableID'] and result['allOff'] is True and result['backend'] == 'Running' and result['service'] == 'active',
                'live identity/all-off mismatch')
        require(result['finalReleaseInstalled'] is False, 'final release already installed')
        if a.output:
            require(a.write_output, 'evidence output requires --write-output')
            write_new(a.output, result)
        print(json.dumps(result, sort_keys=True))
    elif a.action == 'plan':
        require(a.observe_local and a.planner_inputs and a.output and a.write_output,
                'local observation, planner-inputs/output and write-output required')
        require(sys.platform == 'linux' and platform.node() == a.target_data['host'] and os.geteuid() == 0, 'plan only on target root')
        m = module('prod_planner', HERE.parent / 'make-plan.py')
        inputs = plan.read(a.planner_inputs)
        allowed = {'release_dir', 'configuration', 'deployment_id', 'exclusions_peers', 'exclusions_domains',
                   'oob_evidence', 'fallback_evidence', 'external_evidence', 'backup_inventory', 'deadline_seconds'}
        require(not set(inputs) - allowed, 'unknown planner input')
        release_check(inputs['release_dir'], a.release_sha256)
        args = dict(host=a.target_data['host'], output=a.output, fallback_evidence=None, external_evidence=None,
                    backup_inventory=None, deadline_seconds=900, bundle=None)
        args.update(inputs)
        require(60 <= args['deadline_seconds'] <= 1800, 'deadline outside 60..1800')
        p = m.generate(argparse.Namespace(**args))
        require(p['stableID'] == a.target_data['stableID'], 'plan StableID mismatch')
        digest = write_new(a.output, p)
        templates = m.templates(p)
        templates['approval'].update(targetSHA256=sha(a.target), prodActions=[], releaseSHA256=a.release_sha256, oobSHA256=None,
                                     windowStartUnix=None, windowEndUnix=None)
        write_new(a.output + '.templates.json', templates)
        print('Plan SHA256=' + digest + '; templates UNAPPROVED')


def parser():
    ap = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    ap.add_argument('batch', choices=ACTIONS)
    ap.add_argument('--action', default='review')
    modes = ap.add_mutually_exclusive_group()
    modes.add_argument('--execute', action='store_true')
    modes.add_argument('--dry-run', action='store_true')
    ap.add_argument('--connect-readonly', action='store_true')
    ap.add_argument('--observe-local', action='store_true')
    ap.add_argument('--write-output', action='store_true')
    for name in ('target', 'plan', 'plan-sha256', 'approval', 'release-sha256', 'oob-sha256', 'release-dir',
                 'acceptance-sha256', 'oob-key', 'known-hosts', 'remote-cli', 'socket', 'output',
                 'planner-inputs', 'operation', 'source', 'manifest', 'claims', 'expect-sha256', 'configuration'):
        ap.add_argument('--' + name)
    for name in ('expect-generation', 'expect-source-id'):
        ap.add_argument('--' + name, type=int)
    return ap


def main(argv=None):
    raw = sys.argv[1:] if argv is None else argv
    options = [v.split('=')[0] for v in raw if v.startswith('--')]
    require(len(set(options)) == len(options), 'duplicate option')
    a = parser().parse_args(raw)
    require(a.action in ACTIONS[a.batch], 'action not supported by this batch')
    require(not (a.execute and (a.connect_readonly or a.observe_local)), 'conflicting modes')
    require(not a.execute or a.action != 'review', 'execute needs explicit action')
    os.umask(0o077)
    if a.action == 'review':
        print(json.dumps({'mode': 'dry-run', 'target': 'explicit --target required', 'actions': ACTIONS[a.batch], 'network': False,
                          'notice': 'No approval. Read README.md; unsupported upgrades fail closed.'}))
        return
    require(not a.dry_run or not (a.connect_readonly or a.observe_local), 'dry-run cannot observe a host')
    if a.batch == '00-readonly':
        load_target(a)
        require(not a.execute, 'readonly has no execute mode')
        readonly(a); return
    if a.batch == '20-takeover' and a.action == 'config':
        require(not a.execute, 'offline config has no execute mode')
        c = config_value(a)
        if a.dry_run or not a.write_output:
            print(json.dumps({'mode': 'dry-run', 'candidate': c, 'writes': False}))
        else:
            require(a.output, 'candidate file requires --output')
            print('Candidate SHA256=' + write_new(a.output, c))
        return
    load_target(a)
    p = bindings(a)
    if not a.execute:
        if a.observe_local and a.batch == '20-takeover' and a.action in ('adopt', 'reset', 'reset-rollback'):
            local_target(p); takeover(a, p)
        else:
            require(not a.observe_local and not a.connect_readonly, 'observation mode not supported here')
            print(json.dumps({'mode': 'dry-run', 'batch': a.batch, 'action': a.action,
                              'planSHA256': a.plan_sha256, 'network': False, 'writes': False}))
        return
    proof = authorize(a, p)
    # Rollback must remain possible when service is down, so skip readiness here.
    if a.batch == '90-rollback':
        require(sys.platform == 'linux' and os.geteuid() == 0 and platform.node() == a.target_data['host'], 'target root required')
    else:
        local_target(p)
    with lock():
        if a.batch == '90-rollback':
            if a.action == 'disable':
                change_policy(a, p, proof)
                return
            if a.action == 'reverse':
                run(native_args(a, p, 'reverse'), timeout=240)
                require(journal(p)['phase'] == 'rolled-back', 'reverse incomplete')
                return
            require(journal(p)['phase'] not in ('committed',),
                    'committed rollback is a native no-op: STOP for reviewed reverse migration; no success claimed')
            run(native_args(a, p, 'rollback'), timeout=240)
            require(journal(p)['phase'] == 'rolled-back', 'rollback incomplete; retain OOB')
        elif a.batch == '10-alloff':
            release_check(p['releaseDirectory'], a.release_sha256)
            alloff(a, p)
        elif a.batch == '20-takeover':
            release_check(p['releaseDirectory'], a.release_sha256)
            require(journal(p)['phase'] == 'committed', 'takeover requires committed all-off')
            if a.action == 'enable': change_policy(a, p, proof)
            else: takeover(a, p, proof)
        elif a.batch == '30-acceptance':
            private(p['externalEvidence'])
            require(sha(p['externalEvidence']) == a.acceptance_sha256 == proof.get('acceptanceSHA256'),
                    'acceptance digest mismatch')
            acceptance(plan.read(p['externalEvidence']), p, journal(p), live_policy(p)['acceptedFence']['Generation'])
            print('External operator evidence validated; commit remains separate.')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError, AttributeError, subprocess.SubprocessError) as error:
        # Only our fixed check messages are emitted; decoder/OS/child errors may contain secrets.
        message = str(error) if type(error) is ValueError else 'invalid inputs or operation failed (contents redacted)'
        print('STOP: ' + message + '. Retain backups, journal, timer/boot guard and OOB; no retry/second host.', file=sys.stderr)
        sys.exit(1)
