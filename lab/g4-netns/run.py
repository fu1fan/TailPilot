#!/usr/bin/env python3
"""Disposable Linux lab. No host default route, firewall, sysctl or service edits.

PASS is reserved for evidence-complete R20 TCP+UDP and R18 gate assertions, not the full G4
matrix. Missing telemetry or a reset observation window remains BLOCKED.
"""
import argparse
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time
import uuid

import udp

ROLES = ('R', 'I', 'C1', 'C2')
# Source/release manifests use the peeled commit; vendor binaries stamp the
# annotated tag object. These are deliberately different identities.
UPSTREAM = '53a0d659afa51835dd7a9283873cca44261454f8'
OFFICIAL_TAG = '9329c3677031109ff6d0b80abee0cddc8f35ff6f'
OFFICIAL_LONG = '1.102.3-t9329c3677-ga522f65e9'
HERE = Path(__file__).resolve().parent
LIMITS = [
    'R20 PASS covers the recorded IPv4 TCP+UDP/direct-control and path-gate assertions, not full G4 acceptance.',
    'UDP echo covers IPv4, non-QUIC, no NAT/MTU fragmentation or cross-public-network traffic; CLI ping is WG/Disco only.',
    'Evidence uses fixed matched/unmatched groups; exactly one matched C1 is required.',
    'I-PDEF covers all-off/unmatched TCP+UDP and direct retention; throughput/handshake equivalence is not measured.',
    'No independent peer relay, VM reboot, App Connector/DNS/route lease E2E or cross-border QoS.',
    'No SIGKILL/power-loss recovery executor; retain journal and inspect owned resources manually.',
]


def require(ok, why):
    if not ok:
        raise ValueError(why)


def verify_version(version, patch_head=None):
    lines = version.splitlines()
    commits = re.findall(r'^\s*(?:tailscale )?commit: (\S+)\s*$', version, re.M)
    if patch_head is not None:
        # Keep patched full-HEAD and unified stamp requirements unchanged.
        require(re.search(r'^\s*tailscale commit: '+patch_head+r'\s*$', version, re.M), 'binary commit mismatch')
        require('1.102.3' in version and 'unified' in version, 'binary version mismatch')
        return
    require(lines and lines[0] == '1.102.3' and not re.search(r'unified|dev|dirty', version, re.I), 'official binary version mismatch')
    longs = re.findall(r'^\s*long version: (\S+)\s*$', version, re.M)
    require(all(c == OFFICIAL_TAG for c in commits) and all(v == OFFICIAL_LONG for v in longs)
            and (OFFICIAL_TAG in commits or OFFICIAL_LONG in longs), 'official binary commit mismatch')


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for b in iter(lambda: f.read(1024 * 1024), b''):
            h.update(b)
    return h.hexdigest()


def save(path, value):
    temp = path.with_suffix(path.suffix + '.tmp')
    with temp.open('w') as f:
        os.chmod(temp, 0o600)
        json.dump(value, f, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.replace(temp, path)


def netns_inode(name):
    return Path('/run/netns', name).stat().st_ino


def safe_path(s):
    p = Path(s)
    require(p.is_absolute() and '..' not in p.parts and re.fullmatch(r'/[A-Za-z0-9_./-]+', s), 'absolute plain path required')
    return p


def validate_spec(spec):
    require(set(spec) == {'release', 'manifestSHA256', 'patchHEAD', 'arch', 'official', 'helper'}, 'spec fields')
    safe_path(spec['release'])
    require(spec['arch'] in ('amd64', 'arm64'), 'arch')
    require(re.fullmatch('[a-f0-9]{40}', spec['patchHEAD']), 'patch HEAD')
    require(re.fullmatch('[a-f0-9]{64}', spec['manifestSHA256']), 'manifest SHA256')
    require(set(spec['official']) == {'tailscale', 'tailscaled'}, 'official pair required')
    for entry in [*spec['official'].values(), spec['helper']]:
        require(set(entry) == {'path', 'sha256'}, 'binary fields')
        safe_path(entry['path'])
        require(re.fullmatch('[a-f0-9]{64}', entry['sha256']), 'binary SHA256')


def topology(run_id, root, cidr):
    require(re.fullmatch('g4-[a-f0-9]{32}', run_id), 'runID must be g4-<32 hex>')
    root = safe_path(str(root))
    require(root.name == run_id and len(str(root)) < 78, 'root must end in runID and leave room for Unix socket')
    net = ipaddress.IPv4Network(cidr)
    require(net.prefixlen == 29 and any(net.subnet_of(ipaddress.IPv4Network(p)) for p in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')), 'private /29 required')
    prefix = 'g4' + hashlib.sha256(run_id.encode()).hexdigest()[:9]
    return {'runID': run_id, 'root': str(root), 'subnet': str(net), 'bridge': prefix+'b',
            'hostIP': str(net[1]), 'nodes': {role: {'namespace': run_id+'-'+role,
            'veth': prefix+str(i), 'peerVeth': prefix+str(i)+'p', 'ip': str(net[i+2])}
            for i, role in enumerate(ROLES)}}


class Host:
    def run(self, args, timeout=20, env=None):
        return subprocess.run(args, text=True, capture_output=True, timeout=timeout, env=env)


class Lab:
    def __init__(self, plan, spec, host=None):
        self.plan, self.spec = plan, spec
        self.root = Path(plan['root'])
        self.host = host or Host()
        self.resources, self.processes = [], []
        self.seq = 0
        self.report = dict(result='NOT_RUN', runID=plan['runID'], topology=plan,
                           inputs=spec, identities={}, cases=[{'caseID': c, 'result': 'NOT_RUN'} for c in ('I-PDEF', 'I-P001')], evidence=[], limits=LIMITS)
        self.active_case = 'I-PDEF'

    def journal(self):
        save(self.root/'resources.json', {'runID': self.plan['runID'], 'resources': self.resources})

    def command(self, args, timeout=20, allow_failure=False, env=None):
        self.seq += 1
        r = self.host.run([str(x) for x in args], timeout=timeout, env=env)
        name = f'{self.seq:04d}.json'
        save(self.root/name, {'argv': [str(x) for x in args], 'returncode': r.returncode,
                              'stdout': r.stdout, 'stderr': r.stderr, 'monotonic': time.monotonic()})
        self.report['evidence'].append(name)
        require(allow_failure or r.returncode == 0, 'command failed: '+name)
        return r

    def ip(self, *args):
        return self.command(['ip', *args]).stdout

    def ns(self, role):
        return ['ip', 'netns', 'exec', self.plan['nodes'][role]['namespace']]

    def cli(self, role, *args, **kwargs):
        base = Path(self.spec['release']) / ('linux-'+self.spec['arch'])
        binary = base/'tailscale' if role in ('R', 'I') else self.spec['official']['tailscale']['path']
        return self.command([*self.ns(role), binary, '--socket='+str(self.root/(role+'.sock')), *args], **kwargs)

    def status(self, role):
        return json.loads(self.cli(role, 'status', '--json').stdout)

    def policy_status(self, role):
        return json.loads(self.cli(role, 'debug', 'unified-policy', 'status', '--json').stdout)

    def preflight(self):
        require(sys.platform == 'linux' and os.geteuid() == 0, 'execute requires Linux root')
        require(Path('/dev/net/tun').exists(), '/dev/net/tun required')
        spec = self.spec
        release = Path(spec['release'])
        require(sha(release/'manifest.json') == spec['manifestSHA256'], 'manifest hash mismatch')
        manifest = json.loads((release/'manifest.json').read_text())
        require(manifest['patchHEAD'] == spec['patchHEAD'] and manifest['peeledCommit'] == UPSTREAM and not manifest['sourceDirty'], 'release identity mismatch')
        hashes = {'manifest': spec['manifestSHA256'], 'helper': sha(spec['helper']['path'])}
        require(hashes['helper'] == spec['helper']['sha256'], 'helper hash mismatch')
        for kind in ('tailscale', 'tailscaled'):
            rel = 'linux-'+spec['arch']+'/'+kind
            p = release/rel
            hashes['patched-'+kind] = sha(p)
            require(hashes['patched-'+kind] == manifest['files'][rel], 'release binary mismatch')
            entry = spec['official'][kind]
            hashes['official-'+kind] = sha(entry['path'])
            require(hashes['official-'+kind] == entry['sha256'], 'official hash mismatch')
            for binary, commit, official in ((p, spec['patchHEAD'], False), (entry['path'], UPSTREAM, True)):
                version = self.command([binary, 'version'] if kind == 'tailscale' else [binary, '--version']).stdout
                verify_version(version, None if official else commit)
        self.report['hashes'] = hashes
        net = ipaddress.ip_network(self.plan['subnet'])
        routes = json.loads(self.ip('-j', '-4', 'route', 'show', 'table', 'all'))
        for route in routes:
            dst = route.get('dst', 'default')
            if dst != 'default':
                require(not net.overlaps(ipaddress.ip_network(dst, strict=False)), 'subnet overlaps host route')
        # No adoption: exclusive kernel create also rejects races/collisions.
        names = {n['ifname'] for n in json.loads(self.ip('-j', 'link', 'show'))}
        require(self.plan['bridge'] not in names, 'bridge collision')
        for node in self.plan['nodes'].values():
            require(not ({node['veth'], node['peerVeth']} & names), 'veth collision')
            require(not Path('/run/netns', node['namespace']).exists(), 'namespace collision')

    def add_link(self, name, *args):
        self.ip('link', 'add', name, *args)
        # Record immediately, before configuration; delete only this ifindex.
        resource = {'kind': 'link', 'name': name, 'created': True, 'ifindex': None}
        self.resources.append(resource)
        self.journal()
        resource['ifindex'] = json.loads(self.ip('-j', 'link', 'show', 'dev', name))[0]['ifindex']
        self.journal()
        self.ip('link', 'set', 'dev', name, 'alias', self.plan['runID'])

    def create(self):
        bridge = self.plan['bridge']
        self.add_link(bridge, 'type', 'bridge')
        self.ip('addr', 'add', self.plan['hostIP']+'/29', 'dev', bridge)
        self.ip('link', 'set', bridge, 'up')
        for role, node in self.plan['nodes'].items():
            ns, veth, peer = node['namespace'], node['veth'], node['peerVeth']
            self.ip('netns', 'add', ns)
            self.resources.append({'kind': 'netns', 'name': ns, 'created': True,
                                   'inode': netns_inode(ns)})
            self.journal()
            self.add_link(veth, 'type', 'veth', 'peer', 'name', peer)
            self.ip('link', 'set', peer, 'netns', ns)
            self.ip('link', 'set', veth, 'master', bridge)
            self.ip('link', 'set', veth, 'up')
            self.ip('-n', ns, 'link', 'set', 'lo', 'up')
            self.ip('-n', ns, 'addr', 'add', node['ip']+'/29', 'dev', peer)
            self.ip('-n', ns, 'link', 'set', peer, 'up')

    def spawn(self, name, args, env=None):
        log = self.root/(name+'.log')
        with log.open('w') as out:
            p = subprocess.Popen([str(x) for x in args], stdout=out, stderr=subprocess.STDOUT,
                                 start_new_session=True, env=env)
        self.processes.append((name, p))
        self.report['evidence'].append(log.name)
        save(self.root/'processes.json', [{'name': n, 'pid': proc.pid} for n, proc in self.processes])
        return log

    def wait_for(self, fn, seconds=30):
        deadline = time.monotonic()+seconds
        while True:
            if any(p.poll() is not None for _, p in self.processes):
                raise RuntimeError('lab child exited; inspect logs')
            try:
                result = fn()
                if result:
                    require(time.monotonic() <= deadline, 'readiness/convergence deadline exceeded')
                    return result
            except (ValueError, KeyError, OSError):
                pass
            require(time.monotonic() < deadline, 'readiness/convergence deadline exceeded')
            time.sleep(0.25)

    def start(self):
        helperlog = self.spawn('control-derp', [self.spec['helper']['path'], '--bind', self.plan['hostIP']])
        def control_ready():
            for line in helperlog.read_text().splitlines():
                if line.startswith('{'):
                    return json.loads(line)
        info = self.wait_for(control_ready)
        save(self.root/'control.json', info)
        base = Path(self.spec['release']) / ('linux-'+self.spec['arch'])
        for role in ROLES:
            role_dir = self.root/role
            role_dir.mkdir(mode=0o700)
            (role_dir/'etc').mkdir(mode=0o700)
            (role_dir/'run').mkdir(mode=0o700)
            (role_dir/'etc'/'resolv.conf').write_text('nameserver 127.0.0.1\n')
            (role_dir/'etc'/'hosts').write_text('127.0.0.1 localhost\n')
            (role_dir/'etc'/'nsswitch.conf').write_text('hosts: files dns\n')
            policy = self.root/(role+'-policy.json')
            save(policy, {'schema_version': 1, 'enabled': False})
            env = dict(os.environ)
            # Do not inherit user debug knobs/proxies into disposable daemons.
            env = {k: v for k, v in env.items() if not k.startswith(('TS_', 'TAILSCALE_')) and 'proxy' not in k.lower()}
            env['DBUS_SYSTEM_BUS_ADDRESS'] = 'unix:path='+str(role_dir/'no-dbus')
            env['TS_NO_LOGS_NO_SUPPORT'] = 'true'
            env['TS_UNIFIED_POLICY_FILE'] = str(policy)
            binary = base/'tailscaled' if role in ('R', 'I') else self.spec['official']['tailscaled']['path']
            self.spawn(role, [*self.ns(role), 'unshare', '--mount', '--propagation', 'private', '--',
                             'bash', HERE/'daemon.sh', role_dir, binary, '--statedir='+str(role_dir),
                             '--state='+str(role_dir/'tailscaled.state'),
                             '--socket='+str(self.root/(role+'.sock')), '--tun=tailscale0', '--port=41641'], env)
            self.wait_for(lambda: (self.root/(role+'.sock')).exists())
            self.cli(role, 'up', '--login-server='+info['controlURL'], '--hostname='+role.lower(),
                     '--accept-dns=false', '--accept-routes=false', '--netfilter-mode=off', '--timeout=25s', timeout=30)
        for role in ROLES:
            status = self.wait_for(lambda role=role: self.running(role))
            self.report['identities'][role] = {'StableID': status['Self']['ID'], 'IP': status['TailscaleIPs'][0]}
        require(len({v['StableID'] for v in self.report['identities'].values()}) == 4, 'identity collision')
        for role in ROLES:
            for protocol in ('tcp', 'udp'):
                self.spawn(role+'-'+protocol, [*self.ns(role), sys.executable, HERE/(protocol+'.py'), 'serve', self.address(role)])
        time.sleep(0.5)

    def running(self, role):
        s = self.status(role)
        return s if s.get('BackendState') == 'Running' and s.get('Self', {}).get('ID') and len(s.get('Peer', {})) == 3 else None

    def address(self, role):
        return self.report['identities'][role]['IP']

    def snapshot(self, label):
        out = {}
        for role in ROLES:
            metrics = self.cli(role, 'debug', 'metrics').stdout
            out[role] = {'status': self.status(role), 'transportCounters': parse_metrics(metrics)}
            if role in ('R', 'I'):
                out[role]['policy'] = self.policy_status(role)
        save(self.root/(label+'.json'), out)
        self.report['evidence'].append(label+'.json')
        return out

    def retry_probe(self, source, target, protocol, attempts, persist, derp=False):
        # Each direction/protocol has its own total wall-clock budget. Never
        # combine partial UDP successes: every retry uses a fresh nonce/socket.
        started = time.monotonic()
        deadline = started + 30
        for number in range(1, 4):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            timeout = min({'ping': 3, 'tcp': 20, 'udp': 21}[protocol], remaining)
            if protocol == 'udp':
                result = self.udp_probe(source, target, timeout=timeout)
            else:
                try:
                    if protocol == 'ping':
                        process = self.cli(source, 'ping', '--c=1', '--until-direct=false',
                                           '--timeout=2s', self.address(target),
                                           allow_failure=True, timeout=timeout)
                    else:
                        process = self.command([*self.ns(source), sys.executable, HERE/'tcp.py',
                                                'probe', self.address(target)],
                                               allow_failure=True, timeout=timeout)
                    result = dict(ok=process.returncode == 0, returncode=process.returncode,
                                  stdout=process.stdout, stderr=process.stderr)
                    if derp and result['ok'] and 'via DERP(g4)' not in process.stdout:
                        result.update(ok=False, error='R->C1 positive control lacks DERP(g4) pong')
                    if not result['ok']:
                        result.setdefault('error', process.stderr or process.stdout or
                                          f'{protocol} process exited {process.returncode}')
                except (subprocess.TimeoutExpired, OSError) as e:
                    result = dict(ok=False, error=str(e))
            elapsed = time.monotonic() - started
            if elapsed > 30 and result['ok']:
                result.update(ok=False, error='probe exceeded 30 second budget')
            attempts.append(dict(attempt=number, seconds=elapsed, timeoutSeconds=timeout, **result))
            persist()
            if result['ok']:
                break
            if number < 3:
                time.sleep(min(0.25, max(0, deadline-time.monotonic())))
        return attempts[-1] if attempts else dict(ok=False, error='probe budget exhausted before first attempt')

    def strict_warmup(self):
        evidence = self.root/'strict-warmup.json'
        record = dict(source='R', target='C1', protocol='ping', attempts=[])
        self.report['evidence'].append(evidence.name)
        save(evidence, record)
        result = self.retry_probe('R', 'C1', 'ping', record['attempts'],
                                  lambda: save(evidence, record), derp=True)
        require(result['ok'], 'strict R->C1 DERP positive control failed: '+result.get('error', ''))

    def traffic(self, label):
        probes, attempts = [], []
        evidence = self.root/(label+'-traffic.json')
        history = self.root/(label+'-traffic-attempts.json')
        save(evidence, probes)
        save(history, attempts)
        self.report['evidence'].extend([evidence.name, history.name])
        for client in ('C1', 'C2'):
            for server in ('R', 'I'):
                for source, target in ((client, server), (server, client)):
                    record = dict(source=source, target=target, ping=[], tcp=[], udp=[])
                    attempts.append(record)
                    probe = dict(source=source, target=target)
                    probes.append(probe)
                    for protocol in ('ping', 'tcp', 'udp'):
                        result = self.retry_probe(source, target, protocol, record[protocol],
                                                  lambda: save(history, attempts))
                        probe[protocol] = result['ok']
                        probe[protocol+'Result'] = result
                        if protocol == 'ping':
                            probe['pingOutput'] = result.get('stdout', '')
                        save(evidence, probes)
        return probes

    def udp_probe(self, source, target, timeout=udp.COUNT*udp.TIMEOUT+5):
        nonce = uuid.uuid4().hex
        args = [*self.ns(source), sys.executable, HERE/'udp.py', 'probe', self.address(target), nonce]
        try:
            process = self.command(args, timeout=timeout, allow_failure=True)
        except subprocess.TimeoutExpired as e:
            return {'ok': False, 'nonce': nonce, 'target': self.address(target),
                    'error': f'UDP subprocess timeout after {e.timeout}s'}
        except OSError as e:
            return {'ok': False, 'nonce': nonce, 'target': self.address(target),
                    'error': f'UDP launch failed: {e}'}
        return parse_udp(process, self.address(target), nonce)

    def begin_monitor(self):
        self.monitor = self.spawn('C2-continuity', [*self.ns('C2'), sys.executable, HERE/'tcp.py',
                                  'monitor', self.address('R')+','+self.address('I')])
        self.wait_for(lambda: self.monitor.stat().st_size > 0)

    def check_monitor(self):
        lines = self.monitor.read_text().splitlines()
        samples = [json.loads(line) for line in lines]
        require(len(samples) >= 2 and all(s['seconds'] < 5 for s in samples), 'C2 continuity failed')
        require(time.monotonic()-samples[-1]['monotonic'] < 6, 'C2 continuity stale')
        self.report['C2Continuity'] = {'samples': len(samples), 'evidence': self.monitor.name}

    def ready_for_policy(self):
        # Readiness may take longer than path convergence. It is outside the
        # unchanged 30-second policy-to-ACTIVE acceptance window.
        def ready():
            states = {r: self.status(r) for r in ROLES}
            save(self.root/'policy-readiness.json', states)
            return states if peers_ready(states, self.report['identities']) else None
        self.report['evidence'].append('policy-readiness.json')
        try:
            self.wait_for(ready, 90)
        except ValueError as e:
            raise EvidenceUnavailable('peer identity/home DERP readiness: '+str(e)) from e

    def converge(self, started, digest):
        deadline = started+30
        samples = []
        self.report['evidence'].append('convergence.json')
        try:
            while time.monotonic() < deadline:
                p = self.policy_status('R')
                states = {r: self.status(r) for r in ROLES}
                samples.append({'seconds': time.monotonic()-started, 'policy': p,
                                'peers': peer_diagnostics(states, self.report['identities'])})
                save(self.root/'convergence.json', samples)
                evidence_state(p)  # Missing telemetry is BLOCKED, including before ACTIVE.
                if policy_applied(p, digest) and p.get('paths') == {'ACTIVE/derp/ACTIVE': 1}:
                    require(time.monotonic() <= deadline, 'DERP convergence exceeded 30 seconds')
                    return
                # A reload resets lastSendExt. Status polling does not schedule
                # probes; stimulate the matched peer before waiting for ACTIVE.
                # This CLI uses the existing allowed-path gate, never a bypass.
                remaining = deadline-time.monotonic()
                if remaining <= 0:
                    break
                probe = self.cli('R', 'ping', '--c=1', '--until-direct=false', '--timeout=1s',
                                 self.address('C1'), allow_failure=True, timeout=min(3, remaining))
                samples[-1]['probe'] = {'returncode': probe.returncode, 'stdout': probe.stdout}
                save(self.root/'convergence.json', samples)
                time.sleep(min(0.25, max(0, deadline-time.monotonic())))
            raise ValueError('DERP convergence exceeded 30 seconds; inspect convergence.json and R.log')
        finally:
            save(self.root/'convergence.json', samples)

    def cases(self):
        self.snapshot('default-before')
        baseline = self.traffic('default')
        before = self.snapshot('default-after')
        assert_traffic(baseline, 'default')
        require(all(not before[r]['policy']['enabledModules']['root'] for r in ('R', 'I')), 'baseline not all-off')
        # Same-L2 direct positive control is essential; DERP-only baseline is inconclusive.
        require(all(peer(before[c]['status'], self.address(s)).get('CurAddr') for c in ('C1', 'C2') for s in ('R', 'I')), 'direct positive control absent')
        self.report['cases'][0].update(result='BLOCKED', smoke='BASELINE_PASS', reason='Unmatched control and equivalence not yet verified')
        self.active_case = 'I-P001'
        self.ready_for_policy()
        self.begin_monitor()
        config = {'schema_version': 1, 'enabled': True, 'path_policy': {'enabled': True, 'rules': [{
            'id': 'g4-c1', 'stable_ids': [self.report['identities']['C1']['StableID']],
            'allow': {'direct': False, 'peer_relay': False, 'derp': True}, 'prefer': ['derp'], 'fallback': 'strict'}]}}
        save(self.root/'R-policy.json', config)
        self.report['evidence'].append('R-policy.json')
        # File polling is the tested hot-reload mechanism, no daemon restart or CAS race.
        started = time.monotonic()
        digest = sha(self.root/'R-policy.json')
        def applied():
            p = self.policy_status('R')
            return p if policy_applied(p, digest) else None
        applied_status = self.wait_for(applied, 30)
        self.report['reload'] = {'seconds': time.monotonic()-started, 'status': applied_status}
        # One matched peer only: aggregate active path must contain exactly this rule.
        save(self.root/'policy-applied.json', applied_status)
        self.report['evidence'].append('policy-applied.json')
        self.converge(started, digest)
        self.strict_warmup()
        active_before = self.snapshot('strict-before')
        after_traffic = self.traffic('strict')
        after = self.snapshot('strict-after')
        assert_traffic(after_traffic, 'strict')
        require(policy_applied(after['R']['policy'], digest), 'policy no longer applied')
        require(after['R']['policy']['paths'] == {'ACTIVE/derp/ACTIVE': 1}, 'unexpected active path')
        require(not peer(after['R']['status'], self.address('C1')).get('CurAddr'), 'R retained C1 direct path')
        require(not peer(after['C1']['status'], self.address('R')).get('CurAddr'), 'C1 retained R direct path')
        require(all(peer(after[c]['status'], self.address(s)).get('CurAddr') for c, s in (('C2', 'R'), ('C1', 'I'), ('C2', 'I'))), 'unmatched direct path lost')
        require(not after['I']['policy']['enabledModules']['root'], 'I control changed')
        deltas = counter_deltas(active_before, after)
        save(self.root/'counter-deltas.json', deltas)
        for role in ('R', 'C1'):
            require(all(deltas[role].get('magicsock_'+direction+'_data_derp', 0) > 0 for direction in ('send', 'recv')), 'bidirectional DERP counter did not advance')
        self.check_monitor()
        try:
            proof = assert_path_evidence(before, applied_status, active_before, after)
            save(self.root/'path-evidence.json', proof)
            result, reason = 'PASS', 'R20 TCP+UDP and R18 scoped path-gate/control assertions complete.'
        except EvidenceUnavailable as e:
            result, reason = 'BLOCKED', str(e)
        self.report['cases'] = [
            {'caseID': 'I-PDEF', 'result': result, 'smoke': 'PASS',
             'scope': 'R20 all-off and unmatched C2 bidirectional TCP+UDP/direct; TCP continuity',
             'evidence': ['default-after.json', 'strict-after.json', 'default-traffic.json', 'strict-traffic.json', self.monitor.name if hasattr(self, 'monitor') else 'C2-continuity.log'],
             'reason': reason},
            {'caseID': 'I-P001', 'result': result, 'smoke': 'PASS',
             'scope': 'R20 C1 DERP TCP+UDP; zero forbidden gate accepts and health since activation',
             'evidence': ['strict-before.json', 'strict-after.json', 'strict-traffic.json', 'counter-deltas.json'] + (['path-evidence.json'] if result == 'PASS' else []),
             'reason': reason}]
        self.report['result'] = result


    def cleanup(self):
        errors = []
        for name, process in reversed(self.processes):
            try:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGTERM)
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        os.killpg(process.pid, signal.SIGKILL)
                        process.wait(timeout=5)
            except (OSError, subprocess.SubprocessError) as e:
                errors.append(name+': '+str(e))
        for r in reversed(self.resources):
            if not r['created']:
                continue
            try:
                if r['kind'] == 'link':
                    current = json.loads(self.ip('-j', 'link', 'show', 'dev', r['name']))[0]
                    require(r['ifindex'] == current['ifindex'], 'link identity changed; refusing cleanup')
                    self.ip('link', 'del', 'dev', r['name'])
                else:
                    require(netns_inode(r['name']) == r['inode'], 'netns identity changed; refusing cleanup')
                    self.ip('netns', 'del', r['name'])
                r['created'] = False
                self.journal()
            except (ValueError, OSError, KeyError, subprocess.SubprocessError) as e:
                errors.append(r['name']+': '+str(e))
        return errors


class EvidenceUnavailable(ValueError):
    pass


def evidence_state(policy):
    e = policy.get('pathEvidence')
    if not isinstance(e, dict) or type(e.get('schema')) is not int or e['schema'] != 1:
        raise EvidenceUnavailable('Missing R18 pathEvidence schema=1: rebuild release binaries from R18, pin the new manifest and real patchHEAD.')
    fields = ('generation', 'matchedPeers', 'unmatchedPeers')
    if any(type(e.get(k)) is not int or e[k] < 0 for k in fields) or type(e.get('enabled')) is not bool:
        raise EvidenceUnavailable('Incomplete pathEvidence metadata')
    events = ('send/accepted', 'send/rejected', 'probe/accepted', 'probe/rejected',
              'receive/accepted', 'receive/rejected', 'health/confirmed', 'health/forbidden',
              'last_recv/confirmed', 'last_recv/forbidden', 'pong/confirmed', 'pong/forbidden')
    keys = {f'{group}/{path}/{event}' for group in ('matched', 'unmatched', 'unknown')
            for path in ('direct', 'peer_relay', 'derp', 'unknown') for event in events}
    counts = e.get('counters')
    if not isinstance(counts, dict) or set(counts) != keys or any(type(v) is not int or v < 0 for v in counts.values()):
        raise EvidenceUnavailable('Incomplete pathEvidence cells; zero cannot be inferred from missing counters')
    return e


def assert_path_evidence(default, applied, before, after):
    baseline = evidence_state(default['R']['policy'])
    first, start, end = (evidence_state(p) for p in (applied, before['R']['policy'], after['R']['policy']))
    for role in ('R', 'I'):
        off = evidence_state(default[role]['policy'])
        require(not off['enabled'] and not any(off['counters'].values()), 'default-off evidence changed')
    off = evidence_state(after['I']['policy'])
    require(not off['enabled'] and not any(off['counters'].values()), 'I default control evidence changed')
    # Do not lose a violation in a reset between activation and first observation.
    if baseline['generation'] != 0 or first['generation'] != 1 or any(e['generation'] != first['generation'] for e in (start, end)):
        raise EvidenceUnavailable('Evidence generation changed/reset across activation or traffic; repeat with a fresh runID')
    for e in (first, start, end):
        require(e['enabled'] and e['matchedPeers'] == 1 and e['unmatchedPeers'] == 2, 'C1-only evidence scope mismatch')
    for left, right in ((first, start), (start, end)):
        if any(right['counters'][k] < v for k, v in left['counters'].items()):
            raise EvidenceUnavailable('Evidence counter reset within generation')
    # Absolute counts since activation, not merely the steady-state delta.
    for e in (first, start, end):
        for path in ('direct', 'peer_relay', 'unknown'):
            for event in ('send/accepted', 'probe/accepted', 'receive/accepted',
                          'health/confirmed', 'last_recv/confirmed', 'pong/confirmed'):
                require(e['counters'][f'matched/{path}/{event}'] == 0, 'C1 forbidden acceptance/confirmation: '+path+'/'+event)
        require(all(v == 0 for k, v in e['counters'].items() if k.startswith('matched/') and k.endswith('/forbidden')), 'C1 forbidden health audit')
    delta = {k: end['counters'][k]-start['counters'][k] for k in end['counters']}
    for key in ('matched/derp/send/accepted', 'matched/derp/receive/accepted', 'matched/derp/last_recv/confirmed',
                'unmatched/direct/send/accepted', 'unmatched/direct/receive/accepted', 'unmatched/direct/last_recv/confirmed'):
        require(delta[key] > 0, 'Missing positive evidence: '+key)
    require(end['counters']['matched/derp/health/confirmed'] > 0, 'Missing DERP health evidence')
    return {'schema': 1, 'generation': end['generation'], 'sinceActivation': end, 'trafficDelta': delta,
            'attribution': 'Only C1 matched; C2 independently verified by TCP+UDP and CurAddr controls',
            'semantics': 'Gate decisions (may repeat), actual confirmation callbacks; not unique packets'}


def parse_udp(process, target, nonce):
    result = {'ok': False, 'target': target, 'nonce': nonce,
              'returncode': process.returncode, 'stdout': process.stdout, 'stderr': process.stderr}
    try:
        require(process.returncode == 0, f'UDP process exited {process.returncode}')
        data = json.loads(process.stdout)
        require(isinstance(data, dict), 'UDP result must be an object')
        require(data.get('schema') == 1 and data.get('ok') is True, 'UDP probe failed')
        require(data.get('nonce') == nonce and data.get('target') == target, 'UDP nonce/target mismatch')
        require(type(data.get('sent')) is int and type(data.get('received')) is int
                and data['sent'] == data['received'] == udp.COUNT, 'UDP incomplete datagrams')
        require(data.get('sequences') == list(range(udp.COUNT)), 'UDP sequence mismatch')
        require(data.get('bytesEachDirection') == sum(len(udp.payload(nonce, i)) for i in range(udp.COUNT)), 'UDP byte count mismatch')
        seconds = data.get('seconds')
        require(type(seconds) in (int, float) and math.isfinite(seconds) and seconds >= 0, 'UDP invalid duration')
        result.update(ok=True, probe=data)
    except (ValueError, TypeError) as e:
        result['error'] = str(e)
    return result


def assert_traffic(probes, label):
    expected = {(a, b) for c in ('C1', 'C2') for s in ('R', 'I') for a, b in ((c, s), (s, c))}
    require(len(probes) == 8 and {(p.get('source'), p.get('target')) for p in probes} == expected,
            label+' incomplete bidirectional traffic matrix')
    for p in probes:
        for protocol in ('ping', 'tcp', 'udp'):
            require(p.get(protocol) is True,
                    f"{label} {p['source']}->{p['target']} {protocol} failed: "
                    + str(p.get(protocol+'Result', {}).get('error', 'inspect command evidence')))


def policy_applied(p, digest):
    return (p.get('source_sha256') == digest and p.get('applied') is True and
            p.get('runtimeReady') is True and p.get('enabledModules', {}).get('path_policy') is True and
            not p.get('pendingRules') and not p.get('degraded') and not p.get('reconciling'))


def peers_ready(states, identities):
    for role in ROLES:
        s = states[role]
        if (s.get('BackendState') != 'Running' or s.get('Self', {}).get('ID') != identities[role]['StableID']
                or s.get('Self', {}).get('Relay') != 'g4' or len(s.get('Peer', {})) != 3):
            return False
        for other in ROLES:
            if other == role:
                continue
            p = peer(s, identities[other]['IP'])
            if p.get('ID') != identities[other]['StableID'] or p.get('Relay') != 'g4':
                return False
    return True


def peer_diagnostics(states, identities):
    # Status fields are observations, not internal candidate or health claims.
    # R.log's bounded path_decision includes actual bestAddr/derpAddr/candidates.
    return {role: [{'StableID': p.get('ID'), 'homeDERP': p.get('Relay'),
                    'CurAddr': p.get('CurAddr'), 'TailscaleIPs': p.get('TailscaleIPs'),
                    'expectedMatched': role == 'R' and p.get('ID') == identities['C1']['StableID'],
                    'expectedAllow': {'direct': False, 'peer_relay': False, 'derp': True}
                             if role == 'R' and p.get('ID') == identities['C1']['StableID'] else None}
                   for p in states[role].get('Peer', {}).values()] for role in ROLES}


def peer(status, ip):
    matches = [p for p in status.get('Peer', {}).values() if ip in p.get('TailscaleIPs', [])]
    require(len(matches) == 1, 'missing/ambiguous peer')
    return matches[0]


def parse_metrics(text):
    out = {}
    for line in text.splitlines():
        m = re.fullmatch(r'(?:tailscaled_)?(magicsock_(?:send|recv)_data_[a-z0-9_]+) ([0-9]+)', line)
        if m:
            out[m[1]] = int(m[2])
    return out


def counter_deltas(before, after):
    result = {}
    for role in ROLES:
        old, new = before[role]['transportCounters'], after[role]['transportCounters']
        if not old or set(old) != set(new):
            raise EvidenceUnavailable('missing/changed transport metrics')
        if any(new[k] < old[k] for k in old):
            raise EvidenceUnavailable('transport counter reset')
        result[role] = {k: new[k]-old[k] for k in old}
    return result


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--run-id', default='g4-'+uuid.uuid4().hex)
    p.add_argument('--root', help='new private evidence directory ending in runID')
    p.add_argument('--subnet', default='10.203.77.0/29')
    p.add_argument('--inputs', required=True, help='pinned binary/release JSON')
    mode = p.add_mutually_exclusive_group()
    mode.add_argument('--execute', action='store_true')
    mode.add_argument('--dry-run', action='store_true')
    a = p.parse_args(argv)
    plan = topology(a.run_id, a.root or '/tmp/'+a.run_id, a.subnet)
    spec = json.loads(Path(a.inputs).read_text())
    validate_spec(spec)
    if not a.execute:
        print(json.dumps(dict(result='NOT_RUN', mode='dry-run', topology=plan, inputs=spec,
                             cases=['I-PDEF', 'I-P001'], limits=LIMITS), indent=2))
        return 0
    require(sys.platform == 'linux' and os.geteuid() == 0, 'execute requires Linux root')
    root = Path(plan['root'])
    require(root.parent.resolve() == root.parent, 'symlink parent forbidden')
    os.umask(0o077)
    root.mkdir(mode=0o700)  # exclusive; never adopt a previous run
    lab = Lab(plan, spec)
    def interrupted(signum, frame):
        raise InterruptedError('signal '+str(signum))
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    phase = 'preflight'
    try:
        lab.preflight()
        phase = 'setup'
        lab.create()
        lab.start()
        phase = 'cases'
        lab.cases()
    except Exception as e:
        result = 'FAIL' if phase == 'cases' and not isinstance(e, EvidenceUnavailable) else 'BLOCKED'
        lab.report.update(result=result, error=str(e), phase=phase)
        if phase == 'cases':
            for case in lab.report['cases']:
                if case['caseID'] == lab.active_case:
                    case.update(result=result, reason=str(e))
    finally:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        errors = lab.cleanup()
        lab.report['cleanup'] = {'result': 'FAIL' if errors else 'PASS', 'errors': errors}
        if errors:
            lab.report['result'] = 'FAIL'
        save(root/'report.json', lab.report)
    print(json.dumps(lab.report, indent=2))
    return {'PASS': 0, 'NOT_RUN': 0, 'BLOCKED': 2, 'FAIL': 1}[lab.report['result']]


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (ValueError, OSError, KeyError, TypeError) as e:
        print(json.dumps({'result': 'BLOCKED', 'error': str(e)}))
        sys.exit(2)
