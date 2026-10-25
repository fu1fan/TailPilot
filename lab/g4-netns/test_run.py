#!/usr/bin/env python3
"""Fake host only: no root, namespace, daemon or sockets required."""
import copy
import contextlib
import io
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
s = importlib.util.spec_from_file_location('g4', HERE/'run.py')
g4 = importlib.util.module_from_spec(s)
s.loader.exec_module(g4)
RUN = 'g4-'+'a'*32

class FakeHost:
    def __init__(self):
        self.calls = []
        self.links = {}
        self.fail = None

    def run(self, args, **kw):
        self.calls.append(args)
        out, rc = '', 0
        if self.fail and self.fail(args):
            rc = 1
        elif args[:3] == ['ip', 'link', 'add']:
            name = args[3]
            if name in self.links:
                rc = 1
            else:
                self.links[name] = len(self.links)+10
        elif args[:4] == ['ip', '-j', 'link', 'show']:
            name = args[-1]
            if name not in self.links:
                rc = 1
            else:
                out = json.dumps([{'ifname': name, 'ifindex': self.links[name]}])
        elif args[:4] == ['ip', 'link', 'del', 'dev']:
            self.links.pop(args[-1])
        return subprocess.CompletedProcess(args, rc, out, 'injected failure' if rc else '')

class Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir='/tmp')
        self.root = Path(self.temp.name)/RUN
        self.root.mkdir()
        self.spec = json.loads((HERE/'inputs.example.json').read_text())
        self.plan = g4.topology(RUN, self.root, '10.203.77.0/29')
        self.host = FakeHost()
        self.lab = g4.Lab(self.plan, self.spec, self.host)

    def tearDown(self):
        self.temp.cleanup()

    def test_dry_run_no_writes_or_probes(self):
        root = Path(self.temp.name)/('g4-'+'b'*32)
        run = subprocess.run(['bash', str(HERE/'run.sh'), '--run-id', root.name, '--root', str(root),
                              '--inputs', str(HERE/'inputs.example.json')], capture_output=True, text=True)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(json.loads(run.stdout)['result'], 'NOT_RUN')
        self.assertFalse(root.exists())

    def test_complete_topology_and_namespace_reverse_cleanup(self):
        with patch.object(g4, 'netns_inode', return_value=123):
            self.lab.create()
            self.assertEqual(len(self.lab.resources), 9)
            self.assertEqual(self.lab.cleanup(), [])
        calls = self.host.calls
        mutations = [c for c in calls if 'add' in c or 'set' in c or 'del' in c]
        self.assertFalse(any('default' in c or 'sysctl' in c or 'nft' in c or 'iptables' in c for c in calls))
        self.assertTrue(all(c[0] == 'ip' for c in mutations))
        removed = [c[-1] for c in calls if 'del' in c]
        self.assertEqual(removed, [r['name'] for r in reversed(self.lab.resources)])

    def test_namespace_identity_change_retained(self):
        self.lab.resources.append({'kind': 'netns', 'name': RUN+'-R', 'created': True, 'inode': 12})
        with patch.object(g4, 'netns_inode', return_value=13):
            self.assertEqual(len(self.lab.cleanup()), 1)
        self.assertFalse(any('del' in c for c in self.host.calls))

    def test_preflight_hash_commit_and_route_guards(self):
        release = Path(self.temp.name)/'release'
        official = Path(self.temp.name)/'official'
        (release/'linux-amd64').mkdir(parents=True)
        official.mkdir()
        self.spec['release'] = str(release)
        files = {}
        for kind in ('tailscale', 'tailscaled'):
            patched = release/'linux-amd64'/kind
            patched.write_text('patched '+kind)
            files['linux-amd64/'+kind] = g4.sha(patched)
            binary = official/kind
            binary.write_text('official '+kind)
            self.spec['official'][kind] = {'path': str(binary), 'sha256': g4.sha(binary)}
        helper = Path(self.temp.name)/'helper'
        helper.write_text('helper')
        self.spec['helper'] = {'path': str(helper), 'sha256': g4.sha(helper)}
        manifest = release/'manifest.json'
        manifest.write_text(json.dumps({'patchHEAD': self.spec['patchHEAD'], 'peeledCommit': g4.UPSTREAM,
                                       'sourceDirty': False, 'files': files}))
        self.spec['manifestSHA256'] = g4.sha(manifest)
        bad_commit, overlap = False, False
        def run(args, **kwargs):
            if args[0] == 'ip':
                out = json.dumps([{'dst': '10.203.77.0/24'}] if overlap and 'route' in args else [])
            else:
                orig = '/official/' in str(args[0])
                commit = 'bad' if bad_commit else g4.OFFICIAL_TAG if orig else self.spec['patchHEAD']
                out = ('1.102.3' if orig else '1.102.3-unified.u1')+'\n  tailscale commit: '+commit+'\n'
            return subprocess.CompletedProcess(args, 0, out, '')
        exists = Path.exists
        with patch.object(g4.sys, 'platform', 'linux'), patch.object(g4.os, 'geteuid', return_value=0), patch.object(Path, 'exists', lambda p: True if str(p) == '/dev/net/tun' else exists(p)), patch.object(self.host, 'run', side_effect=run):
            self.lab.preflight()
            bad_commit = True
            with self.assertRaisesRegex(ValueError, 'commit mismatch'):
                self.lab.preflight()
            bad_commit, overlap = False, True
            with self.assertRaisesRegex(ValueError, 'overlaps'):
                self.lab.preflight()
            overlap = False
            (official/'tailscale').write_text('tampered')
            with self.assertRaisesRegex(ValueError, 'official hash mismatch'):
                self.lab.preflight()
        self.assertFalse(self.lab.resources)

    def test_official_tag_not_peeled_source_identity(self):
        for label in ('commit', 'tailscale commit'):
            g4.verify_version('1.102.3\n  '+label+': '+g4.OFFICIAL_TAG+'\n')
        g4.verify_version('1.102.3\n  long version: '+g4.OFFICIAL_LONG+'\n')
        for v in ('1.102.3\n  tailscale commit: '+g4.UPSTREAM,
                  '1.102.3-unified.u1\n  commit: '+g4.OFFICIAL_TAG,
                  '1.102.3\n  long version: '+g4.OFFICIAL_LONG+'\n  commit: '+g4.UPSTREAM,
                  '1.102.3\n', '1.102.3\n  commit: '+g4.OFFICIAL_TAG+'\n  long version: source-built'):
            with self.assertRaises(ValueError):
                g4.verify_version(v)
        with self.assertRaises(ValueError):
            g4.verify_version('1.102.3-unified.u1\n tailscale commit: '+g4.OFFICIAL_TAG, 'f'*40)

    def test_start_scopes_daemon_mounts_state_and_control(self):
        statuses = [{'Self': {'ID': 'n'+str(i)}, 'TailscaleIPs': ['100.64.0.'+str(i+1)]} for i in range(4)]
        waits = [{'controlURL': 'http://10.203.77.1:1234'}, True, True, True, True, *statuses]
        with patch.object(self.lab, 'spawn', return_value=self.root/'log') as spawn, patch.object(self.lab, 'wait_for', side_effect=waits), patch.object(g4.time, 'sleep'):
            self.lab.start()
        calls = {call.args[0]: call for call in spawn.call_args_list}
        for role in g4.ROLES:
            args = [str(x) for x in calls[role].args[1]]
            self.assertEqual(args[:4], ['ip', 'netns', 'exec', RUN+'-'+role])
            self.assertIn('unshare', args)
            self.assertIn('--mount', args)
            self.assertIn('--statedir='+str(self.root/role), args)
            self.assertIn('--state='+str(self.root/role/'tailscaled.state'), args)
            self.assertTrue((self.root/role/'etc'/'resolv.conf').is_file())
            self.assertIn('DBUS_SYSTEM_BUS_ADDRESS', calls[role].args[2])
            udp_args = [str(x) for x in calls[role+'-udp'].args[1]]
            self.assertEqual(udp_args[:4], ['ip', 'netns', 'exec', RUN+'-'+role])
            self.assertEqual(udp_args[-2:], ['serve', self.lab.address(role)])
        self.assertEqual(len(self.lab.report['identities']), 4)

    def test_main_setup_failure_cleans_and_retains_evidence(self):
        run_id = 'g4-'+'c'*32
        root = Path(self.temp.name).resolve()/run_id
        inputs = Path(self.temp.name)/'inputs.json'
        inputs.write_text(json.dumps(self.spec))
        def create(lab):
            lab.add_link('owned', 'type', 'bridge')
            raise RuntimeError('injected setup failure')
        with patch.object(g4.sys, 'platform', 'linux'), patch.object(g4.os, 'geteuid', return_value=0), patch.object(g4.signal, 'signal'), patch.object(g4, 'Host', return_value=self.host), patch.object(g4.Lab, 'preflight'), patch.object(g4.Lab, 'create', create), contextlib.redirect_stdout(io.StringIO()):
            result = g4.main(['--run-id', run_id, '--root', str(root), '--inputs', str(inputs), '--execute'])
        report = json.loads((root/'report.json').read_text())
        self.assertEqual(result, 2)
        self.assertEqual(report['result'], 'BLOCKED')
        self.assertEqual(report['cleanup']['result'], 'PASS')
        self.assertTrue(all(c['result'] == 'NOT_RUN' for c in report['cases']))
        self.assertFalse(self.host.links)
        self.assertTrue((root/'resources.json').exists())

    def test_main_missing_evidence_is_blocked_and_cleaned(self):
        run_id = 'g4-'+'d'*32
        root = Path(self.temp.name).resolve()/run_id
        inputs = Path(self.temp.name)/'inputs.json'
        inputs.write_text(json.dumps(self.spec))
        with patch.object(g4.sys, 'platform', 'linux'), patch.object(g4.os, 'geteuid', return_value=0), patch.object(g4.signal, 'signal'), patch.object(g4, 'Host', return_value=self.host), patch.object(g4.Lab, 'preflight'), patch.object(g4.Lab, 'create'), patch.object(g4.Lab, 'start'), patch.object(g4.Lab, 'cases', side_effect=g4.EvidenceUnavailable('missing transport metrics')), contextlib.redirect_stdout(io.StringIO()):
            result = g4.main(['--run-id', run_id, '--root', str(root), '--inputs', str(inputs), '--execute'])
        report = json.loads((root/'report.json').read_text())
        self.assertEqual(result, 2)
        self.assertEqual(report['result'], 'BLOCKED')
        self.assertEqual(report['cases'][0]['result'], 'BLOCKED')
        self.assertEqual(report['cleanup']['result'], 'PASS')

    def test_scope(self):
        for rid, root, subnet in [('g4-x', self.root, '10.0.0.0/29'),
                                  (RUN, '/tmp/wrong', '10.0.0.0/29'),
                                  (RUN, self.root, '8.8.8.0/29'),
                                  (RUN, self.root, '10.0.0.0/24'),
                                  (RUN, '/tmp/../tmp/'+RUN, '10.0.0.0/29')]:
            with self.assertRaises(ValueError):
                g4.topology(rid, root, subnet)
        self.assertEqual(len(self.plan['nodes']), 4)
        self.assertEqual(len({n['ip'] for n in self.plan['nodes'].values()}), 4)
        self.assertTrue(all(len(n['peerVeth']) <= 15 for n in self.plan['nodes'].values()))

    def test_spec_negative(self):
        g4.validate_spec(self.spec)
        for key, value in [('arch', 'riscv'), ('manifestSHA256', 'a963a891'), ('patchHEAD', 'HEAD')]:
            bad = copy.deepcopy(self.spec)
            bad[key] = value
            with self.assertRaises(ValueError):
                g4.validate_spec(bad)
        self.spec['official']['tailscale']['path'] = '/tmp/$(touch-x)'
        with self.assertRaises(ValueError):
            g4.validate_spec(self.spec)

    def test_reverse_created_only_cleanup(self):
        self.lab.add_link('one', 'type', 'bridge')
        self.lab.add_link('two', 'type', 'bridge')
        self.lab.resources.append({'kind': 'link', 'name': 'foreign', 'created': False})
        self.assertEqual(self.lab.cleanup(), [])
        deletions = [c[-1] for c in self.host.calls if c[:3] == ['ip', 'link', 'del']]
        self.assertEqual(deletions, ['two', 'one'])
        self.assertEqual(self.lab.cleanup(), [])
        self.assertEqual(len([c for c in self.host.calls if c[:3] == ['ip', 'link', 'del']]), 2)

    def test_create_collision_not_adopted(self):
        self.host.links['foreign'] = 99
        with self.assertRaises(ValueError):
            self.lab.add_link('foreign', 'type', 'bridge')
        self.assertEqual(self.lab.resources, [])
        self.lab.cleanup()
        self.assertEqual(self.host.links['foreign'], 99)

    def test_partial_configuration_cleanup(self):
        self.host.fail = lambda args: 'alias' in args
        with self.assertRaises(ValueError):
            self.lab.add_link('partial', 'type', 'bridge')
        self.assertEqual(self.lab.cleanup(), [])
        self.assertFalse(self.host.links)

    def test_foreign_replacement_not_deleted(self):
        self.lab.add_link('owned', 'type', 'bridge')
        self.host.links['owned'] = 999
        self.assertTrue(self.lab.cleanup())
        self.assertIn('owned', self.host.links)
        self.assertTrue(self.lab.resources[0]['created'])

    def test_cleanup_continues_after_failure(self):
        self.lab.add_link('one', 'type', 'bridge')
        self.lab.add_link('two', 'type', 'bridge')
        self.host.fail = lambda args: args == ['ip', 'link', 'del', 'dev', 'two']
        self.assertEqual(len(self.lab.cleanup()), 1)
        self.assertNotIn('one', self.host.links)
        self.assertIn('two', self.host.links)

    def test_policy_requires_applied_identity(self):
        p = {'source_sha256': 'abc', 'applied': True, 'runtimeReady': True,
             'enabledModules': {'path_policy': True}, 'paths': {'ACTIVE/derp/ACTIVE': 1}}
        self.assertTrue(g4.policy_applied(p, 'abc'))
        for k, v in [('applied', False), ('source_sha256', 'old'), ('pendingRules', 1), ('degraded', True), ('reconciling', True)]:
            bad = dict(p, **{k: v})
            self.assertFalse(g4.policy_applied(bad, 'abc'))

    def test_counter_missing_reset_and_delta(self):
        metrics = g4.parse_metrics('# HELP foo\nmagicsock_recv_data_derp 9\ntailscaled_magicsock_send_data_ipv4 4\n')
        self.assertEqual(metrics, {'magicsock_recv_data_derp': 9, 'magicsock_send_data_ipv4': 4})
        before = {r: {'transportCounters': dict(metrics)} for r in g4.ROLES}
        after = copy.deepcopy(before)
        for r in g4.ROLES:
            after[r]['transportCounters']['magicsock_recv_data_derp'] += 3
        self.assertEqual(g4.counter_deltas(before, after)['C1']['magicsock_recv_data_derp'], 3)
        after['R']['transportCounters']['magicsock_recv_data_derp'] = 0
        with self.assertRaises(ValueError):
            g4.counter_deltas(before, after)
        after['R']['transportCounters'] = {}
        with self.assertRaises(ValueError):
            g4.counter_deltas(before, after)

    def test_peer_no_guessing(self):
        with self.assertRaises(ValueError):
            g4.peer({'Peer': {}}, '100.64.0.1')
        p = {'TailscaleIPs': ['100.64.0.1'], 'CurAddr': ''}
        self.assertEqual(g4.peer({'Peer': {'key': p}}, '100.64.0.1'), p)

    def evidence_fixture(self):
        events = ('send/accepted', 'send/rejected', 'probe/accepted', 'probe/rejected',
                  'receive/accepted', 'receive/rejected', 'health/confirmed', 'health/forbidden',
                  'last_recv/confirmed', 'last_recv/forbidden', 'pong/confirmed', 'pong/forbidden')
        off = dict(schema=1, generation=0, enabled=False, matchedPeers=0, unmatchedPeers=0,
                   counters={f'{g}/{p}/{e}': 0 for g in ('matched', 'unmatched', 'unknown')
                             for p in ('direct', 'peer_relay', 'derp', 'unknown') for e in events})
        active = copy.deepcopy(off)
        active.update(generation=1, enabled=True, matchedPeers=1, unmatchedPeers=2)
        default = {r: {'policy': {'pathEvidence': copy.deepcopy(off)}} for r in ('R', 'I')}
        first = {'pathEvidence': copy.deepcopy(active)}
        before = copy.deepcopy(default)
        before['R']['policy'] = copy.deepcopy(first)
        after = copy.deepcopy(before)
        for cell in ('matched/derp/send/accepted', 'matched/derp/receive/accepted', 'matched/derp/last_recv/confirmed',
                     'matched/derp/health/confirmed', 'unmatched/direct/send/accepted', 'unmatched/direct/receive/accepted',
                     'unmatched/direct/last_recv/confirmed'):
            after['R']['policy']['pathEvidence']['counters'][cell] = 10
        return default, first, before, after

    def test_complete_evidence_and_forbidden_cells(self):
        args = self.evidence_fixture()
        proof = g4.assert_path_evidence(*args)
        self.assertEqual(proof['generation'], 1)
        for path in ('direct', 'peer_relay', 'unknown'):
            for event in ('send/accepted', 'probe/accepted', 'receive/accepted', 'health/confirmed', 'last_recv/confirmed', 'pong/confirmed'):
                for at in (1, 2, 3):
                    args = self.evidence_fixture()
                    p = args[at] if at == 1 else args[at]['R']['policy']
                    # Persist in subsequent samples to avoid a reset error masking the violation.
                    for later in range(at, 4):
                        p = args[later] if later == 1 else args[later]['R']['policy']
                        p['pathEvidence']['counters'][f'matched/{path}/{event}'] = 1
                    with self.assertRaisesRegex(ValueError, 'forbidden acceptance'):
                        g4.assert_path_evidence(*args)

    def test_missing_reset_scope_positive_and_off_evidence(self):
        for mutate, error in (
            (lambda e: e.pop('schema'), g4.EvidenceUnavailable),
            (lambda e: e['counters'].pop('matched/direct/send/accepted'), g4.EvidenceUnavailable),
            (lambda e: e.update(generation=2), g4.EvidenceUnavailable),
            (lambda e: e.update(matchedPeers=2), ValueError),
            (lambda e: e['counters'].update({'matched/derp/receive/accepted': 0}), ValueError),
            (lambda e: e['counters'].update({'matched/derp/health/forbidden': 1}), ValueError),
        ):
            args = self.evidence_fixture()
            mutate(args[3]['R']['policy']['pathEvidence'])
            with self.assertRaises(error):
                g4.assert_path_evidence(*args)
        args = self.evidence_fixture()
        args[0]['I']['policy']['pathEvidence']['counters']['unmatched/direct/send/accepted'] = 1
        with self.assertRaisesRegex(ValueError, 'default-off'):
            g4.assert_path_evidence(*args)
        args = self.evidence_fixture()
        args[2]['R']['policy']['pathEvidence']['counters']['matched/direct/send/rejected'] = 1
        with self.assertRaisesRegex(g4.EvidenceUnavailable, 'reset'):
            g4.assert_path_evidence(*args)

    def test_var_lib_root(self):
        self.assertEqual(g4.topology(RUN, '/var/lib/'+RUN, '10.203.77.0/29')['root'], '/var/lib/'+RUN)

    def ready_states(self):
        ids = {r: {'IP': '100.64.0.'+str(i+1), 'StableID': 'n'+str(i)} for i, r in enumerate(g4.ROLES)}
        self.lab.report['identities'] = ids
        return {r: {'BackendState': 'Running', 'Self': {'ID': ids[r]['StableID'], 'Relay': 'g4'},
                    'Peer': {o: {'ID': ids[o]['StableID'], 'Relay': 'g4', 'TailscaleIPs': [ids[o]['IP']]}
                             for o in g4.ROLES if o != r}} for r in g4.ROLES}

    def test_readiness_identity_and_derp_required(self):
        states = self.ready_states()
        self.assertTrue(g4.peers_ready(states, self.lab.report['identities']))
        for field, value in (('ID', 'wrong'), ('Relay', '')):
            bad = copy.deepcopy(states)
            bad['R']['Peer']['C1'][field] = value
            self.assertFalse(g4.peers_ready(bad, self.lab.report['identities']))
        with patch.object(self.lab, 'status', side_effect=lambda r: states[r]):
            self.lab.ready_for_policy()
        self.assertTrue((self.root/'policy-readiness.json').exists())
        with patch.object(self.lab, 'wait_for', side_effect=ValueError('deadline')):
            with self.assertRaisesRegex(g4.EvidenceUnavailable, 'readiness'):
                self.lab.ready_for_policy()

    def test_convergence_drives_allowed_probe_and_records_failure(self):
        states = self.ready_states()
        clock = [0.0]
        probed = []
        def policy():
            return {'source_sha256': 'digest', 'applied': True, 'runtimeReady': True,
                    'enabledModules': {'path_policy': True},
                    'pathEvidence': self.evidence_fixture()[1]['pathEvidence'],
                    'paths': {'ACTIVE/derp/ACTIVE': 1} if probed else {'PROBING//POLICY_NO_PATH': 1}}
        def cli(*args, **kw):
            probed.append(args)
            clock[0] += 1
            return subprocess.CompletedProcess(args, 0, 'pong via DERP(g4)', '')
        with patch.object(g4.time, 'monotonic', side_effect=lambda: clock[0]), patch.object(g4.time, 'sleep'), patch.object(self.lab, 'policy_status', side_effect=lambda r: policy()), patch.object(self.lab, 'status', side_effect=lambda r: states[r]), patch.object(self.lab, 'cli', side_effect=cli):
            self.lab.converge(0, 'digest')
        self.assertEqual(probed[0][:3], ('R', 'ping', '--c=1'))
        samples = json.loads((self.root/'convergence.json').read_text())
        self.assertEqual(samples[0]['policy']['paths'], {'PROBING//POLICY_NO_PATH': 1})
        self.assertEqual(samples[-1]['policy']['paths'], {'ACTIVE/derp/ACTIVE': 1})
        self.assertTrue(samples[0]['peers']['R'][1]['expectedMatched'])
        clock[0] = 0
        def never(*args, **kw):
            clock[0] += 10
            return subprocess.CompletedProcess(args, 1, 'timeout', '')
        with patch.object(g4.time, 'monotonic', side_effect=lambda: clock[0]), patch.object(g4.time, 'sleep'), patch.object(self.lab, 'policy_status', return_value={'paths': {'PROBING//POLICY_NO_PATH': 1}, 'pathEvidence': self.evidence_fixture()[1]['pathEvidence']}), patch.object(self.lab, 'status', side_effect=lambda r: states[r]), patch.object(self.lab, 'cli', side_effect=never):
            with self.assertRaisesRegex(ValueError, 'exceeded 30 seconds'):
                self.lab.converge(0, 'digest')
        self.assertEqual(len(json.loads((self.root/'convergence.json').read_text())), 3)
        with patch.object(g4.time, 'monotonic', return_value=0), patch.object(self.lab, 'policy_status', return_value={}), patch.object(self.lab, 'status', side_effect=lambda r: states[r]), patch.object(self.lab, 'cli') as cli_mock:
            with self.assertRaisesRegex(g4.EvidenceUnavailable, 'Missing R18'):
                self.lab.converge(0, 'digest')
            cli_mock.assert_not_called()

    def lab_traffic(self, label):
        # Exercise the real traffic collector and parser, including strict phase.
        def run(args, **kw):
            output = ''
            if str(HERE/'udp.py') in args:
                ip, nonce = args[-2:]
                output = json.dumps(self.udp_success(ip, nonce))
            return subprocess.CompletedProcess(args, 0, output, '')
        with patch.object(self.host, 'run', side_effect=run):
            return g4.Lab.traffic(self.lab, label)

    def udp_success(self, ip, nonce):
        return dict(schema=1, ok=True, target=ip, nonce=nonce, sent=8, received=8,
                    sequences=list(range(8)), seconds=0.1,
                    bytesEachDirection=sum(len(g4.udp.payload(nonce, i)) for i in range(8)))

    def test_udp_parser_rejects_bad_or_failed_evidence(self):
        data = self.udp_success('100.64.0.1', 'nonce')
        def parse(value, rc=0):
            return g4.parse_udp(subprocess.CompletedProcess([], rc, json.dumps(value), 'error'), '100.64.0.1', 'nonce')
        self.assertTrue(parse(data)['ok'])
        for value in ([], {}, dict(data, nonce='stale'), dict(data, target='127.0.0.1'),
                      dict(data, received=7), dict(data, sent=True), dict(data, sequences=[0]*8),
                      dict(data, bytesEachDirection=0), dict(data, seconds=float('nan')), dict(data, ok=False)):
            self.assertFalse(parse(value)['ok'], value)
        self.assertIn('exited 1', parse(data, 1)['error'])
        self.assertFalse(g4.parse_udp(subprocess.CompletedProcess([], 0, 'not json', ''), 'ip', 'nonce')['ok'])

    def test_udp_timeout_and_nonzero_preserved_in_traffic(self):
        self.ready_states()
        for failure in ('timeout', 'exit', 'invalid'):
            def run(args, **kw):
                if str(HERE/'udp.py') in args:
                    if failure == 'timeout':
                        raise subprocess.TimeoutExpired(args, kw['timeout'])
                    return subprocess.CompletedProcess(args, 1 if failure == 'exit' else 0, '{}', 'injected UDP failure')
                return subprocess.CompletedProcess(args, 0, '', '')
            with patch.object(self.host, 'run', side_effect=run):
                probes = self.lab.traffic('strict')
            saved = json.loads((self.root/'strict-traffic.json').read_text())
            self.assertEqual(saved, probes)
            self.assertEqual(len(probes), 8)
            self.assertTrue(all(p['tcp'] and p['ping'] and not p['udp'] and p['udpResult']['error'] for p in probes))
            with self.assertRaisesRegex(ValueError, 'strict C1->R udp failed'):
                g4.assert_traffic(probes, 'strict')
        good = self.lab_traffic('default')
        g4.assert_traffic(good, 'default')
        with self.assertRaisesRegex(ValueError, 'incomplete'):
            g4.assert_traffic(good[:-1], 'default')

    def test_retry_success_and_exhaustion_all_protocols(self):
        self.ready_states()
        for protocol in ('ping', 'tcp', 'udp'):
            for recover in (True, False):
                counts = {}
                def run(args, **kw):
                    kind = 'udp' if str(HERE/'udp.py') in args else 'tcp' if str(HERE/'tcp.py') in args else 'ping'
                    key = (args[3], kind)
                    counts[key] = counts.get(key, 0) + 1
                    failed = kind == protocol and (not recover or counts[key] == 1)
                    output = json.dumps(self.udp_success(*args[-2:])) if kind == 'udp' else 'pong'
                    return subprocess.CompletedProcess(args, int(failed), output, 'last injected failure' if failed else '')
                with patch.object(self.host, 'run', side_effect=run), patch.object(g4.time, 'sleep'):
                    probes = self.lab.traffic('strict')
                history = json.loads((self.root/'strict-traffic-attempts.json').read_text())
                self.assertEqual(len(history[0][protocol]), 2 if recover else 3)
                self.assertFalse(history[0][protocol][0]['ok'])
                self.assertEqual(probes[0][protocol], recover)
                if protocol == 'udp':
                    self.assertEqual(len({a['nonce'] for a in history[0]['udp']}), len(history[0]['udp']))
                if recover:
                    g4.assert_traffic(probes, 'strict')
                else:
                    with self.assertRaisesRegex(ValueError, 'strict C1->R '+protocol+' failed'):
                        g4.assert_traffic(probes, 'strict')
                    self.assertEqual(probes[0][protocol+'Result']['stderr'], 'last injected failure')
                    self.assertNotEqual(self.lab.report['result'], 'PASS')

    def test_main_exhausted_ping_is_fail_even_with_tcp_udp_success(self):
        self.ready_states()
        root = Path(self.temp.name).resolve()/('g4-'+'e'*32)
        def cases(lab):
            lab.report['identities'] = self.lab.report['identities']
            lab.active_case = 'I-P001'
            g4.assert_traffic(lab.traffic('strict'), 'strict')
        def run(args, **kw):
            if 'ping' in args:
                return subprocess.CompletedProcess(args, 1, '', 'last ping timeout')
            out = json.dumps(self.udp_success(*args[-2:])) if str(HERE/'udp.py') in args else ''
            return subprocess.CompletedProcess(args, 0, out, '')
        with patch.object(g4.sys, 'platform', 'linux'), patch.object(g4.os, 'geteuid', return_value=0), patch.object(g4.signal, 'signal'), patch.object(g4, 'Host', return_value=self.host), patch.object(self.host, 'run', side_effect=run), patch.object(g4.time, 'sleep'), patch.object(g4.Lab, 'preflight'), patch.object(g4.Lab, 'create'), patch.object(g4.Lab, 'start'), patch.object(g4.Lab, 'cases', cases), contextlib.redirect_stdout(io.StringIO()):
            rc = g4.main(['--run-id', root.name, '--root', str(root), '--inputs', str(HERE/'inputs.example.json'), '--execute'])
        report = json.loads((root/'report.json').read_text())
        self.assertEqual(rc, 1)
        self.assertEqual(report['result'], 'FAIL')
        self.assertEqual(report['cases'][1]['result'], 'FAIL')
        self.assertIn('last ping timeout', report['error'])
        self.assertEqual(report['cleanup']['result'], 'PASS')
        probes = json.loads((root/'strict-traffic.json').read_text())
        self.assertTrue(all(p['tcp'] and p['udp'] and not p['ping'] for p in probes))

    def test_retry_total_deadline_and_timeout_evidence(self):
        self.ready_states()
        clock, timeouts, attempts = [0.0], [], []
        def run(args, timeout, **kw):
            timeouts.append(timeout)
            clock[0] += timeout
            raise subprocess.TimeoutExpired(args, timeout)
        with patch.object(self.host, 'run', side_effect=run), patch.object(g4.time, 'monotonic', side_effect=lambda: clock[0]), patch.object(g4.time, 'sleep', side_effect=lambda t: clock.__setitem__(0, clock[0]+t)):
            result = self.lab.retry_probe('C1', 'R', 'tcp', attempts, lambda: None)
        self.assertFalse(result['ok'])
        self.assertEqual(timeouts, [20, 9.75])
        self.assertEqual(clock[0], 30)
        self.assertEqual(len(attempts), 2)
        self.assertIn('timed out', result['error'])

    def test_strict_positive_control_requires_successful_derp(self):
        self.ready_states()
        for outputs, ok in (([(1, 'timeout'), (0, 'pong via DERP(g4)')], True),
                            ([(0, 'pong via 10.0.0.1:41641')]*3, False),
                            ([(1, 'last timeout')]*3, False)):
            replies = [subprocess.CompletedProcess([], rc, out, '') for rc, out in outputs]
            with patch.object(self.lab, 'cli', side_effect=replies), patch.object(g4.time, 'sleep'):
                if ok:
                    self.lab.strict_warmup()
                else:
                    with self.assertRaisesRegex(ValueError, 'DERP positive control failed'):
                        self.lab.strict_warmup()
            record = json.loads((self.root/'strict-warmup.json').read_text())
            self.assertEqual(record['attempts'][-1]['ok'], ok)
            self.assertEqual(len(record['attempts']), len(outputs))

    def test_warmup_failure_stops_before_strict_traffic(self):
        self.ready_states()
        before = {r: {'policy': {'enabledModules': {'root': False}},
                       'status': {'Peer': {o: {'TailscaleIPs': [self.lab.address(o)], 'CurAddr': 'direct'}
                                          for o in g4.ROLES if o != r}}} for r in g4.ROLES}
        with patch.object(self.lab, 'snapshot', return_value=before), patch.object(self.lab, 'traffic', side_effect=self.lab_traffic) as traffic, patch.object(self.lab, 'ready_for_policy'), patch.object(self.lab, 'begin_monitor'), patch.object(self.lab, 'wait_for', return_value={}), patch.object(self.lab, 'converge'), patch.object(self.lab, 'strict_warmup', side_effect=ValueError('positive control failed')):
            with self.assertRaisesRegex(ValueError, 'positive control failed'):
                self.lab.cases()
        self.assertEqual([c.args[0] for c in traffic.call_args_list], ['default'])
        self.assertNotEqual(self.lab.report['result'], 'PASS')

    def test_udp_datagram_nonce_sequence_source_and_timeout(self):
        # Socket double exercises the real probe loop without host network rights.
        from unittest.mock import MagicMock
        for failure in (None, 'nonce', 'sequence', 'source', 'timeout'):
            sock = MagicMock()
            sock.__enter__.return_value = sock
            last = []
            def send(data, target):
                last[:] = [data, target]
                return len(data)
            def receive(size):
                data, target = last
                if failure == 'timeout':
                    raise TimeoutError('timed out')
                if failure == 'nonce':
                    data = data.replace(b'nonce', b'wrong')
                if failure == 'sequence':
                    data = g4.udp.payload('nonce', 7)
                return data, ('127.0.0.2', target[1]) if failure == 'source' else target
            sock.sendto.side_effect = send
            sock.recvfrom.side_effect = receive
            with patch.object(g4.udp.socket, 'socket', return_value=sock):
                result = g4.udp.probe('127.0.0.1', 'nonce')
            self.assertEqual(result['ok'], failure is None)
            if failure is None:
                self.assertEqual(result['sequences'], list(range(8)))
                self.assertEqual(result['received'], 8)
            else:
                self.assertIn('error', result)
            sock.connect.assert_not_called()

    def test_case_smoke_never_becomes_full_pass(self):
        identities = {r: {'IP': '100.64.0.'+str(i+1), 'StableID': 'n'+str(i)} for i, r in enumerate(g4.ROLES)}
        self.lab.report['identities'] = identities
        def snap(label):
            strict = label.startswith('strict')
            data = {}
            for role in g4.ROLES:
                data[role] = {'status': {'Peer': {other: {'TailscaleIPs': [identities[other]['IP']],
                    'CurAddr': '' if strict and {role, other} == {'R', 'C1'} else '10.0.0.2:41641'}
                    for other in g4.ROLES if other != role}}, 'transportCounters': {
                        'magicsock_send_data_derp': 20 if label == 'strict-after' else 10,
                        'magicsock_recv_data_derp': 20 if label == 'strict-after' else 10}}
                if role in ('R', 'I'):
                    data[role]['policy'] = {'enabledModules': {'root': strict and role == 'R'}}
            if strict:
                data['R']['policy'] = policy()
            return data
        def policy():
            return {'source_sha256': g4.sha(self.root/'R-policy.json'), 'applied': True, 'runtimeReady': True,
                    'enabledModules': {'root': True, 'path_policy': True}, 'paths': {'ACTIVE/derp/ACTIVE': 1}}
        with patch.object(self.lab, 'ready_for_policy'), patch.object(self.lab, 'converge'), patch.object(self.lab, 'strict_warmup'), patch.object(self.lab, 'begin_monitor'), patch.object(self.lab, 'check_monitor'), patch.object(self.lab, 'snapshot', side_effect=snap), patch.object(self.lab, 'traffic', side_effect=lambda label: self.lab_traffic(label)), patch.object(self.lab, 'policy_status', side_effect=lambda r: policy()):
            self.lab.cases()
        self.assertEqual(self.lab.report['result'], 'BLOCKED')
        self.assertEqual([c['smoke'] for c in self.lab.report['cases']], ['PASS', 'PASS'])
        config = json.loads((self.root/'R-policy.json').read_text())
        self.assertEqual(config['path_policy']['rules'][0]['stable_ids'], ['n2'])
        default, first, start, end = self.evidence_fixture()
        def complete_snap(label):
            data = snap(label)
            fixture = end if label == 'strict-after' else start if label == 'strict-before' else default
            for role in ('R', 'I'):
                data[role]['policy']['pathEvidence'] = fixture[role]['policy']['pathEvidence']
            return data
        with patch.object(self.lab, 'ready_for_policy'), patch.object(self.lab, 'converge'), patch.object(self.lab, 'strict_warmup'), patch.object(self.lab, 'begin_monitor'), patch.object(self.lab, 'check_monitor'), patch.object(self.lab, 'snapshot', side_effect=complete_snap), patch.object(self.lab, 'traffic', side_effect=lambda label: self.lab_traffic(label)), patch.object(self.lab, 'policy_status', side_effect=lambda r: dict(policy(), **first)):
            self.lab.cases()
        self.assertEqual(self.lab.report['result'], 'PASS')
        self.assertTrue((self.root/'path-evidence.json').exists())
        for phase in ('default', 'strict'):
            def failed_udp(label):
                probes = self.lab_traffic(label)
                if label == phase:
                    probes[0].update(udp=False, udpResult={'error': 'injected timeout'})
                return probes
            with patch.object(self.lab, 'ready_for_policy'), patch.object(self.lab, 'converge'), patch.object(self.lab, 'strict_warmup'), patch.object(self.lab, 'begin_monitor'), patch.object(self.lab, 'check_monitor'), patch.object(self.lab, 'snapshot', side_effect=complete_snap), patch.object(self.lab, 'traffic', side_effect=failed_udp), patch.object(self.lab, 'policy_status', side_effect=lambda r: dict(policy(), **first)):
                with self.assertRaisesRegex(ValueError, phase+' C1->R udp failed: injected timeout'):
                    self.lab.cases()
        def stale_client(label):
            data = complete_snap(label)
            if label == 'strict-after':
                data['C1']['status']['Peer']['R']['CurAddr'] = '10.0.0.2:41641'
            return data
        with patch.object(self.lab, 'ready_for_policy'), patch.object(self.lab, 'converge'), patch.object(self.lab, 'strict_warmup'), patch.object(self.lab, 'begin_monitor'), patch.object(self.lab, 'check_monitor'), patch.object(self.lab, 'snapshot', side_effect=stale_client), patch.object(self.lab, 'traffic', side_effect=lambda label: self.lab_traffic(label)), patch.object(self.lab, 'policy_status', side_effect=lambda r: dict(policy(), **first)):
            with self.assertRaisesRegex(ValueError, 'C1 retained R direct path'):
                self.lab.cases()


if __name__ == '__main__':
    unittest.main()
