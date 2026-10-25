#!/usr/bin/env python3
"""Wire-envelope regression only; does not claim a daemon lifecycle pass."""
import ast
import base64
import hashlib
import copy
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import Mock

# Load the actual transport/preview/execute functions without starting the
# Linux-only top-level lifecycle or changing its assertions for this unit test.
source = Path(__file__).with_name('cli810.py')
tree = ast.parse(source.read_text(), filename=str(source))
functions = ast.Module(body=[n for n in tree.body if isinstance(n, ast.FunctionDef)
                            and n.name in ('save', 'command', 'cli', 'preview', 'execute', 'settled_preview', 'takeover_ready', 'enable_takeover', 'seed_control_history')],
                       type_ignores=[])


class EnvelopeTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        commands = (root/'commands.jsonl').open('w')
        self.addCleanup(commands.close)
        self.run = Mock()
        self.ns = dict(json=json, base64=base64, hashlib=hashlib, time=time, subprocess=Mock(run=self.run),
                       root=root, bin=root/'bin', sock=root/'socket', commands=commands,
                       count=0, phase='regression')
        exec(compile(functions, str(source), 'exec'), self.ns)

    def respond(self, response):
        self.run.return_value = Mock(returncode=0, stdout=json.dumps(response), stderr='')

    def test_adopt_and_reset_preserve_plan_and_cas(self):
        for kind in ('appc-route-adopt', 'appc-route-reset'):
            with self.subTest(kind=kind):
                plan = dict(Fence=dict(ProfileID='fixture', Generation=17), SourceID=29,
                            LegacySourceID=13, SnapshotHash='ab'*32,
                            Entries=[dict(Eligible=True)], Withdraw=['192.0.1.1/32'],
                            Retain=['0.0.0.0/0', '::/0'])
                response = dict(clear_preview=plan, accepted_generation=99,
                                Fence=dict(Generation=999), SourceID=999)
                self.respond(response)
                args = ('--manifest=manifest.json', '--claims=claims.json') if kind.endswith('adopt') else ()
                actual = self.ns['preview'](kind, *args)
                self.assertEqual(actual, plan)
                raw = self.ns['root']/f"{self.ns['count']:03d}.stdout"
                self.assertEqual(json.loads(raw.read_text()), response)
                self.ns['execute'](kind, actual, *args)
                self.assertEqual(self.run.call_args.args[0][2:], [
                    'debug', kind, '--source=r27-synthetic-control', '--execute',
                    '--expect-sha256='+'ab'*32, '--expect-generation=17',
                    '--expect-source-id=29', *args])

    def test_invalid_envelope_fails_without_retry_or_execute(self):
        for response in ({'Fence': {}}, {'clear_preview': None},
                         {'clear_preview': []}, {'clear_preview': '{}'}, []):
            with self.subTest(response=response):
                self.run.reset_mock()
                self.respond(response)
                with self.assertRaisesRegex(ValueError, 'response.clear_preview'):
                    self.ns['preview']('appc-route-adopt')
                self.assertEqual(self.run.call_count, 1)


class StablePreviewTest(EnvelopeTest):
    def test_waits_for_same_hash_for_two_seconds(self):
        self.ns['time'] = Mock(monotonic=Mock(side_effect=[0, 0, 0, .5, 1.5, 2.5]))
        self.ns['preview'] = Mock(side_effect=[{'SnapshotHash':h} for h in ('old','new','new','new')])
        self.assertEqual(self.ns['settled_preview']('appc-route-adopt', '--manifest=m'), {'SnapshotHash':'new'})
        self.assertEqual(self.ns['preview'].call_count, 4)
        self.ns['preview'].assert_called_with('appc-route-adopt', '--manifest=m')
        self.run.assert_not_called()

    def test_continuous_change_is_bounded(self):
        self.ns['time'] = Mock(monotonic=Mock(side_effect=[0, 0, 0, 31]))
        self.ns['preview'] = Mock(side_effect=[{'SnapshotHash':'a'}, {'SnapshotHash':'b'}])
        with self.assertRaisesRegex(RuntimeError, 'preview did not settle'):
            self.ns['settled_preview']('appc-route-reset')
        self.run.assert_not_called()


class TakeoverTest(EnvelopeTest):
    def test_settled_preview_returns_latest_plan_without_execute(self):
        plans = [{'SnapshotHash':h, 'sample':i} for i,h in enumerate('abbbbb')]
        self.ns['preview'] = Mock(side_effect=plans)
        self.ns['execute'] = Mock()
        self.ns['time'] = Mock(monotonic=Mock(side_effect=[0,0,0,.5,1,1.5,2,2.5]))
        self.assertEqual(self.ns['settled_preview']('appc-route-adopt'), plans[-1])
        self.ns['execute'].assert_not_called()
        self.ns['preview'] = Mock(side_effect=plans[:2])
        self.ns['time'] = Mock(monotonic=Mock(side_effect=[0,0,0,31]))
        with self.assertRaisesRegex(RuntimeError, 'preview did not settle'):
            self.ns['settled_preview']('appc-route-adopt')

    def test_enable_retries_only_readonly_input_race(self):
        self.ns['policy'] = self.ns['root']/'policy.json'
        self.ns['time'] = Mock(monotonic=Mock(return_value=0))
        self.ns['cli'] = Mock(side_effect=[
            RuntimeError('policy_inputs_changed_retry'),
            dict(schemaValid=True, runtimeReady=True, requested_sha256='ab'*32),
            dict(acceptedFence={'Generation':8}), dict(accepted=True)])
        self.ns['takeover_ready'] = Mock(return_value={'ready':True})
        self.assertEqual(self.ns['enable_takeover'](), {'ready':True})
        calls = self.ns['cli'].call_args_list
        self.assertEqual(calls[0], calls[1])
        self.assertEqual(sum(c.args[2] == 'reload' for c in calls), 1)
        self.ns['cli'] = Mock(side_effect=RuntimeError('unrelated failure'))
        with self.assertRaisesRegex(RuntimeError, 'unrelated failure'):
            self.ns['enable_takeover']()
        self.assertEqual(self.ns['cli'].call_count, 1)

    def test_enable_uses_real_reload_cas_before_readiness(self):
        self.ns['policy'] = self.ns['root']/'policy.json'
        self.ns['cli'] = Mock(side_effect=[
            dict(schemaValid=True, runtimeReady=True, requested_sha256='ab'*32),
            dict(acceptedFence={'Generation':8}), dict(accepted=True)])
        self.ns['takeover_ready'] = Mock(return_value={'ready':True})
        self.assertEqual(self.ns['enable_takeover'](), {'ready':True})
        policy = json.loads(self.ns['policy'].read_text())
        self.assertEqual(policy, {'schema_version':2, 'enabled':True,
                                 'app_connector_ttl':{'enabled':True}})
        self.assertEqual(self.ns['cli'].call_args.args, ('debug', 'unified-policy', 'reload',
                         '--expect-generation=8', '--expect-sha256='+'ab'*32))
        self.ns['takeover_ready'].assert_called_once_with('takeover-before-seed')

    def test_seed_preserves_authority_and_go_checksum(self):
        journal = dict(Schema=2, Complete=True, Handoff=False,
                       Transition={'After':{'Fence':{'Generation':42}, 'Leases':[]}},
                       Ledger={'Owners':{'198.51.100.0/24':{'Control':{'appc-control':True}}}},
                       Unclaimed={'Control':['198.51.100.0/24']})
        original = copy.deepcopy(journal)
        payload = json.dumps(journal, separators=(',', ':'))
        envelope = ('{"Payload":'+payload+',"SHA256":'+
                    json.dumps(list(hashlib.sha256(payload.encode()).digest()))+'}')
        store = {'profile-p||_appConnectorTTLV2':base64.b64encode(envelope.encode()).decode(),
                 'identity':'unchanged', 'profile-p||_unifiedRouteLedgerV1':'unchanged'}
        prefixes = [f'192.0.{i//250+1}.{i%250+1}/32' for i in range(810)]
        self.ns['seed_control_history'](store, 'profile-p', prefixes)
        raw = base64.b64decode(store['profile-p||_appConnectorTTLV2']).decode()
        out = json.loads(raw)
        value, end = json.JSONDecoder().raw_decode(raw[len('{"Payload":'):])
        self.assertEqual(out['SHA256'], list(hashlib.sha256(raw[len('{"Payload":'):][:end].encode()).digest()))
        self.assertEqual(value['Unclaimed']['Control'], prefixes)
        self.assertEqual(value['Unclaimed']['Domains'], {})
        value.pop('Unclaimed'); original.pop('Unclaimed')
        self.assertEqual(value, original)
        self.assertEqual(store['identity'], 'unchanged')
        self.assertEqual(store['profile-p||_unifiedRouteLedgerV1'], 'unchanged')
        corrupted = dict(store)
        corrupted['profile-p||_appConnectorTTLV2'] = base64.b64encode(raw.replace('"Schema":2', '"Schema":3').encode()).decode()
        with self.assertRaisesRegex(AssertionError, 'checksum'):
            self.ns['seed_control_history'](corrupted, 'profile-p', prefixes)

    def test_ready_requires_enabled_modules_and_current_consumer(self):
        self.ns['policy'] = self.ns['root']/'policy.json'
        self.ns['policy'].write_text('{}')
        status = dict(enabledModules={'root':True, 'lease':True, 'auto_ipv6':False,
                      'dns_ipv4_only':False, 'path_policy':False}, runtimeReady=True,
                      degraded=False, source_sha256=hashlib.sha256(b'{}').hexdigest(),
                      acceptedFence={'Generation':7}, applied=False)
        plan = dict(Fence={'Generation':7}, Roots=['*.example.test'], Control=['198.51.100.0/24'])
        self.ns['cli'] = Mock(return_value=status)
        self.ns['settled_preview'] = Mock(return_value=plan)
        self.assertEqual(self.ns['takeover_ready']('ready'), plan)
        for bad in ('all-off', 'stale', 'degraded', 'wrong-file'):
            with self.subTest(bad=bad):
                st, pl = copy.deepcopy(status), copy.deepcopy(plan)
                if bad == 'all-off': st['enabledModules']['lease'] = False
                if bad == 'stale': pl['Fence']['Generation'] = 6
                if bad == 'degraded': st['degraded'] = True
                if bad == 'wrong-file': st['source_sha256'] = 'old'
                self.ns['cli'].return_value = st
                self.ns['settled_preview'].return_value = pl
                self.ns['time'] = Mock(monotonic=Mock(side_effect=[0,31]))
                with self.assertRaisesRegex(RuntimeError, 'takeover runtime not ready'):
                    self.ns['takeover_ready']('blocked')


if __name__ == '__main__':
    unittest.main()
