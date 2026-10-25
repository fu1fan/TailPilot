#!/usr/bin/env python3
"""Fake host tests. These are NOT native systemd or VM acceptance."""
import concurrent.futures
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import native
import plan


class FakeSystemctl(native.Host):
    def __init__(self, root):
        self.root = root
        self.calls = []
        self.boot = 'boot-a'
        self.wall, self.mono = 1000, 500
        self.fail = None
        self.tx = None
        self.statuses = []
        self.active = True
        self.sleeps = []
        self.timeouts = []
        self.prefs = {'AutoUpdate': {'Check': True, 'Apply': False}}
        self.held = True
    def path(self, path):
        return self.root / str(path).lstrip('/')
    def now(self):
        return self.wall, self.mono, self.boot
    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.mono += seconds
        self.wall += seconds
    def run(self, *args, timeout=120):
        self.timeouts.append(timeout)
        self.calls.append(args)
        if self.fail and self.fail in args:
            raise ValueError('injected host failure')
        if args[0] == '/usr/bin/systemctl':
            if args[1] == 'is-active':
                return 'active\n' if args[2] != native.UNIT or self.active else 'inactive\n'
            if '--property=MainPID' in args: return '42\n'
            if args[1:3] == ('start', native.UNIT):
                source = self.tx.stage / 'tailscaled' if self.tx.drop.exists() else self.path(self.tx.n['daemon'])
                exe = self.path('/proc/42/exe'); exe.parent.mkdir(parents=True, exist_ok=True)
                exe.write_bytes(source.read_bytes())
            if '--property=LoadState' in args: return 'loaded\n'
            if '--property=NextElapseUSecMonotonic' in args: return 'NextElapseUSecMonotonic=1500000000\n'
            if '--property=ExecStart' in args: return ' '.join(self.tx.argv('rollback'))
        if 'status' in args and '--json' in args and 'unified-policy' not in args:
            status = self.statuses.pop(0) if len(self.statuses) > 1 else (self.statuses[0] if self.statuses else 'Running')
            if isinstance(status, Exception): raise status
            if isinstance(status, dict): return json.dumps(status)
            return json.dumps(dict(BackendState=status, Self={'ID': self.tx.p['stableID']},
                                   TailscaleIPs=self.tx.n['tailscaleIPs']))
        if 'unified-policy' in args:
            return json.dumps(dict(schemaValid=True, runtimeReady=True, applied=True,
                                   source_sha256=self.tx.p['configurationSHA256'], enabledModules={},
                                   acceptedFence={'Generation': 1}))
        if 'version' in args: return 'fixture-version'
        if 'prefs' in args: return json.dumps(self.prefs)
        if 'set' in args:
            self.prefs['AutoUpdate']['Apply'] = '--auto-update=true' in args
        if args[0] == '/usr/bin/apt-mark':
            if args[1] == 'hold': self.held = True
            if args[1] == 'unhold': self.held = False
            if args[1] == 'showhold': return 'tailscale' if self.held else ''
        if args[0] == '/usr/bin/ss': return 'pid=42,'
        return ''


class NativeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.h = FakeSystemctl(Path(self.tmp.name))
        p = plan.read(Path(__file__).resolve().parents[1] / 'plan.example.json')
        p['native'] = dict(socket='/run/tailscale/tailscaled.sock', daemon='/usr/sbin/tailscaled',
                           cli='/usr/bin/tailscale', unit='/lib/systemd/system/tailscaled.service',
                           tailscaleIPs=['100.64.0.1'], dropins=[], stateFiles=['/var/lib/tailscale/tailscaled.state'])
        p['backupFiles']['config'] = []
        for name in ('daemon','cli','unit'):
            f = self.h.path(p['native'][name]); f.parent.mkdir(parents=True,exist_ok=True); f.write_text(name)
            p['expectedBefore'][p['native'][name]] = plan.digest(f)
        p['environmentFiles'] = []
        self.t = native.Transaction(p, 'a'*64, self.h, acceptance_hash='b'*64)
        self.h.tx = self.t
        self.t.d.mkdir(parents=True)
        self.t.write('stage', candidateSHA256='c'*64)
        for name in ('native.py','plan.py','compatibility.py','schema-v2.json','plan.json'):
            (self.t.d / name).write_text('fixture')
        plan.atomic(self.t.d / 'policy-local.json', {'acceptedFence': {'Generation': 1}})
        # Actual filesystem writes, actual flock and durable journals; fake commands only.
    def arm(self):
        with self.t.lock(): self.t.dispatch('arm')
    def ready_fixture(self):
        for name in ('/var/lib/dpkg/lock', '/var/lib/dpkg/lock-frontend', '/var/lib/apt/lists/lock'):
            f = self.h.path(name); f.parent.mkdir(parents=True, exist_ok=True); f.touch()
        self.t.stage.mkdir(parents=True)
        for name in ('tailscaled', 'tailscale', 'policy.json'):
            (self.t.stage / name).write_text(name)
        plan.atomic(self.t.stage / 'policy.json', {'schema_version': 2, 'enabled': False,
                                                   'app_connector_ttl': {'enabled': False}})
        self.t.p['configurationSHA256'] = plan.digest(self.t.stage / 'policy.json')
        (self.t.d / 'candidate.conf').write_text('candidate')
        self.t.write('stage', candidateSHA256=plan.digest(self.t.d / 'candidate.conf'),
                     daemonSHA256=plan.digest(self.t.stage / 'tailscaled'),
                     cliSHA256=plan.digest(self.t.stage / 'tailscale'))
        plan.atomic(self.t.d / 'prefs-before.json', self.h.prefs)
        state = self.h.path(self.t.n['stateFiles'][0])
        state.parent.mkdir(parents=True); state.write_text('before')
        self.t.p['expectedBefore'] = {name: plan.digest(self.h.path(name)) for name in
                                      [self.t.n[k] for k in ('daemon', 'cli', 'unit')] + self.t.n['stateFiles']}
        self.arm()

    def test_delayed_switch_verify_and_rollback_preserve_changed_state(self):
        self.ready_fixture()
        self.t.dispatch('switch'); self.t.dispatch('switch-worker')
        calls = list(self.h.calls)
        with self.assertRaisesRegex(ValueError, 'invalid phase'): self.t.dispatch('switch')
        self.assertEqual(calls, self.h.calls)
        self.h.statuses = [ValueError('socket not ready'), 'Starting', 'Starting', 'Running']
        self.t.dispatch('verify')
        self.assertEqual(self.t.journal()['phase'], 'verified')
        state = self.h.path(self.t.n['stateFiles'][0]); state.write_text('normal daemon update')
        self.h.statuses = ['Starting'] * 4 + ['Running']
        with patch.object(self.t, 'fallback', wraps=self.t.fallback) as fallback:
            self.t.dispatch('rollback'); fallback.assert_not_called()
        self.assertEqual(state.read_text(), 'normal daemon update')
        self.assertEqual(self.t.journal()['phase'], 'rolled-back')
        self.assertEqual(self.h.prefs['AutoUpdate']['Apply'], self.t.p['autoUpdateApply'])
        calls = list(self.h.calls); self.t.dispatch('rollback'); self.assertEqual(calls, self.h.calls)
        self.assertTrue(self.h.sleeps)

    def test_boot_finish_waits_before_update_restore(self):
        self.ready_fixture(); self.h.boot = 'boot-b'
        self.t.dispatch('boot')
        self.h.statuses = ['Starting', 'Starting', 'Running']
        with patch.object(self.t, 'restore_updates', wraps=self.t.restore_updates) as restore:
            self.t.dispatch('finish'); restore.assert_called_once()
        self.assertEqual(self.t.journal()['phase'], 'rolled-back')
        self.assertTrue(self.t.guard.exists())

    def test_never_running_and_identity_do_not_fallback(self):
        self.ready_fixture()
        for status, category in [('Starting', 'backend-not-running'),
                                  (ValueError('socket'), 'status-unavailable'),
                                  ({'BackendState': 'Running', 'Self': {'ID': 'different'},
                                    'TailscaleIPs': self.t.n['tailscaleIPs']}, 'identity-mismatch'),
                                  ({'BackendState': 'Running', 'Self': {'ID': self.t.p['stableID']},
                                    'TailscaleIPs': ['100.64.0.2']}, 'identity-mismatch')]:
            with self.subTest(category=category):
                self.h.statuses = [status]; start = self.h.mono
                with patch.object(self.t, 'fallback') as fallback, patch.object(self.t, 'restore_updates') as updates:
                    with self.assertRaisesRegex(native.ReadinessError, category): self.t.dispatch('rollback')
                    fallback.assert_not_called(); updates.assert_not_called()
                self.assertAlmostEqual(self.h.mono - start, 30)
                self.assertEqual(self.t.journal()['phase'], 'rolling-back')
                self.assertTrue(self.t.guard.exists())
                self.assertNotIn(('/usr/bin/systemctl', 'stop', self.t.prefix + '-rollback.timer'), self.h.calls)

    def test_identity_mismatch_cannot_be_hidden(self):
        self.ready_fixture()
        self.h.statuses = [{'BackendState': 'Running', 'Self': {'ID': 'different'},
                            'TailscaleIPs': self.t.n['tailscaleIPs']}, 'Running']
        with self.assertRaisesRegex(native.ReadinessError, 'identity-mismatch'): self.t.wait_ready(old=True)

    def test_unavailable_service_fallback_still_refuses_changed_state(self):
        self.ready_fixture(); self.t.snapshot('consistent')
        state = self.h.path(self.t.n['stateFiles'][0]); state.write_text('changed')
        self.h.active = False
        with patch.object(self.t, 'fallback', wraps=self.t.fallback) as fallback:
            with self.assertRaisesRegex(ValueError, 'state changed'): self.t.dispatch('rollback')
            fallback.assert_called_once()
        self.assertEqual(state.read_text(), 'changed')

    def test_failed_start_uses_fallback_once(self):
        self.ready_fixture(); self.h.fail = 'start'
        with patch.object(self.t, 'fallback') as fallback:
            with self.assertRaisesRegex(ValueError, 'injected'): self.t.dispatch('rollback')
            fallback.assert_called_once()

    def test_commit_readiness_cannot_extend_deadline(self):
        self.ready_fixture(); self.t.write('verified')
        self.h.mono = self.t.journal()['monotonicDeadline'] - 0.2
        self.h.statuses = ['Starting']
        with patch.object(self.t, 'disarm') as disarm:
            with self.assertRaisesRegex(ValueError, 'deadline expired'): self.t.dispatch('commit')
            disarm.assert_not_called()
        self.assertEqual(self.t.journal()['phase'], 'verified')

    def test_non_readiness_verification_failure_never_rewinds_state(self):
        self.ready_fixture()
        self.h.prefs['RunSSH'] = True
        with patch.object(self.t, 'fallback') as fallback, patch.object(self.t, 'restore_updates') as updates:
            with self.assertRaisesRegex(ValueError, 'prefs drift'): self.t.dispatch('rollback')
            fallback.assert_not_called(); updates.assert_not_called()

    def test_inactive_then_active_ready(self):
        self.ready_fixture(); self.h.active = False
        original_sleep = self.h.sleep
        def advance(seconds):
            original_sleep(seconds)
            if len(self.h.sleeps) == 3: self.h.active = True
        with patch.object(self.h, 'sleep', side_effect=advance): self.t.wait_ready(old=True)
        self.assertEqual(len(self.h.sleeps), 3)

    def test_eligible_fallback_retries_readiness_before_updates(self):
        self.ready_fixture()
        self.t.snapshot('consistent'); self.h.active = False
        original_fallback = self.t.fallback
        def fallback():
            original_fallback()
            self.h.active = True
            self.h.statuses = ['Starting', 'Running']
        with patch.object(native.os, 'chown'), patch.object(self.t, 'fallback', side_effect=fallback) as restore:
            self.t.dispatch('rollback'); restore.assert_called_once()
        self.assertEqual(self.t.journal()['phase'], 'rolled-back')
        self.assertGreater(self.h.mono, 530)

    def test_probe_time_is_in_readiness_budget(self):
        self.ready_fixture()
        def blocked(*args, timeout=120):
            self.h.sleep(timeout)
            raise native.subprocess.TimeoutExpired(args, timeout)
        start = self.h.mono
        with patch.object(self.h, 'ctl', side_effect=blocked):
            with self.assertRaisesRegex(native.ReadinessError, 'service-unavailable'): self.t.wait_ready(old=True)
        self.assertAlmostEqual(self.h.mono - start, 30)

    def test_arm_timer_guard_full_argv(self):
        self.arm()
        self.assertEqual(self.t.journal()['phase'], 'armed')
        calls = self.h.calls
        timer = next(c for c in calls if c[0] == '/usr/bin/systemd-run')
        self.assertIn('--on-active=900s', timer)
        self.assertEqual(list(timer[-6:]), self.t.argv('rollback'))
        self.assertIn('Requires='+self.t.boot, self.t.guard.read_text())
        self.assertIn('Before=tailscaled.service', self.h.path('/etc/systemd/system/'+self.t.boot).read_text())
        with self.assertRaises(ValueError): self.t.dispatch('arm')
    def test_expiry_and_reboot_block_commit(self):
        self.arm()
        self.h.mono += 901
        with self.assertRaises(ValueError): self.t.valid_deadline()
        self.h.mono = 501; self.h.wall = 1
        self.h.boot = 'boot-b'
        with self.assertRaises(ValueError): self.t.valid_deadline()
    def test_boot_restores_before_async_start(self):
        self.arm(); self.h.boot = 'boot-b'
        with self.t.lock(): self.t.dispatch('boot')
        self.assertEqual(self.t.journal()['phase'], 'boot-restored')
        self.assertNotIn(('/usr/bin/systemctl','start','tailscaled.service'), self.h.calls)
        self.assertTrue(any('--property=After='+self.t.boot in c for c in self.h.calls))
    def test_same_boot_guard_noop_and_committed_reboot(self):
        self.arm(); before = self.t.jf.read_bytes()
        self.t.dispatch('boot'); self.assertEqual(before, self.t.jf.read_bytes())
        self.t.write('committed'); self.h.boot = 'boot-b'
        self.t.dispatch('boot'); self.assertEqual(self.t.journal()['phase'],'committed')
    def test_foreign_dropin_preserved(self):
        self.arm(); self.t.drop.write_text('manual edit')
        with self.assertRaises(ValueError): self.t.dispatch('rollback')
        self.assertEqual(self.t.drop.read_text(), 'manual edit')
        self.assertEqual(self.t.journal()['phase'], 'rolling-back')
        with self.assertRaises(ValueError): self.t.dispatch('commit')
    def test_rollback_idempotent_no_route_writes(self):
        self.arm()
        with patch.object(self.t,'verify'), patch.object(self.t,'restore_updates'):
            self.t.dispatch('rollback')
            before = list(self.h.calls)
            self.t.dispatch('rollback')
        self.assertEqual(before,self.h.calls)
        self.assertEqual(self.t.journal()['phase'],'rolled-back')
        self.assertFalse(any('/usr/sbin/ip' in c for c in self.h.calls))
    def test_actual_lock_commit_rollback_race(self):
        self.arm(); self.t.write('verified')
        e = dict(deploymentID=self.t.p['deploymentID'], stableID=self.t.p['stableID'],
                 releaseSHA256=self.t.p['releaseSHA256'], configurationSHA256=self.t.p['configurationSHA256'],
                 kind='external-e2e', passed=True, generation=1, expiresUnix=9999999999,
                 host=self.t.p['host'], deadlineUnix=self.t.journal()['wallDeadline'])
        f = self.t.d/'e2e.json'; plan.atomic(f,e)
        self.t.p['externalEvidence'] = str(f); self.t.acceptance_hash=plan.digest(f)
        def act(action):
            try:
                with self.t.lock(): self.t.dispatch(action)
            except ValueError:
                return 'refused'
        with patch.object(native,'private'), patch.object(self.t,'verify'), patch.object(self.t,'restore_updates'):
            with concurrent.futures.ThreadPoolExecutor(2) as pool:
                list(pool.map(act,['commit','rollback']))
        self.assertIn(self.t.journal()['phase'],native.TERMINAL)
        if self.t.journal()['phase']=='rolled-back':
            with self.assertRaises(ValueError): self.t.dispatch('commit')
        else:
            before=self.t.jf.read_bytes(); self.t.dispatch('rollback')
            self.assertEqual(before,self.t.jf.read_bytes())
    def test_commit_is_durable_before_timer_stop(self):
        self.arm(); self.t.write('verified')
        e=self.t.d/'e2e'; plan.atomic(e,dict(deadlineUnix=self.t.journal()['wallDeadline'],host=self.t.p['host'],generation=1))
        self.t.p['externalEvidence']=str(e)
        def stop():
            self.assertEqual(plan.read(self.t.jf)['phase'],'committed')
            raise ValueError('stop failure')
        with patch.object(native,'private'), patch.object(plan,'evidence'), patch.object(self.t,'verify'), patch.object(self.t,'disarm',stop):
            with self.assertRaises(ValueError): self.t.dispatch('commit')
        self.assertEqual(self.t.journal()['phase'],'committed')
    def test_state_fallback_refuses_new_manual_owner(self):
        state=self.h.path(self.t.n['stateFiles'][0]); state.parent.mkdir(parents=True); state.write_text('old')
        self.t.p['expectedBefore']={str('/var/lib/tailscale/tailscaled.state'):plan.digest(state)}
        self.t.snapshot('consistent'); state.write_text('new manual/control owner')
        with self.assertRaises(ValueError): self.t.fallback()
        self.assertEqual(state.read_text(),'new manual/control owner')
    def test_backup_permissions_and_manifest(self):
        self.t.p['expectedBefore']={self.t.n['daemon']:self.t.p['expectedBefore'][self.t.n['daemon']]}
        self.t.snapshot('readable')
        self.assertEqual((self.t.d/'readable').stat().st_mode&0o777,0o700)
        for f in (self.t.d/'readable').iterdir(): self.assertEqual(f.stat().st_mode&0o777,0o600)
    def test_pending_other_transaction_blocks(self):
        other=self.t.root/'other';other.mkdir();plan.atomic(other/'journal.json',{'phase':'armed'})
        with self.assertRaises(ValueError):
            with self.t.lock(): pass
    def test_cleanup_detaches_dependency_before_stopping_guard(self):
        self.arm(); self.t.write('committed')
        self.h.calls.clear()
        self.t.dispatch('cleanup')
        self.assertFalse(self.t.guard.exists())
        reload = self.h.calls.index(('/usr/bin/systemctl','daemon-reload'))
        stop = self.h.calls.index(('/usr/bin/systemctl','stop',self.t.boot))
        self.assertLess(reload,stop)
        self.assertTrue(self.t.jf.exists())
        self.assertTrue(self.t.journal()['cleaned'])
        self.assertNotIn(('/usr/bin/systemctl','stop','tailscaled.service'),self.h.calls)

    def test_no_early_switch_and_timer_failure(self):
        with self.assertRaises(ValueError): self.t.dispatch('switch')
        self.h.fail='is-active'
        with self.assertRaises(ValueError): self.arm()
        self.assertEqual(self.t.journal()['phase'],'pending')
        self.assertFalse(any('tailscaled.service' in c and 'stop' in c for c in self.h.calls))


if __name__ == '__main__': unittest.main()
