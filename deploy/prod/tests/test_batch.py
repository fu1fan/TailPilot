"""Offline only. Every host command is intercepted; fixture IDs are fictional."""
import ast
import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import batch as b
import probe


class BatchTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.clock = patch.object(b.time, 'time', return_value=1000)
        self.clock.start(); self.addCleanup(self.clock.stop)
        self.guard = patch.object(b, 'run', side_effect=AssertionError('unexpected host command'))
        self.run = self.guard.start(); self.addCleanup(self.guard.stop)
        self.stdout = contextlib.redirect_stdout(io.StringIO())
        self.stdout.__enter__(); self.addCleanup(self.stdout.__exit__, None, None, None)
        self.p = b.plan.read(ROOT.parent / 'plan.example.json')
        self.p['native'] = b.plan.read(ROOT.parent / 'native-contract.example.json')
        self.p.update(host='fixture-host', stableID='fixtureStable', releaseSHA256='a'*64)
        self.target = dict(machine='idcfast', host=self.p['host'], stableID=self.p['stableID'],
                           oobHost='192.0.2.10', releaseSHA256='a'*64)
        self.tf = self.save('target', self.target)
        self.oob = {k:self.p[k] for k in ('deploymentID','host','stableID','releaseSHA256')}
        self.oob.update(kind='oob', passed=True, independent=True, rootRecovery=True, expiresUnix=2000)
        self.p['oobEvidence'] = str(self.save('oob', self.oob))
        self.p['oobSHA256'] = b.sha(self.p['oobEvidence'])
        self.pf = self.save('plan', self.p)
        self.common = ['--target', str(self.tf), '--plan', str(self.pf), '--plan-sha256', b.sha(self.pf),
                       '--release-sha256', 'a'*64, '--oob-sha256', self.p['oobSHA256']]
        self.proof = dict(approvedPlanSHA256=b.sha(self.pf), deploymentID=self.p['deploymentID'],
                          host=self.p['host'], expiresUnix=2000, serialWindowExclusive=True,
                          targetSHA256=b.sha(self.tf), prodActions=['10-alloff:start'],
                          releaseSHA256='a'*64, oobSHA256=self.p['oobSHA256'],
                          excludePeers=self.p['excludePeers'], excludeDomains=self.p['excludeDomains'],
                          windowStartUnix=900, windowEndUnix=2000)
        self.af = self.save('approval', self.proof)

    def save(self, name, obj):
        path = self.root/name
        path.write_text(json.dumps(obj)); path.chmod(0o600)
        return path

    def args(self, batch='10-alloff', action='start', extra=()):
        return b.parser().parse_args([batch, '--action', action, *self.common, *extra])

    def test_default_all_batches_offline(self):
        for batch in b.ACTIONS:
            b.main([batch])
        self.run.assert_not_called()

    def test_all_actions_dry_run_never_host(self):
        for batch, actions in b.ACTIONS.items():
            if batch == '00-readonly': continue
            for action in actions:
                if action in ('review','config'): continue
                b.main([batch, '--action', action, *self.common])
        self.run.assert_not_called()

    def test_parameters_rejected_before_host(self):
        cases = [ ['10-alloff','--execute'], ['10-alloff','--action','invalid'],
                  ['10-alloff','--execute','--dry-run'], ['10-alloff','--adopt-all'],
                  ['10-alloff','--action','start','--action=start'],
                  ['00-readonly','--action','probe','--dry-run','--connect-readonly'],
                  ['20-takeover','--action','reset','--dry-run','--observe-local'] ]
        for argv in cases:
            with self.subTest(argv=argv), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises((ValueError,SystemExit)): b.main(argv)
        self.run.assert_not_called()

    def test_target_required_and_residential_rejected(self):
        with self.assertRaises(ValueError): b.main(['10-alloff','--action','start'])
        for key, value in [('machine','residential'),('oobHost','host;touch /tmp/no'),('releaseSHA256','b'*64)]:
            self.save('target',dict(self.target, **{key:value}))
            with self.subTest(key=key), self.assertRaises(ValueError):
                b.main(['10-alloff','--action','start',*self.common])
        self.run.assert_not_called()

    def test_real_plan_binding_and_tamper(self):
        a = self.args(); b.load_target(a)
        self.assertEqual(b.bindings(a), self.p)
        for key, value in [('host','residential'),('stableID','wrong'),('releaseSHA256','b'*64),('cohort','second')]:
            self.save('plan',dict(self.p,**{key:value})); a.plan_sha256 = b.sha(self.pf)
            with self.subTest(key=key), self.assertRaises(ValueError): b.bindings(a)
        self.save('plan',self.p); a.plan_sha256='0'*64
        with self.assertRaises(ValueError): b.bindings(a)

    def test_approval_matrix(self):
        a=self.args(extra=['--approval',str(self.af)]); b.load_target(a)
        with patch.object(b,'private'):
            self.assertEqual(b.authorize(a,self.p),self.proof)
            negatives = dict(approvedPlanSHA256='0'*64, host='other', expiresUnix=999,
                serialWindowExclusive=False, targetSHA256='0'*64, prodActions=[],
                releaseSHA256='0'*64, oobSHA256='0'*64, excludePeers=[], excludeDomains=[],
                windowStartUnix=1001, windowEndUnix=999)
            for key,value in negatives.items():
                self.save('approval',dict(self.proof,**{key:value}))
                with self.subTest(key=key), self.assertRaises(ValueError): b.authorize(a,self.p)
        self.run.assert_not_called()

    def test_execute_missing_approval_no_host(self):
        with self.assertRaisesRegex(ValueError,'approval required'):
            b.main(['10-alloff','--action','start',*self.common,'--execute'])
        self.run.assert_not_called()

    def test_config_default_and_explicit_write(self):
        out=self.root/'candidate'
        b.main(['20-takeover','--action','config','--output',str(out)])
        b.main(['20-takeover','--action','config','--dry-run','--write-output','--output',str(out)])
        self.assertFalse(out.exists())
        b.main(['20-takeover','--action','config','--write-output','--output',str(out)])
        self.assertEqual(out.stat().st_mode & 0o777,0o600)
        self.assertTrue(json.loads(out.read_text())['app_connector_ttl']['enabled'])
        with self.assertRaises(FileExistsError): b.write_new(out,{})
        link=self.root/'link';link.symlink_to(out)
        with self.assertRaises(FileExistsError): b.write_new(link,{})
        with self.assertRaises(ValueError): b.sha(link)
        self.run.assert_not_called()

    def test_config_rejects_v1_and_other_modules(self):
        for c in [dict(schema_version=1, enabled=True),
                  dict(schema_version=2,machine='idcfast',enabled=True,
                       app_connector_ttl={'enabled':True},auto_ipv6={'enabled':True})]:
            f=self.save('candidate-input',c)
            with self.assertRaises(ValueError):
                b.main(['20-takeover','--action','config','--configuration',str(f)])

    def test_start_serial_order_stop_on_failure_and_rehearsal_flag(self):
        self.run.side_effect=None; self.run.return_value=''
        a=self.args(extra=['--approval',str(self.af)])
        b.alloff(a,self.p)
        self.assertEqual([Path(c.args[0][1]).stem for c in self.run.call_args_list],
                         ['preflight','backup','stage','arm','switch'])
        self.run.reset_mock();self.run.side_effect=['',ValueError('injected')]
        with self.assertRaises(ValueError): b.alloff(a,self.p)
        self.assertEqual(self.run.call_count,2)
        self.assertIn('--rehearsal', b.native_args(a,self.p,'rehearse'))
        with self.assertRaises(ValueError): b.native_args(a,self.p,'commit')

    def route_fixture(self, action='adopt'):
        ref=dict(AssignedRoot='example.invalid',Domain='www.example.invalid',IP='192.0.2.2')
        claims=self.save('claims',[ref])
        a=self.args('20-takeover',action,['--source','ticket','--execute','--expect-sha256','b'*64,
                  '--expect-generation','4','--expect-source-id','8'])
        if action=='adopt': a.claims=str(claims)
        v=dict(Source='ticket', SnapshotHash='b'*64,Fence={'Generation':4},SourceID=8,
               Entries=[dict(Reference=ref,Eligible=True)])
        proof={'takeover':dict(source='ticket',hash='b'*64,generation=4,sourceID=8,
                              manifestSHA256=None,claimsSHA256=b.sha(claims) if a.claims else None)}
        self.run.side_effect=None;self.run.return_value=json.dumps({'clear_preview':v})
        return a,v,proof

    def test_takeover_exact_selection_and_reset_rollback(self):
        for action,flag in [('adopt','--execute'),('reset','--execute'),('reset-rollback','--rollback')]:
            a,v,proof=self.route_fixture(action); self.run.reset_mock()
            with patch.object(b,'private'): b.takeover(a,self.p,proof)
            calls=[c.args[0] for c in self.run.call_args_list]
            self.assertEqual(len(calls),2);self.assertNotIn(flag,calls[0]);self.assertIn(flag,calls[1])
            self.assertNotIn('--adopt-all',calls[1])

    def test_takeover_stale_cas_or_empty_ineligible_duplicate_claims_no_write(self):
        for case in ('hash','generation','sourceID','approval','empty','ineligible','duplicate','absent'):
            a,v,proof=self.route_fixture();self.run.reset_mock()
            if case=='hash':a.expect_sha256='c'*64
            if case=='generation':a.expect_generation=5
            if case=='sourceID':a.expect_source_id=9
            if case=='approval':proof['takeover']['hash']='c'*64
            if case in ('empty','ineligible','duplicate'):
                ref=v['Entries'][0]['Reference']
                value=[] if case=='empty' else ([dict(ref,IP='192.0.2.9')] if case=='ineligible' else [ref,ref])
                self.save('claims',value);proof['takeover']['claimsSHA256']=b.sha(a.claims)
            if case=='absent':a.claims=None;proof['takeover']['claimsSHA256']=None
            with self.subTest(case=case), patch.object(b,'private'), self.assertRaises(ValueError):
                b.takeover(a,self.p,proof)
            self.assertEqual(self.run.call_count,1)

    def test_preview_only_and_reset_wrong_arguments(self):
        a,v,proof=self.route_fixture();a.execute=False
        b.takeover(a,self.p);self.assertEqual(self.run.call_count,1)
        a.action='reset'
        with self.assertRaises(ValueError):b.preview(a,self.p)

    def evidence(self):
        e={k:self.p[k] for k in ('deploymentID','host','stableID','releaseSHA256','configurationSHA256')}
        e.update(kind='external-e2e',passed=True,expiresUnix=1200,observedUnix=999,deadlineUnix=1100,generation=4,
                 checks={k:dict(passed=True,observer='external-fixture',evidenceSHA256='c'*64,measurement='fixture') for k in b.CHECKS})
        e['checks']['routeCounts']['counts']=dict(advertisedBefore=810,advertisedAfter=810,enabledBefore=50,enabledAfter=50)
        return e

    def test_acceptance_fresh_complete_no_unexplained_delta(self):
        j=dict(phase='verified',wallDeadline=1100);e=self.evidence()
        b.acceptance(e,self.p,j,4)
        for key,value in [('host','wrong'),('generation',5),('expiresUnix',999),('observedUnix',1001),('passed',False),('deadlineUnix',1101)]:
            with self.subTest(key=key),self.assertRaises(ValueError):b.acceptance(dict(e,**{key:value}),self.p,j,4)
        for case in ('missing','failed','delta','hash','expired-journal','committed'):
            bad=copy.deepcopy(e);journal=copy.deepcopy(j)
            if case=='missing':del bad['checks']['dns']
            if case=='failed':bad['checks']['dns']['passed']=False
            if case=='delta':bad['checks']['routeCounts']['counts']['enabledAfter']=49
            if case=='hash':bad['checks']['dns']['evidenceSHA256']='bad'
            if case=='expired-journal':journal['wallDeadline']=999
            if case=='committed':journal['phase']='committed'
            with self.subTest(case=case),self.assertRaises(ValueError):b.acceptance(bad,self.p,journal,4)

    def test_policy_requires_approval_before_host_access(self):
        for batch,action in [('20-takeover','enable'),('90-rollback','disable')]:
            with self.assertRaisesRegex(ValueError,'approval required'):
                b.main([batch,'--action',action,*self.common,'--execute'])
        self.run.assert_not_called()

    def test_committed_rollback_refuses_noop(self):
        with patch.object(b,'authorize',return_value=self.proof), patch.object(b.sys,'platform','linux'), \
             patch.object(b.os,'geteuid',return_value=0),patch.object(b.platform,'node',return_value='fixture-host'), \
             patch.object(b,'lock',return_value=contextlib.nullcontext()),patch.object(b,'journal',return_value={'phase':'committed'}):
            with self.assertRaisesRegex(ValueError,'native no-op'):
                b.main(['90-rollback','--action','release',*self.common,'--execute'])
        self.run.assert_not_called()

    def test_pending_rollback_allowed_when_daemon_down(self):
        self.run.side_effect=None;self.run.return_value=''
        with patch.object(b,'authorize',return_value=self.proof),patch.object(b.sys,'platform','linux'), \
             patch.object(b.os,'geteuid',return_value=0),patch.object(b.platform,'node',return_value='fixture-host'), \
             patch.object(b,'lock',return_value=contextlib.nullcontext()), \
             patch.object(b,'local_target',side_effect=AssertionError('must not probe failed daemon')), \
             patch.object(b,'journal',side_effect=[{'phase':'switched'},{'phase':'rolled-back'}]):
            b.main(['90-rollback','--action','release',*self.common,'--execute'])
        self.assertEqual(Path(self.run.call_args.args[0][1]).name,'rollback.sh')

    def test_probe_requires_explicit_opt_in(self):
        with self.assertRaises(ValueError):
            b.main(['00-readonly','--action','probe',*self.common])
        self.run.assert_not_called()

    def test_probe_ssh_argv_and_key_parameter_fake_only(self):
        self.run.side_effect=None
        self.run.return_value=json.dumps(dict(host='fixture-host',stableID='fixtureStable',allOff=True,
              backend='Running',service='active',finalReleaseInstalled=False))
        with patch.object(b,'release_check',return_value={'releaseID':'fixture','files':{'linux-amd64/tailscaled':'a'*64}}):
            b.main(['00-readonly','--action','probe',*self.common,'--connect-readonly','--oob-key','/fixture/key',
                    '--known-hosts','/fixture/known','--remote-cli','/fixture/cli','--socket','/fixture/sock',
                    '--release-dir','/fixture/release'])
        argv=self.run.call_args.args[0]
        self.assertIn('root@192.0.2.10',argv);self.assertIn('/fixture/key',argv)
        for option in ('StrictHostKeyChecking=yes','IdentityAgent=none','IdentitiesOnly=yes','ClearAllForwardings=yes'):
            self.assertIn(option,argv)

    def test_run_redacts_failure_and_environment(self):
        self.guard.stop()
        with patch.object(b.subprocess,'run',return_value=subprocess.CompletedProcess([],1,b'',b'SECRET')) as fake:
            with self.assertRaisesRegex(ValueError,'^command failed'): b.run(['/fixture/command'])
            self.assertNotIn('SSH_AUTH_SOCK',fake.call_args.kwargs['env'])
        self.guard.start()

    def test_fake_host_probe_and_incomplete_modules(self):
        exe=self.root/'proc/42/exe';exe.parent.mkdir(parents=True);exe.write_bytes(b'fake-daemon')
        calls=[]
        modules={k:False for k in ('app_connector_ttl','auto_ipv6','dns_ipv4_only','path_policy')}
        def command(*args):
            calls.append(args)
            if 'unified-policy' in args:
                return json.dumps(dict(applied=True,schemaValid=True,runtimeReady=True,enabledModules=modules))
            if 'status' in args:return json.dumps(dict(Self={'ID':'fixtureStable'},BackendState='Running'))
            if 'prefs' in args:return json.dumps(dict(AdvertiseRoutes=['192.0.2.0/24'],Secret='NEVER_OUTPUT'))
            if args[0].endswith('systemctl'):
                key=args[3].split('=')[1]
                return dict(MainPID='42',ActiveState='active',FragmentPath='/unit',DropInPaths='')[key]
            if args[0].endswith('ip'):return '[]'
            if args[0].endswith('apt-mark'):return 'tailscale'
            raise AssertionError(args)
        def fake_path(*parts):return self.root/str(Path(*parts)).lstrip('/')
        with patch.object(probe,'Path',side_effect=fake_path),patch.object(probe.platform,'node',return_value='fixture-host'):
            params=dict(cli='/fixture/cli',socket='/fixture/sock',releaseID='fixture',daemonSHA256='a'*64)
            result=probe.probe(params,command)
            self.assertTrue(result['allOff']);self.assertEqual(result['advertisedCount'],1)
            self.assertNotIn('NEVER_OUTPUT',json.dumps(result));self.assertFalse(result['finalReleaseInstalled'])
            del modules['path_policy']
            self.assertFalse(probe.probe(params,command)['allOff'])
        self.assertTrue(all('set' not in c and 'start' not in c for c in calls))

    def test_release_fixture_integrity_and_architecture(self):
        spec=importlib.util.spec_from_file_location('bundle_fixture', ROOT.parent.parent/'release/tests/bundle_test.py')
        fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)
        root=self.root/'release';root.mkdir();fixture.fixture(root)
        manifest=json.loads((root/'manifest.json').read_text())
        for name in ('tailscale','tailscaled','route-reconcile'):
            file=root/'linux-amd64'/name
            file.write_bytes(b'\x7fELF\x02'+bytes(13)+b'\x3e\x00'+bytes(20))
            manifest['files']['linux-amd64/'+name]=b.sha(file)
        (root/'manifest.json').write_text(json.dumps(manifest))
        sums={**manifest['files'],'manifest.json':b.sha(root/'manifest.json')}
        (root/'SHA256SUMS').write_text(''.join(f'{v}  {k}\n' for k,v in sorted(sums.items())))
        digest=b.sha(root/'manifest.json')
        self.assertEqual(b.release_check(root,digest)['schemaVersion'],2)
        with self.assertRaises(ValueError):b.release_check(root,'0'*64)
        (root/'linux-amd64/tailscale').write_bytes(b'changed')
        with self.assertRaises(ValueError):b.release_check(root,digest)
        self.run.assert_not_called()

    def test_local_target_rejects_wrong_identity(self):
        self.run.side_effect=None;self.run.return_value=json.dumps(dict(BackendState='Running',Self={'ID':'wrong'}))
        with patch.object(b.sys,'platform','linux'),patch.object(b.os,'geteuid',return_value=0), \
             patch.object(b.platform,'node',return_value=self.p['host']):
            with self.assertRaisesRegex(ValueError,'StableID'):b.local_target(self.p)


    def test_formal_planner_allows_rehearsal_stage_reuse(self):
        from types import SimpleNamespace
        inputs=self.save('inputs',{'release_dir':'/fixture/release'})
        output=self.root/'formal-plan'
        planner=SimpleNamespace(generate=lambda a:self.p,templates=lambda p:{'approval':{}})
        with patch.object(b.sys,'platform','linux'),patch.object(b.os,'geteuid',return_value=0), \
             patch.object(b.platform,'node',return_value=self.p['host']), \
             patch.object(b,'release_check'),patch.object(b,'module',return_value=planner), \
             patch.object(Path,'exists',return_value=True):
            b.main(['00-readonly','--action','plan',*self.common,'--observe-local','--write-output',
                    '--planner-inputs',str(inputs),'--output',str(output)])
        self.assertEqual(json.loads(output.read_text()),self.p)
        templates=json.loads(Path(str(output)+'.templates.json').read_text())
        self.assertEqual(templates['approval']['prodActions'],[])
        self.assertEqual(templates['approval']['targetSHA256'],b.sha(self.tf))
        self.run.assert_not_called()

    def test_batch_lock_nonblocking_exclusion(self):
        from types import SimpleNamespace
        real_open=os.open
        def fake_open(path,flags,mode):return real_open(self.root/'batch.lock',flags,mode)
        with patch.object(b.os,'open',side_effect=fake_open), \
             patch.object(b.os,'fstat',return_value=SimpleNamespace(st_uid=0)):
            with b.lock():
                with self.assertRaises(BlockingIOError):
                    with b.lock():self.fail('second batch entered')
            with b.lock():pass



class StaticTests(unittest.TestCase):
    def test_python_ast(self):
        for path in ROOT.rglob('*.py'): ast.parse(path.read_text(),filename=str(path))

    def test_bash_syntax_and_offline_wrappers(self):
        for name in b.ACTIONS:
            path=ROOT/name
            subprocess.run(['/bin/bash','-n',str(path)],check=True)
            r=subprocess.run(['/bin/bash',str(path)],capture_output=True,text=True,check=True)
            self.assertFalse(json.loads(r.stdout)['network'])
            self.assertEqual(json.loads(r.stdout)['mode'],'dry-run')

    def test_no_production_defaults_in_code(self):
        for path in list(ROOT.glob('*.py'))+[ROOT/name for name in b.ACTIONS]:
            text=path.read_text()
            self.assertNotIn('192.0.2.10',text);self.assertNotIn('192.0.2.20',text)
            self.assertNotIn('connector-a',text)


if __name__=='__main__': unittest.main(verbosity=2)
