"""Real transaction methods/files, fake host commands only; no native acceptance."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.dont_write_bytecode = True
sys.path[:0] = [str(Path(__file__).resolve().parent), str(Path(__file__).resolve().parents[1])]
from native_test import FakeSystemctl
import native
import plan

class Fake(FakeSystemctl):
    def path(self, name):
        if str(name).startswith(str(self.root)): return Path(name)
        return super().path(name)
    def run(self, *args, timeout=120):
        if args[:2] == ('/usr/bin/systemctl', 'cat'): return self.cat
        if '--property=FragmentPath' in args: return self.tx.n['unit']
        if '--property=DropInPaths' in args or '--property=EnvironmentFiles' in args: return ''
        return super().run(*args, timeout=timeout)

class Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve();self.h = Fake(self.root)
        p = plan.read(Path(__file__).resolve().parents[1]/'plan.example.json')
        state='/var/lib/tailscale/tailscaled.state'
        p['native'] = dict(socket='/sock', daemon='/usr/sbin/tailscaled', cli='/usr/bin/tailscale',
            unit='/lib/systemd/system/tailscaled.service',dropins=[],stateFiles=[state],tailscaleIPs=['100.64.0.1'],
            environmentFilesShow='',minFreeBytes=64*1024**2,minAvailableMemoryBytes=64*1024**2,
            fallbackEvidence=str(self.root/'fallback.json'),predecessorEvidenceFile=str(self.root/'prev.json'))
        p['originalExecStart']='ExecStart=/usr/sbin/tailscaled --state='+state+' --socket=/sock'
        self.h.cat=p['originalExecStart']+'\n'
        p['native']['unitCatSHA256']=native.hashlib.sha256(self.h.cat.encode()).hexdigest()
        p['environmentFiles']=[]
        p['configuration']=str(self.root/'config.json')
        plan.atomic(p['configuration'],dict(schema_version=2,enabled=False))
        p['configurationSHA256']=plan.digest(p['configuration'])
        for name in [p['native'][k] for k in ('daemon','cli','unit')]+[state]:
            f=self.h.path(name);f.parent.mkdir(parents=True,exist_ok=True);f.write_text('original')
        p['backupFiles']={k:[state] for k in p['backupFiles']}
        for k in ('daemon','cli','unit'):p['backupFiles'][k]=[p['native'][k]]
        p['backupFiles']['config']=[p['configuration']]
        p['expectedBefore']={n:plan.digest(self.h.path(n)) for v in p['backupFiles'].values() for n in v}
        for name, data in {'/proc/42/cmdline':b'/usr/sbin/tailscaled\0--state='+state.encode()+b'\0--socket=/sock\0',
                           '/proc/meminfo':b'MemAvailable: 999999999 kB', '/var/lib/dpkg/lock':b'',
                           '/var/lib/dpkg/lock-frontend':b'', '/var/lib/apt/lists/lock':b''}.items():
            f=self.h.path(name);f.parent.mkdir(parents=True,exist_ok=True);f.write_bytes(data)
        release=self.root/'release';release.mkdir();files={}
        for name in ('tailscaled','tailscale','route-reconcile'):
            f=release/'linux-amd64'/name;f.parent.mkdir(exist_ok=True)
            f.write_bytes(b'\x7fELF\x02'+b'\0'*13+b'\x3e\x00'+name.encode());files[str(f.relative_to(release))]=plan.digest(f)
        plan.atomic(release/'manifest.json',dict(releaseID=p['releaseID'],repeatBuild='PASS',sourceDirty=False,schemaVersion=2,files=files))
        p['releaseDirectory']=str(release);p['releaseSHA256']=plan.digest(release/'manifest.json')
        p['oobEvidence']=str(self.root/'oob.json')
        plan.atomic(p['oobEvidence'],dict(kind='oob',passed=True,independent=True,rootRecovery=True,
            deploymentID=p['deploymentID'],host=p['host'],stableID=p['stableID'],releaseSHA256=p['releaseSHA256'],expiresUnix=9999999999))
        p['oobSHA256']=plan.digest(p['oobEvidence'])
        self.source=self.root/'plan.json';plan.atomic(self.source,p);plan.load(self.source)
        self.approval=self.root/'approval.json'
        plan.atomic(self.approval,dict(deploymentID=p['deploymentID'],host=p['host'],approvedPlanSHA256=plan.digest(self.source),
            expiresUnix=9999999999,serialWindowExclusive=True,excludePeers=p['excludePeers'],excludeDomains=p['excludeDomains'],rehearsal=True))
        self.t=native.Transaction(p,plan.digest(self.source),self.h);self.h.tx=self.t
        self.h.prefs['AutoUpdate']={'Check':p['autoUpdateCheck'],'Apply':p['autoUpdateApply']};self.h.held=p['aptHeld']
        self.t.root.mkdir(parents=True)
        # Fake ownership checks only: macOS tests are not Linux root/private-path acceptance.
        for target, kwargs in [(native,dict(private=lambda p: None)), (native.platform,dict(node=lambda:p['host'],machine=lambda:'x86_64'))]:
            ctx=patch.multiple(target,**kwargs);ctx.start();self.addCleanup(ctx.stop)
        ctx=patch.object(self.t,'rehearsal_destination',side_effect=self.destination);ctx.start();self.addCleanup(ctx.stop)
    def destination(self):
        out=Path(self.t.n['fallbackEvidence'])
        native.require(not out.exists() and not out.is_symlink(),'rehearsal output must be unused')
        return out
    def queue(self):
        with self.t.lock():self.t.rehearse(self.source,self.approval)
        self.assertEqual(self.t.journal()['phase'],'queued')
        self.assertTrue(any('rehearse-worker' in c for c in self.h.calls))
        for name in ('oob-evidence.json','approval.json','arm-evidence.txt','payload-evidence.json','readable/manifest.json'):
            self.assertTrue((self.t.d/name).exists(),name)
    def test_success_and_formal_evidence_binding(self):
        self.queue()
        with self.t.lock():self.t.execute('rehearse-worker')
        out=Path(self.t.n['fallbackEvidence']);e=plan.read(out)
        self.assertEqual(e['kind'],'state-downgrade-rehearsal');self.assertIs(e['passed'],True)
        self.assertEqual(e['rehearsalID'],self.t.p['deploymentID']);self.assertTrue(e['timestamp'])
        self.assertEqual(out.stat().st_mode&0o777,0o600)
        self.assertEqual(self.t.journal()['rollbackReason'],'operator')
        self.t.fallback_evidence(out)
        for key in ('host','stableID','releaseSHA256','oldDaemonSHA256','kind','passed'):
            bad=dict(e);bad[key]='wrong';plan.atomic(out,bad)
            with self.assertRaisesRegex(ValueError,'binding mismatch'):self.t.fallback_evidence(out)
        self.assertEqual(self.t.journal()['phase'],'rolled-back')
        self.assertFalse(self.t.drop.exists());self.assertTrue(self.t.guard.exists())
    def test_verify_failure_no_evidence(self):
        self.queue()
        original=self.h.run
        def fail(*args,**kw):
            if 'unified-policy' in args and 'status' in args:raise ValueError('verify failure')
            return original(*args,**kw)
        with patch.object(self.h,'run',side_effect=fail):
            with self.assertRaisesRegex(ValueError,'verify failure'):self.t.execute('rehearse-worker')
        self.assertEqual(self.t.journal()['phase'],'rolled-back')
        self.assertFalse(Path(self.t.n['fallbackEvidence']).exists())
        self.assertTrue((self.t.d/'oob-evidence.json').exists())
    def test_rollback_failure_no_evidence_and_no_bootstrap_replay(self):
        self.queue();original=self.h.run
        def fail(*args,**kw):
            if args[:3]==('/usr/bin/systemctl','start',native.UNIT) and not self.t.drop.exists():
                raise ValueError('old start failure')
            return original(*args,**kw)
        with patch.object(self.h,'run',side_effect=fail):
            with self.assertRaisesRegex(ValueError,'no prior fallback proof'):self.t.execute('rehearse-worker')
        self.assertFalse(Path(self.t.n['fallbackEvidence']).exists())
        self.assertTrue(self.t.guard.exists());self.assertTrue((self.t.d/'oob-evidence.json').exists())
        self.assertEqual(self.t.journal()['phase'],'rollback-failed')
    def test_missing_or_wrong_approval_oob_and_normal_no_bypass(self):
        a=plan.read(self.approval)
        for key,value in [('rehearsal',False),('approvedPlanSHA256','c'*64),('expiresUnix',0),('serialWindowExclusive',False),('excludePeers',[])]:
            bad=dict(a);bad[key]=value;plan.atomic(self.approval,bad)
            with self.assertRaises(ValueError):self.t.rehearse(self.source,self.approval)
            self.assertFalse(self.t.d.exists())
        a.pop('rehearsal');plan.atomic(self.approval,a)
        with self.assertRaises(FileNotFoundError):self.t.preflight(self.source,self.approval)
        a['rehearsal']=True;plan.atomic(self.approval,a)
        with self.assertRaisesRegex(ValueError,'cannot authorize deployment'):self.t.preflight(self.source,self.approval)
        oob=plan.read(self.t.p['oobEvidence']);oob['stableID']='wrong';plan.atomic(self.t.p['oobEvidence'],oob)
        self.t.p['oobSHA256']=plan.digest(self.t.p['oobEvidence'])
        with self.assertRaises(ValueError):self.t.rehearse(self.source,self.approval)
    def test_no_commit_or_split_switch_and_timeout_no_pass(self):
        self.queue()
        for action in ('commit','verify','switch-worker'):
            with self.assertRaises(ValueError):self.t.dispatch(action)
        self.h.mono+=901
        with self.assertRaisesRegex(ValueError,'deadline'):self.t.execute('rehearse-worker')
        self.t.rollback();self.assertFalse(Path(self.t.n['fallbackEvidence']).exists())
    def test_stage_reuse_is_exact_and_read_only(self):
        self.queue();self.t.execute('rehearse-worker');self.t.cleanup()
        before={f.name:f.read_bytes() for f in self.t.stage.iterdir()}
        self.t.stage_release()
        self.assertEqual(before,{f.name:f.read_bytes() for f in self.t.stage.iterdir()})
        (self.t.stage/'tailscaled').write_text('wrong')
        with self.assertRaisesRegex(ValueError,'existing stage differs'):self.t.stage_release()
    def test_fresh_formal_preflight_after_cleanup(self):
        self.queue();self.t.execute('rehearse-worker');self.t.cleanup()
        p=json.loads(json.dumps(self.t.p));p['deploymentID']='after-rehearsal'
        p['externalEvidence']=str(self.root/'formal-external.json')
        oob=plan.read(p['oobEvidence']);oob['deploymentID']=p['deploymentID']
        plan.atomic(p['oobEvidence'],oob);p['oobSHA256']=plan.digest(p['oobEvidence'])
        source=self.root/'formal-plan.json';plan.atomic(source,p);plan.load(source)
        a=plan.read(self.approval);a.pop('rehearsal');a['deploymentID']=p['deploymentID']
        a['approvedPlanSHA256']=plan.digest(source);plan.atomic(self.approval,a)
        fresh=native.Transaction(p,plan.digest(source),self.h);self.h.tx=fresh
        with fresh.lock():
            fresh.execute('preflight',source,self.approval)
            fresh.dispatch('backup');fresh.dispatch('stage')
        self.assertFalse(fresh.journal()['rehearsal'])
        self.assertTrue((fresh.d/'fallback-evidence.json').exists())
        with fresh.lock():
            for phase in ('arm', 'switch', 'switch-worker', 'verify'):
                fresh.dispatch(phase)
            plan.atomic(p['externalEvidence'], dict(kind='external-e2e', passed=True,
                deploymentID=p['deploymentID'], stableID=p['stableID'], host=p['host'],
                releaseSHA256=p['releaseSHA256'], configurationSHA256=p['configurationSHA256'],
                generation=1, expiresUnix=9999999999, deadlineUnix=fresh.journal()['wallDeadline']))
            fresh.acceptance_hash=plan.digest(p['externalEvidence'])
            fresh.dispatch('commit')
        self.assertEqual(fresh.journal()['phase'], 'committed')
        plan.all_off_config(plan.read(fresh.stage/'policy.json'))


    def test_all_off_backup_arm_and_output_failures(self):
        config=Path(self.t.p['configuration'])
        plan.atomic(config,dict(schema_version=2,enabled=False,app_connector_ttl={'enabled':True}))
        self.t.p['configurationSHA256']=plan.digest(config)
        self.t.p['expectedBefore'][str(config)]=plan.digest(config)
        with self.assertRaisesRegex(ValueError,'module must be off'):
            self.t.rehearse(self.source,self.approval)
        self.assertFalse(self.t.d.exists())
        # Restore the exact reviewed configuration, then fail arm readback.
        plan.atomic(config,dict(schema_version=2,enabled=False))
        self.t.p['configurationSHA256']=plan.digest(config)
        self.t.p['expectedBefore'][str(config)]=plan.digest(config)
        self.h.fail='is-active'
        with self.assertRaises(ValueError):self.t.execute('rehearse',self.source,self.approval)
        self.assertFalse(Path(self.t.n['fallbackEvidence']).exists())
        self.assertFalse(any('rehearse-worker' in c for c in self.h.calls))
        self.assertTrue((self.t.d/'readable/manifest.json').exists())

    def test_publication_journal_failure_removes_passed_output(self):
        self.queue();original=self.t.write
        def fail(phase,**extra):
            if 'rehearsalEvidenceSHA256' in extra:raise OSError('journal full')
            return original(phase,**extra)
        with patch.object(self.t,'write',side_effect=fail):
            with self.assertRaises(OSError):self.t.execute('rehearse-worker')
        self.assertFalse(Path(self.t.n['fallbackEvidence']).exists())
        self.assertEqual(self.t.journal()['phase'],'rolled-back')
        self.assertTrue((self.t.d/'oob-evidence.json').exists())

    def test_existing_output_never_replaced(self):
        out=Path(self.t.n['fallbackEvidence']);out.write_text('existing')
        with self.assertRaisesRegex(ValueError,'unused'):self.t.rehearse(self.source,self.approval)
        self.assertEqual(out.read_text(),'existing');self.assertFalse(self.t.d.exists())

    def test_shell_requires_opt_in_and_bindings(self):
        deploy=Path(__file__).resolve().parents[1]
        args=['--plan',str(self.source),'--deployment-id',self.t.p['deploymentID'],'--host',self.t.p['host'],
              '--stable-id',self.t.p['stableID'],'--release-sha256',self.t.p['releaseSHA256'],
              '--approved-plan-sha256',self.t.approved]
        for script,extra,ok in [('rehearse.sh',[],False),('preflight.sh',['--rehearsal'],False),
                                ('rehearse.sh',['--rehearsal'],True),('rehearse.sh',['--rehearsal','--host','wrong'],False)]:
            result=subprocess.run(['bash',str(deploy/script),*args,*extra],capture_output=True)
            self.assertEqual(result.returncode==0,ok,result.stderr)
        self.assertFalse(self.t.d.exists())

if __name__=='__main__':unittest.main()
