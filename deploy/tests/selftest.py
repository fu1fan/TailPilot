#!/usr/bin/env python3
"""Offline tests only. No backend, credentials, services or network."""
import concurrent.futures
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('plan',ROOT/'plan.py')
plan=importlib.util.module_from_spec(spec); spec.loader.exec_module(plan)

def fixture():
    categories=['daemon','cli','unit','dropins','config','prefs','state','routeinfo','ledger','routes','control','updates']
    return dict(deploymentID='dev-fixture-001',host='isolated-dev',stableID='fixtureStableID',
        releaseID='1.102.3-unified.u1-fixture',releaseDirectory='/fixture/release',releaseSHA256='a'*64,
        deadlineSeconds=900,oobEvidence='/fixture/oob.json',oobSHA256='b'*64,
        externalEvidence='/fixture/e2e.json',externalSHA256='c'*64,
        backupFiles={k:['/fixture/'+k] for k in categories},
        expectedBefore={'/fixture/'+k:'ABSENT' for k in categories},
        originalExecStart='ExecStart=/usr/sbin/tailscaled --state=/var/lib/tailscale/tailscaled.state --socket=/run/tailscale/tailscaled.sock --port=$PORT $FLAGS',
        environmentFiles=['/fixture/defaults'],configuration='/fixture/config.json',configurationSHA256='d'*64,
        excludePeers=['management-fixture','codex-fixture'],excludeDomains=['management.example.invalid','codex.example.invalid'],
        cohort='first',predecessorEvidence='',autoUpdateCheck=True,autoUpdateApply=True,aptHeld=False)

class Tests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name); self.p=fixture(); self.p['expectedBefore']['/fixture/defaults']='ABSENT'
        self.file=self.root/'plan.json'; self.save(); self.txn=self.root/'txn'; self.txn.mkdir()
    def save(self): self.file.write_text(json.dumps(self.p,sort_keys=True)+'\n')
    def command(self,*args):
        return subprocess.run(['python3',str(ROOT/'plan.py'),*map(str,args)],capture_output=True,text=True)
    def phase(self,phase): return self.command('journal',self.file,self.txn,phase)
    def advance(self):
        for p in ['preflight','backup','stage','armed','switching','switched','verified']:
            self.assertEqual(self.phase(p).returncode,0,p)
    def argv(self):
        return ['--plan',str(self.file),'--deployment-id',self.p['deploymentID'],'--host',self.p['host'],
          '--stable-id',self.p['stableID'],'--release-sha256',self.p['releaseSHA256'],
          '--approved-plan-sha256',plan.digest(self.file)]
    def shell(self,name,args):
        return subprocess.run(['bash',str(ROOT/(name+'.sh')),*args],capture_output=True,text=True)
    def test_all_scripts_usage_dry_run_and_bindings(self):
        for name in ['preflight','backup','stage','arm','switch','verify','commit','rollback','cleanup']:
            self.assertEqual(self.shell(name,['--help']).returncode,0)
            r=self.shell(name,self.argv()); self.assertEqual(r.returncode,0,r.stderr)
            d=json.loads(r.stdout); self.assertFalse(d['executable']); self.assertEqual(d['phase'],name)
            self.assertNotEqual(self.shell(name,['--execute',*self.argv()]).returncode,0)
            for args in [[],['--unknown'],['--host'],self.argv()+['--host','duplicate'],
                         ['--dry-run','--execute',*self.argv()]]:
                self.assertNotEqual(self.shell(name,args).returncode,0)
        self.assertEqual(list(self.txn.iterdir()),[])
    def test_rollback_argv_and_boot(self):
        r=self.shell('arm',self.argv()); argv=json.loads(r.stdout)['rollbackArgv'][1:]
        argv[argv.index('--plan')+1]=str(self.file)
        self.assertEqual(self.shell('rollback',argv).returncode,0)
        self.assertEqual(self.shell('rollback',argv+['--boot-recovery']).returncode,0)
        self.assertNotEqual(self.shell('switch',self.argv()+['--boot-recovery']).returncode,0)
    def test_invalid_hash_and_identity(self):
        for key in ['--host','--stable-id','--release-sha256','--approved-plan-sha256','--deployment-id']:
            args=self.argv(); args[args.index(key)+1]='0'*64
            self.assertNotEqual(self.shell('switch',args).returncode,0)
    def test_installed_policy_schema(self):
        import shutil
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            shutil.copyfile(ROOT/'plan.py', root/'plan.py')
            shutil.copyfile(ROOT.parent/'featurepolicy/schema-v2.json', root/'schema-v2.json')
            spec = importlib.util.spec_from_file_location('installed_plan', root/'plan.py')
            installed = importlib.util.module_from_spec(spec); spec.loader.exec_module(installed)
            installed.all_off_config({'schema_version': 2, 'enabled': False})
            (root/'schema-v2.json').unlink()
            with self.assertRaises(FileNotFoundError):
                installed.all_off_config({'schema_version': 2, 'enabled': False})

    def test_v2_all_off_strict(self):
        import copy
        good = {'schema_version': 2, 'enabled': False, 'app_connector_ttl': {'enabled': False}}
        plan.all_off_config(good)
        self.assertEqual((ROOT.parent/'featurepolicy/schema-v2.json').read_bytes(),
                         (ROOT.parent/'release/config/schema.json').read_bytes())
        for name in ('idcfast', 'residential'):
            plan.all_off_config(plan.read(ROOT.parent/'release/config'/ (name+'.json')))
        for change in ({'schema_version': 1}, {'schema_version': True}, {'lease': {}},
                       {'app_connector_ttl': {'enabled': True}}, {'app_connector_ttl': None},
                       {'app_connector_ttl': {'batch_size': True}},
                       {'app_connector_ttl': {'batch_size': 0}},
                       {'app_connector_ttl': {'unknown': False}},
                       {'unknown': False}, {'path_policy': {'rules': [{}]}},
                       {'dns_ipv4_only': {'targets': ['example.test']}}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                plan.all_off_config(dict(copy.deepcopy(good), **change))

    def test_strict_parser(self):
        self.p['unexpected']='secret-canary'; self.save()
        r=self.command('validate',self.file); self.assertNotEqual(r.returncode,0)
        self.assertNotIn('secret-canary',r.stderr+r.stdout)
        self.file.write_text('{"host":"a","host":"b"}')
        self.assertNotEqual(self.command('validate',self.file).returncode,0)
    def test_before_conflict_and_backup_permissions(self):
        self.p['expectedBefore']={}
        for category in self.p['backupFiles']:
            f=self.root/category; f.write_text('fixture-only')
            self.p['backupFiles'][category]=[str(f)]; self.p['expectedBefore'][str(f)]=plan.digest(f)
        self.p['environmentFiles']=[]; self.save()
        dest=self.root/'backup'
        r=self.command('backup',self.file,dest); self.assertEqual(r.returncode,0,r.stderr)
        self.assertEqual(dest.stat().st_mode & 0o777,0o700)
        for f in dest.iterdir(): self.assertEqual(f.stat().st_mode & 0o777,0o600)
        (self.root/'state').write_text('changed')
        self.assertNotEqual(self.command('before',self.file).returncode,0)
    def test_deadline_and_idempotence(self):
        self.assertNotEqual(self.phase('committed').returncode,0)
        self.advance(); jf=self.txn/'journal.json'; old=plan.read(jf)
        self.assertNotEqual(self.phase('armed').returncode,0)  # no renewal
        old['deadline']=1; plan.atomic(jf,old)
        self.assertNotEqual(self.phase('committed').returncode,0)
        self.assertEqual(self.phase('rolling-back').returncode,0)
        self.assertEqual(self.phase('rolled-back').returncode,0)
        before=jf.read_bytes(); self.assertEqual(self.phase('rolling-back').returncode,0)
        self.assertEqual(before,jf.read_bytes())
    def test_commit_rollback_race(self):
        self.advance()
        with concurrent.futures.ThreadPoolExecutor(2) as pool:
            list(pool.map(self.phase,['committed','rolling-back']))
        p=plan.read(self.txn/'journal.json')['phase']
        self.assertIn(p,['committed','rolling-back'])
        if p=='rolling-back': self.assertNotEqual(self.phase('committed').returncode,0)
        else:
            self.assertEqual(self.phase('rolling-back').returncode,0)
            self.assertEqual(plan.read(self.txn/'journal.json')['phase'],'committed')
    def test_dropin_preserves_arguments(self):
        r=self.command('dropin',self.file); self.assertEqual(r.returncode,0)
        self.assertIn(self.p['originalExecStart'].split(' ',1)[1],r.stdout)
        self.assertTrue(r.stdout.startswith('[Service]\nExecStart=\n'))
    def test_evidence_expiry(self):
        f=self.root/'evidence'; e=dict(deploymentID=self.p['deploymentID'],stableID=self.p['stableID'],
          releaseSHA256=self.p['releaseSHA256'],kind='oob',passed=True,independent=True,rootRecovery=True,expiresUnix=int(time.time())+60)
        f.write_text(json.dumps(e)); plan.evidence(f,plan.digest(f),self.p,'oob')
        e['expiresUnix']=1; f.write_text(json.dumps(e))
        with self.assertRaises(ValueError): plan.evidence(f,plan.digest(f),self.p,'oob')

if __name__=='__main__': unittest.main()
