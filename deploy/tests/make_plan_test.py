import argparse
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT.parent/'release/tests')]
from bundle_test import fixture
spec=importlib.util.spec_from_file_location('make_plan',ROOT/'make-plan.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class Fake(m.Host):
    def __init__(self,root):self.root=root;self.drift=False;self.calls=0;self.layout=False
    def path(self,name):
        if name.startswith(str(self.root)):return Path(name)
        return self.root/name.lstrip('/')
    def hostname(self):return 'fixture-host'
    def machine(self):return 'x86_64'
    def run(self,*args):
        self.calls+=1
        if args[0].endswith('systemctl'):
            if args[1]=='cat':return 'ExecStart=/usr/sbin/tailscaled --state=/state --socket=/sock\n' if not self.layout else 'ExecStart=/other\n'
            return {'FragmentPath':'/unit','DropInPaths':'/drop','EnvironmentFiles':'/defaults (ignore_errors=yes)','MainPID':'1'}[args[3].split('=')[1]]
        if args[0].endswith('apt-mark'):return ''
        if args[-1]=='--json':return json.dumps({'BackendState':'Running','Self':{'ID':'changed' if self.drift and self.calls>10 else 'stable','TailscaleIPs':['100.64.0.1']}})
        return json.dumps({'AutoUpdate':{'Check':True,'Apply':True}})

class Tests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);self.h=Fake(self.root)
        release=self.root/'release';release.mkdir();fixture(release)
        for name in ('usr/sbin/tailscaled','usr/bin/tailscale','unit','drop','defaults','state','proc/1/cmdline','snapshot'):
            p=self.root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text('opaque secret marker')
        (self.root/'proc/1/cmdline').write_bytes(b'/usr/sbin/tailscaled\0--state=/state\0--socket=/sock\0')
        for name,value in [('config',{'schema_version':2,'enabled':False}),('peers',['management']),('domains',['example.invalid']),('oob',{}),('inventory',{k:['/snapshot'] for k in ('prefs','routeinfo','ledger','routes','control','updates')})]:
            (self.root/name).write_text(json.dumps(value))
        self.a=argparse.Namespace(release_dir=str(release),configuration=str(self.root/'config'),deployment_id='fixture',host=None,
             exclusions_peers=str(self.root/'peers'),exclusions_domains=str(self.root/'domains'),oob_evidence=str(self.root/'oob'),
             output=str(self.root/'plan.json'),fallback_evidence=None,external_evidence=None,deadline_seconds=900,
             backup_inventory=str(self.root/'inventory'),dry_run=False)
    def tearDown(self):self.tmp.cleanup()
    def test_validator_layouts_and_explicit_missing(self):
        self.assertEqual(m.bundle_path(), ROOT.parent/'release/bundle.py')
        with patch.object(m, '__file__', str(self.root/'pkg/deploy/make-plan.py')):
            with self.assertRaisesRegex(ValueError, 'bundle.py missing'): m.bundle_path()
            tool=self.root/'pkg/tools/bundle.py';tool.parent.mkdir(parents=True)
            tool.write_text((ROOT.parent/'release/bundle.py').read_text())
            self.assertEqual(m.bundle_path(), tool.resolve())
            self.assertEqual(m.generate(self.a,self.h)['stableID'], 'stable')
            with self.assertRaises(ValueError): m.bundle_path(self.root/'missing')
            self.assertEqual(m.bundle_path(tool),tool)

    def test_packaged_dry_run_manifest(self):
        import shutil
        import subprocess
        release=Path(self.a.release_dir)
        for name in ('deploy/make-plan.py','deploy/plan.py','tools/bundle.py'):
            source=ROOT.parent/name if not name.startswith('tools/') else ROOT.parent/'release/bundle.py'
            dest=release/name;dest.parent.mkdir(exist_ok=True);shutil.copyfile(source,dest)
        (release/'manifest.json').unlink();(release/'SHA256SUMS').unlink()
        subprocess.run([sys.executable,str(ROOT.parent/'release/manifest.py'),str(release),'a'*40,'b'*64,'fixture','false'],check=True)
        spec=importlib.util.spec_from_file_location('packaged_planner',release/'deploy/make-plan.py')
        packaged=importlib.util.module_from_spec(spec);spec.loader.exec_module(packaged)
        argv=['make-plan','--dry-run']
        for k,v in vars(self.a).items():
            if v is not None and k!='dry_run':argv+=['--'+k.replace('_','-'),str(v)]
        with patch.object(sys,'argv',argv),patch.object(packaged,'Host',return_value=self.h),patch('builtins.print'):
            packaged.main()
        self.assertFalse(Path(self.a.output).exists())
        (release/'tools/bundle.py').write_text('# tampered')
        with self.assertRaisesRegex(ValueError,'hash mismatch'): m.generate(self.a,self.h)

    def test_second_cohort_requires_first_host_evidence(self):
        self.a.cohort='second'
        self.a.predecessor_evidence=None
        with self.assertRaisesRegex(ValueError,'first-host terminal stability evidence'):
            m.generate(self.a,self.h)
        evidence=self.root/'first-host.json'
        evidence.write_text(json.dumps({'phase':'committed','stable':True,'host':'other-host'}))
        self.a.predecessor_evidence=str(evidence)
        p=m.generate(self.a,self.h)
        self.assertEqual(p['cohort'],'second')
        self.assertEqual(p['predecessorEvidence'],m.filehash(evidence))
        self.assertEqual(p['native']['predecessorEvidenceFile'],str(evidence))
        # First cohort must not silently accept second-host evidence.
        self.a.cohort='first'
        self.a.predecessor_evidence=str(evidence)
        with self.assertRaisesRegex(ValueError,'reserved for the second cohort'):
            m.generate(self.a,self.h)

    def test_normal_templates_and_no_writes(self):
        files=set(self.root.rglob('*'));p=m.generate(self.a,self.h)
        self.assertEqual(set(self.root.rglob('*')),files)
        self.assertIsNone(p['externalSHA256']);m.plan.validate(p)
        t=m.templates(p);self.assertIsNone(t['oob']['passed']);self.assertIsNone(t['approval']['approvedPlanSHA256'])
        self.assertNotIn('opaque secret marker',json.dumps(p))
    def test_missing_category_file_drift_layout(self):
        self.a.backup_inventory=None
        with self.assertRaisesRegex(ValueError,'missing backup categories'):m.generate(self.a,self.h)
        self.a.backup_inventory=str(self.root/'inventory')
        self.h.calls=0;self.h.drift=True
        with self.assertRaisesRegex(ValueError,'changed'):m.generate(self.a,self.h)
        self.h.drift=False;self.h.layout=True
        with self.assertRaisesRegex(ValueError,'unsupported'):m.generate(self.a,self.h)
        self.h.layout=False;(self.root/'state').unlink()
        with self.assertRaises(ValueError):m.generate(self.a,self.h)
    def test_rejects_v1_release_with_v2_policy(self):
        from bundle_test import b
        release=Path(self.a.release_dir)
        manifest=json.loads((release/'manifest.json').read_text())
        manifest['schemaVersion']=1
        (release/'manifest.json').write_text(json.dumps(manifest))
        sums={str(p.relative_to(release)):b.sha(p.read_bytes()) for p in release.rglob('*')
              if p.is_file() and p.name!='SHA256SUMS'}
        (release/'SHA256SUMS').write_text(''.join(f'{v}  {k}\n' for k,v in sorted(sums.items())))
        with self.assertRaisesRegex(ValueError, 'v2 release'): m.generate(self.a,self.h)

    def test_config_exclusions_and_missing_optional_evidence(self):
        for config in ({'schema_version':2,'enabled':True},
                       {'schema_version':2,'enabled':False,'app_connector_ttl':{'enabled':True}},
                       {'schema_version':2,'enabled':False,'path_policy':{'rules':[{}]}}):
            (self.root/'config').write_text(json.dumps(config))
            with self.assertRaises(ValueError):m.generate(self.a,self.h)
        (self.root/'config').write_text('{"schema_version":2,"enabled":false}')
        (self.root/'peers').write_text('[]')
        with self.assertRaises(ValueError):m.generate(self.a,self.h)
        (self.root/'peers').write_text('["management"]')
        self.a.external_evidence=str(self.root/'missing')
        with self.assertRaises(ValueError):m.generate(self.a,self.h)
    def test_file_change_and_symlink_refused(self):
        original=self.h.run
        count=0
        def changing(*args):
            nonlocal count
            count+=1
            if count==12:(self.root/'state').write_text('changed state')
            return original(*args)
        with patch.object(self.h,'run',side_effect=changing):
            with self.assertRaisesRegex(ValueError,'changed'):m.generate(self.a,self.h)
        (self.root/'state').unlink();(self.root/'state').symlink_to(self.root/'snapshot')
        with self.assertRaises(ValueError):m.generate(self.a,self.h)
    def test_output_permissions_and_dry_run(self):
        argv=['make-plan']
        for k,v in vars(self.a).items():
            if v is not None and k!='dry_run':argv+=['--'+k.replace('_','-'),str(v)]
        with patch.object(sys,'argv',argv+['--dry-run']),patch.object(m,'Host',return_value=self.h),patch('builtins.print'):
            m.main()
        self.assertFalse(Path(self.a.output).exists())
        with patch.object(sys,'argv',argv),patch.object(m,'Host',return_value=self.h),patch('builtins.print'):
            m.main()
            self.assertEqual(os.stat(self.a.output).st_mode & 0o777,0o600)
            with self.assertRaises(FileExistsError):m.main()
if __name__=='__main__':unittest.main()
