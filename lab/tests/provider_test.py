#!/usr/bin/env python3
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
RUN='lab-'+'a'*32


class Tests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)/RUN
    def invoke(self, action='create', *extra):
        return subprocess.run(['bash', str(ROOT/'provider_qemu.sh'),action,'--run-id',RUN,
            '--root',str(self.root),'--images',str(ROOT/'provider-images.example.json'),*extra],
            capture_output=True,text=True)
    def test_create_dry_run_no_writes(self):
        r=self.invoke();self.assertEqual(r.returncode,0,r.stderr)
        s=json.loads(r.stdout);self.assertEqual(len(s['resources']),10)
        self.assertFalse(self.root.exists())
        for r in s['resources']:
            self.assertFalse(r['created']);self.assertIn(RUN,r['name'])
            c=' '.join(r['command']);self.assertNotIn('iptables',c);self.assertNotIn('tap,',c)
        for r in s['resources'][1:]:
            c=' '.join(r['command'])
            self.assertIn('user,id=management,restrict=on',c);self.assertIn('vde,id=data',c)
    def test_reverse_owned_intent_cleanup(self):
        s=json.loads(self.invoke().stdout);self.root.mkdir()
        s['resources'][1]['created']=True;s['resources'][4]['intent']=True
        (self.root/'inventory.json').write_text(json.dumps(s))
        r=self.invoke('destroy');self.assertEqual(r.returncode,0,r.stderr)
        self.assertEqual([x['role'] for x in json.loads(r.stdout)['reverseDeletionPlan']],['C2','R'])
        self.assertTrue((self.root/'inventory.json').exists())
    def test_inventory_tamper_refused(self):
        s=json.loads(self.invoke().stdout);self.root.mkdir()
        s['resources'][1]['files']=['/etc/passwd']
        (self.root/'inventory.json').write_text(json.dumps(s))
        self.assertNotEqual(self.invoke('destroy').returncode,0)
    def test_bad_scope_port_and_mode(self):
        for args in [('--run-id','foreign'),('--management-port','80'),('--execute','--dry-run')]:
            self.assertNotEqual(self.invoke('create',*args).returncode,0)
        self.assertFalse(self.root.exists())


if __name__=='__main__':unittest.main()
