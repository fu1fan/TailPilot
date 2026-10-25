#!/usr/bin/env python3
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('labplan',ROOT/'plan.py'); model=importlib.util.module_from_spec(spec); spec.loader.exec_module(model)
class Tests(unittest.TestCase):
 def run_script(self,name,*args):
  return subprocess.run(['bash',str(ROOT/(name+'.sh')),*args],capture_output=True,text=True)
 def test_usage_and_no_execute(self):
  for name in ['create-topology','run-case','collect','destroy-topology']:
   self.assertEqual(self.run_script(name,'--help').returncode,0)
   for args in [('--execute',),('--unknown',),('--run-id',)]: self.assertNotEqual(self.run_script(name,*args).returncode,0)
 def test_unique_scope_and_reverse_cleanup(self):
  a=json.loads(self.run_script('create-topology').stdout); b=json.loads(self.run_script('create-topology').stdout)
  self.assertNotEqual(a['runID'],b['runID'])
  self.assertEqual(len(a['resources']),11)
  with tempfile.TemporaryDirectory() as d:
   f=Path(d)/'inventory.json';f.write_text(json.dumps(a));args=['--run-id',a['runID'],'--inventory',str(f)]
   r=self.run_script('destroy-topology',*args); self.assertEqual(json.loads(r.stdout)['reverseDeletionPlan'],[])
   for resource in a['resources'][:4]: resource['created']=True
   f.write_text(json.dumps(a));r=self.run_script('destroy-topology',*args)
   self.assertEqual(json.loads(r.stdout)['reverseDeletionPlan'],list(reversed(a['resources'][:4])))
   a['resources'][0]['name']='unowned';f.write_text(json.dumps(a))
   self.assertNotEqual(self.run_script('destroy-topology',*args).returncode,0)
 def test_every_matrix_case_both_connectors(self):
  a=json.loads(self.run_script('create-topology').stdout)
  with tempfile.TemporaryDirectory() as d:
   f=Path(d)/'inventory.json'; f.write_text(json.dumps(a));args=['--run-id',a['runID'],'--inventory',str(f)]
   for case in model.CASES:
    for connector in ['R','I']:
     for version in ['1.102.3','1.104.1']:
      r=self.run_script('run-case',*args,'--case',case,'--connector',connector,'--client-version',version)
      self.assertEqual(r.returncode,0,r.stderr);self.assertEqual(json.loads(r.stdout)['result'],'NOT_RUN')
   self.assertNotEqual(self.run_script('run-case',*args,'--case','I-P999','--connector','R','--client-version','1.102.3').returncode,0)
   self.assertEqual(self.run_script('collect',*args).returncode,0)
if __name__=='__main__':unittest.main()
