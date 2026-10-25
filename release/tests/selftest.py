#!/usr/bin/env python3
import hashlib
import json
import os
import shutil
from pathlib import Path
import subprocess
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[1]
class Tests(unittest.TestCase):
 def test_parser_rejects_incomplete_or_unknown(self):
  for args in [[],['--go'],['--execute'],['--unknown'],['--expect-head','$(touch /tmp/not-executed)']]:
   r=subprocess.run(['bash',str(ROOT/'build-release.sh'),*args],capture_output=True,text=True)
   self.assertNotEqual(r.returncode,0)
  self.assertEqual(subprocess.run(['bash',str(ROOT/'build-release.sh'),'--help'],capture_output=True).returncode,0)
 def test_prepare_parser(self):
  for args in [[], ['--go'], ['--proxy', 'direct'], ['--unknown']]:
   r=subprocess.run(['bash', str(ROOT/'prepare-modcache.sh'), *args], capture_output=True)
   self.assertNotEqual(r.returncode, 0)
  self.assertEqual(subprocess.run(['bash', str(ROOT/'prepare-modcache.sh'), '--help'], capture_output=True).returncode, 0)
 def test_cache_preflight_stages(self):
  # A command-protocol fixture, not evidence that real modules were downloaded.
  with tempfile.TemporaryDirectory() as d:
   p=Path(d); go=p/'go'; log=p/'calls'
   go.write_text('#!/usr/bin/env bash\necho "$GOARCH $*" >> "$CALLS"\n[[ "$*" != "$FAIL_ARGS" ]]\n')
   go.chmod(0o700)
   command='source "$1"; check_release_modcache "$2" true'
   for fail in ['', 'list -mod=readonly -m -json all', 'list -mod=readonly -deps ./cmd/tailscaled ./cmd/tailscale ./cmd/route-reconcile', 'mod verify']:
    log.write_text('')
    env=dict(os.environ, CALLS=str(log), FAIL_ARGS=fail, GOARCH='amd64')
    r=subprocess.run(['bash','-c',command,'test',str(ROOT/'check-modcache.sh'),str(go)],env=env,capture_output=True,text=True)
    self.assertEqual(r.returncode == 0, not fail, r.stderr)
    calls=log.read_text()
    if not fail:
     self.assertIn('arm64 list -mod=readonly -deps',calls)
     self.assertIn('mod verify',calls)
    elif fail.startswith('list'):
     self.assertIn('prepare-modcache.sh',r.stderr)
     self.assertNotIn('mod verify',calls)
 def test_prepare_isolates_download_sums(self):
  # Stub Go validates script isolation/environment, not network provenance.
  with tempfile.TemporaryDirectory() as d:
   p=Path(d); repo=p/'source'; repo.mkdir(); rel=repo/'release'; rel.mkdir()
   for name in ['prepare-modcache.sh','check-modcache.sh']:
    shutil.copy(ROOT/name,rel/name)
   (rel/'toolchain-hash.py').write_text('print("b" * 64)')
   (repo/'go.mod').write_text('module fixture\n')
   (repo/'go.sum').write_text('original\n')
   for args in [['init','-q'],['add','.'],['-c','user.name=Fixture','-c','user.email=fixture@example.invalid','commit','-qm','fixture']]:
    subprocess.run(['git',*args],cwd=repo,check=True,capture_output=True)
   head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=repo,text=True).strip()
   bindir=p/'toolchain/bin'; bindir.mkdir(parents=True); go=bindir/'go'; log=p/'calls'
   go.write_text("""#!/usr/bin/env bash
set -eu
printf '%s:%s:%s:%s\\n' "$PWD" "${GOPROXY:-}" "${GOSUMDB:-}" "$*" >> "$CALLS"
case "$*" in
 'env GOVERSION') echo go1.26.6;;
 'env GOMODCACHE') echo "$CACHE";;
 'mod download all') echo added >> go.sum;;
 'list -mod=readonly -m -json all') [[ "${FAIL_CHECK:-}" != yes ]];;
esac
""")
   go.chmod(0o700)
   for fail in ['', 'yes']:
    log.write_text('')
    env=dict(os.environ,CALLS=str(log),CACHE=str(p/'cache'),FAIL_CHECK=fail)
    r=subprocess.run(['bash',str(rel/'prepare-modcache.sh'),'--go',str(go),'--expect-head',head,'--toolchain-sha256','b'*64,'--proxy','https://proxy.example.invalid','--arm64'],cwd=repo,env=env,capture_output=True,text=True)
    self.assertEqual(r.returncode == 0, not fail, r.stderr)
    self.assertEqual((repo/'go.sum').read_text(),'original\n')
    self.assertEqual(subprocess.check_output(['git','status','--porcelain'],cwd=repo),b'')
    calls=log.read_text()
    self.assertIn(':https://proxy.example.invalid:sum.golang.org:mod download all',calls)
    self.assertIn(str(repo)+':off:off:list -mod=readonly -m -json all',calls)
 def test_manifest_hashes_and_unverified_claims(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d);(p/'source').mkdir();(p/'source/PATCH.diff').write_text('fixture');(p/'source/modules.json').write_text('[]')
   r=subprocess.run(['python3',str(ROOT/'manifest.py'),d,'a'*40,'b'*64,'fixture-flags','true'],capture_output=True,text=True)
   self.assertEqual(r.returncode,0,r.stderr);m=json.loads((p/'manifest.json').read_text())
   self.assertEqual(m['patchHEAD'],'a'*40);self.assertIn('arm64-build-only',m['architectures'])
   self.assertEqual(m['officialHashComparison'],'NOT_CLAIMED');self.assertEqual(m['stateCompatibility'],'I-B1_REQUIRED')
   for line in (p/'SHA256SUMS').read_text().splitlines():
    digest,name=line.split('  ',1);self.assertEqual(digest,hashlib.sha256((p/name).read_bytes()).hexdigest())
 def test_toolchain_hash_content_and_path_sensitive(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d);(p/'a').write_text('one')
   def h():return subprocess.check_output(['python3',str(ROOT/'toolchain-hash.py'),d],text=True)
   first=h();(p/'a').write_text('two');self.assertNotEqual(first,h())
   second=h();(p/'a').rename(p/'b');self.assertNotEqual(second,h())
if __name__=='__main__':unittest.main()
