import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('bundle',ROOT/'bundle.py')
b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)

def fixture(root):
    names=['release-ready','source/patched-source.tar','source/patch-head.txt','source/PATCH.diff',
           'source/modules.json','config/schema.json','config/schema-v2.json','config/idcfast.json','config/residential.json',
           'TEST-REPORT.md','RELEASE-NOTES.md','evidence-index.json','deploy/plan.py','deploy/native.py']
    names += ['linux-amd64/'+x for x in ('tailscaled','tailscale','route-reconcile')]
    names += ['source/'+x for x in ('base.txt','series','unified.patch','wireguard-base.txt','UPSTREAM.sha256','LICENSE')]
    names += ['linux-amd64/'+x+'.buildinfo' for x in ('tailscaled','tailscale','route-reconcile')]
    data={n:b'fixture' for n in names};data['source/patch-head.txt']=b'a'*40+b'\n'
    data['config/schema.json'] = data['config/schema-v2.json'] = (ROOT.parent/'featurepolicy/schema-v2.json').read_bytes()
    files={n:b.sha(v) for n,v in data.items()}
    m=dict(sourceDirty=False,repeatBuild='PASS',patchHEAD='a'*40,releaseID='1.102.3-unified.u1-'+'a'*40,
           files=files,moduleManifestSHA256=files['source/modules.json'],wireguardPatchSHA256=files['source/PATCH.diff'])
    m.update(upstreamTag='v1.102.3', tagObject='fixture', peeledCommit='fixture', wireguardBase='fixture',
             go='go1.26.6', toolchainTreeSHA256='b'*64, CGO_ENABLED='0', GOOS='linux', GOAMD64='v1',
             GOARM64='v8.0', architectures=['amd64'], tags=[], ldflags='fixture', trimpath=True,
             buildvcs=False, schemaVersion=2, officialHashComparison='NOT_CLAIMED',
             stateCompatibility='I-B1_REQUIRED', buildTimeUTC='fixture')
    data['manifest.json']=json.dumps(m).encode()
    sums={n:b.sha(v) for n,v in data.items()}
    data['SHA256SUMS']=''.join(f'{v}  {k}\n' for k,v in sorted(sums.items())).encode()
    for n,v in data.items():
        p=root/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(v)
    return data

class Tests(unittest.TestCase):
    def test_determinism_verify_and_damage(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);data=fixture(root);raw=b.archive(b.directory(root))
            for p in root.rglob('*'):
                if p.is_file():p.chmod(0o600)
            self.assertEqual(raw,b.archive(b.directory(root)))
            tar=root.parent/(root.name+'.tar')
            try:
                tar.write_bytes(raw);self.assertEqual(b.verify(tar),b.sha(raw))
                tar.write_bytes(raw+b'bad')
                with self.assertRaises(ValueError):b.verify(tar)
            finally:tar.unlink()
            (root/'linux-amd64/tailscaled').write_bytes(b'bad')
            with self.assertRaises(ValueError):b.directory(root)
    def test_unsafe_members_and_duplicate(self):
        import io
        import tarfile
        for name in ('../escape','/absolute','safe'):
            with tempfile.TemporaryDirectory() as d:
                path=Path(d)/'bad.tar'
                with tarfile.open(path,'w') as tar:
                    item=tarfile.TarInfo(name);item.size=1
                    tar.addfile(item,io.BytesIO(b'x'))
                    tar.addfile(item,io.BytesIO(b'x'))
                with self.assertRaises(ValueError):b.verify(path)
    def test_dirty_incomplete_extra_symlink(self):
        for case in ('dirty','missing','extra','symlink'):
            with self.subTest(case=case),tempfile.TemporaryDirectory() as d:
                root=Path(d);fixture(root)
                if case=='dirty':
                    m=json.loads((root/'manifest.json').read_text());m['sourceDirty']=True
                    (root/'manifest.json').write_text(json.dumps(m))
                if case=='missing':(root/'linux-amd64/tailscale').unlink()
                if case=='extra':(root/'extra').write_text('x')
                if case=='symlink':(root/'extra').symlink_to(root/'manifest.json')
                with self.assertRaises((ValueError,KeyError)):b.directory(root)
if __name__=='__main__':unittest.main()
