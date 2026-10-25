#!/usr/bin/env python3
"""Generate test-only Go overlay; never edits production or existing test sources."""
import json
from pathlib import Path
import sys
root = Path(__file__).resolve().parents[2]
out = Path(sys.argv[1]).resolve()
out.mkdir(parents=True, exist_ok=False)
src = root/'ipn/ipnlocal/unified_takeover_daemon_test.go'
s = src.read_text()
a = 'func (s *connectorDaemonStore) WriteState(k ipn.StateKey, v []byte) error {\n'
b = '\tif fail {\n\t\treturn fmt.Errorf("injected power cut after write")'
assert s.count(a)==1 and s.count(b)==1
s=s.replace(a,a+'\tr26StoreHook(s, false)\n').replace(b,'\tr26StoreHook(s, true)\n'+b)
(out/'daemon_test.go').write_text(s)
(out/'power_test.go').write_text((root/'lab/appc-e2e/power_test.go.txt').read_text())
(out/'cli810_seed_test.go').write_text((root/'lab/appc-e2e/cli810-seed-test.go.txt').read_text())
(out/'overlay.json').write_text(json.dumps({'Replace':{str(src):str(out/'daemon_test.go'),str(root/'ipn/ipnlocal/r26_process_test.go'):str(out/'power_test.go'),str(root/'ipn/ipnlocal/r29_seed_test.go'):str(out/'cli810_seed_test.go')}}))
print(out/'overlay.json')
