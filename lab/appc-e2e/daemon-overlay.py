#!/usr/bin/env python3
"""Instrument real FileStore calls in a separate test-only tailscaled binary."""
import json
from pathlib import Path
import sys
root = Path(__file__).resolve().parents[2]
out = Path(sys.argv[1]).resolve()
out.mkdir(parents=True, exist_ok=False)
src = root/'ipn/store/stores.go'
s = src.read_text()
a = 'func (s *FileStore) WriteState(id ipn.StateKey, bs []byte) error {\n\ts.mu.Lock()\n\tdefer s.mu.Unlock()'
assert s.count(a) == 1
s = s.replace(a, a.replace('error {', '(writeErr error) {')+'\n r33Before(string(id), bs)\n defer func() { r33After(writeErr == nil) }()')
(out/'stores.go').write_text(s)
(out/'r33.go').write_text('''package store
import (
 "bytes"
 "encoding/json"
 "os"
 "path/filepath"
 "strings"
 "sync"
 "time"
)
// Only linked by lab overlay. Real FileStore atomic writes remain unchanged.
var r33 struct { sync.Mutex; active bool; count int; dir string; cut int; after bool; key string }
func r33Before(key string, data []byte) {
 r33.Lock()
 dir := os.Getenv("R33_BARRIER_DIR")
 if dir == "" { return }
 if !r33.active {
  raw, err := os.ReadFile(filepath.Join(dir,"arm.json")); if err != nil { return }
  var arm struct { Cut int; After bool }; if json.Unmarshal(raw,&arm)!=nil { panic("bad arm") }
  if !strings.HasSuffix(key,"||_appConnectorTTLV2") || !bytes.Contains(data,[]byte(`"Action":"reset"`)) || !bytes.Contains(data,[]byte(`"Complete":false`)) { return }
  r33.active=true; r33.count=0; r33.dir=dir; r33.cut=arm.Cut; r33.after=arm.After
  if err:=os.Remove(filepath.Join(dir,"arm.json")); err!=nil { panic(err) }
 }
 r33.count++; r33.key=key
 r33Mark(false)
}
func r33After(ok bool) { defer r33.Unlock(); if r33.active && ok { r33Mark(true) } }
func r33Mark(after bool) {
 b,_:=json.Marshal(map[string]any{"write":r33.count,"after":after,"key":r33.key,"pid":os.Getpid()})
 f,e:=os.OpenFile(filepath.Join(r33.dir,"trace.jsonl"),os.O_CREATE|os.O_WRONLY|os.O_APPEND,0600); if e!=nil { panic(e) }; f.Write(append(b,'\\n')); f.Sync(); f.Close()
 if r33.count==r33.cut && after==r33.after {
  if e:=os.WriteFile(filepath.Join(r33.dir,"reached.json"),b,0600); e!=nil {panic(e)}
  for { time.Sleep(time.Hour) } // external runner sends SIGKILL; no synthetic state
 }
 if after && r33.count==6 { r33.active=false }
}
''')
(out/'overlay.json').write_text(json.dumps({'Replace':{str(src):str(out/'stores.go'),str(root/'ipn/store/r33_barrier.go'):str(out/'r33.go')}}))
print(out/'overlay.json')
