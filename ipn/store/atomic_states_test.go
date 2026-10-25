package store

import (
	"os"
	"path/filepath"
	"tailscale.com/ipn"
	"testing"
)

func TestFileStoreAtomicStatesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state")
	st, e := New(t.Logf, path)
	if e != nil {
		t.Fatal(e)
	}
	s := st.(*FileStore)
	if e = s.WriteState("unrelated", []byte("keep")); e != nil {
		t.Fatal(e)
	}
	if e = s.WriteStates(map[ipn.StateKey][]byte{"lease": []byte("new"), "ledger": []byte("same transaction")}); e != nil {
		t.Fatal(e)
	}
	reopened, e := New(t.Logf, path)
	if e != nil {
		t.Fatal(e)
	}
	for k, want := range map[ipn.StateKey]string{"unrelated": "keep", "lease": "new", "ledger": "same transaction"} {
		got, e := reopened.ReadState(k)
		if e != nil || string(got) != want {
			t.Fatalf("%s %q %v", k, got, e)
		}
	}
	// A failed write must not publish a partial transaction in memory.
	original := s.path
	s.path = filepath.Join(path, "not-a-directory")
	if e = s.WriteStates(map[ipn.StateKey][]byte{"lease": []byte("bad"), "ledger": nil}); e == nil {
		t.Fatal("expected write error")
	}
	s.path = original
	got, _ := s.ReadState("lease")
	if string(got) != "new" {
		t.Fatal("failed write changed cache")
	}
	if _, e = os.Stat(path); e != nil {
		t.Fatal(e)
	}
}
