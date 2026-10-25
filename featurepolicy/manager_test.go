package featurepolicy

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"testing"
)

type memoryStore struct {
	data map[string][]byte
	fail bool
}

func (s *memoryStore) Load(p string) ([]byte, error) {
	b, ok := s.data[p]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return b, nil
}
func (s *memoryStore) Save(p string, b []byte) error {
	if s.fail {
		return errors.New("disk full")
	}
	if s.data == nil {
		s.data = map[string][]byte{}
	}
	s.data[p] = append([]byte(nil), b...)
	return nil
}

func TestManagerTransactions(t *testing.T) {
	store := &memoryStore{}
	reject := false
	m := NewManager(store, func(s *PolicySnapshot) error {
		if reject {
			return errors.New("stage")
		}
		return nil
	})
	b := []byte(`{"schema_version":1}`)
	if _, e := m.Start(Inputs{ProfileID: "one"}, func() ([]byte, error) { return b, nil }); e != nil {
		t.Fatal(e)
	}
	first := m.Current()
	next := []byte(`{"schema_version":1,"enabled":true}`)
	for _, failure := range []string{"stage", "disk", "cas", "invalid"} {
		reject = failure == "stage"
		store.fail = failure == "disk"
		g := first.Fence().Generation
		data := next
		if failure == "cas" {
			g++
		}
		if failure == "invalid" {
			data = []byte(`{"schema_version":1,"enabled":true,"bogus":0}`)
		}
		if e := m.Reload(data, g, hash(data)); e == nil {
			t.Fatalf("%s accepted", failure)
		}
		if m.Current() != first {
			t.Fatalf("%s published", failure)
		}
	}
	reject = false
	store.fail = false
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 1000 {
				s := m.Current()
				_ = s.Config()
				_ = s.Fence()
			}
		})
	}
	if e := m.Reload(next, first.Fence().Generation, hash(next)); e != nil {
		t.Fatal(e)
	}
	wg.Wait()
	if !m.Current().Enabled() || m.CurrentFence(first.Fence()) {
		t.Fatal("publication/fence")
	}
	c := m.Current().Config()
	c.Enabled = false
	if !m.Current().Enabled() {
		t.Fatal("mutable snapshot")
	}
	// Corrupt runtime input retains LKG; a new manager recovers the same policy.
	m2 := NewManager(store)
	warning, e := m2.Start(Inputs{ProfileID: "one"}, func() ([]byte, error) { return nil, errors.New("partial file") })
	if e != nil || warning == "" || !m2.Current().Enabled() {
		t.Fatalf("LKG: %v %v", warning, e)
	}
	if m2.Current().Fence().Generation <= m.Current().Fence().Generation {
		t.Fatal("generation regressed")
	}
	if e = m2.Recompile(Inputs{ProfileID: "other"}); e == nil {
		t.Fatal("cross-profile accepted")
	}
}

func TestStartupAndHash(t *testing.T) {
	m := NewManager(&memoryStore{})
	if _, e := m.Start(Inputs{}, func() ([]byte, error) { return []byte("{"), nil }); e == nil {
		t.Fatal("first invalid file accepted")
	}
	if _, e := m.Start(Inputs{}, func() ([]byte, error) { return nil, fs.ErrNotExist }); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(t.TempDir(), "policy")
	a := []byte(`{"schema_version":1,"machine":"a"}`)
	b := []byte(`{"schema_version":1,"machine":"b"}`)
	if e := os.WriteFile(path, a, 0600); e != nil {
		t.Fatal(e)
	}
	st, _ := os.Stat(path)
	read := func() ([]byte, error) { return os.ReadFile(path) }
	if _, e := m.Start(Inputs{}, read); e != nil {
		t.Fatal(e)
	}
	g := m.Current().Fence().Generation
	if e := os.WriteFile(path, b, 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.Chtimes(path, st.ModTime(), st.ModTime()); e != nil {
		t.Fatal(e)
	}
	data, _ := read()
	if e := m.Reload(data, g, hash(data)); e != nil {
		t.Fatal(e)
	}
	if m.Current().Config().Machine != "b" {
		t.Fatal("same mtime update missed")
	}
	// Production trust checks reject relative paths, symlinks, and writable parents.
	if _, e := ReadFile("relative.json"); e == nil {
		t.Fatal("relative accepted")
	}
	link := filepath.Join(t.TempDir(), "link")
	if e := os.Symlink(path, link); e != nil {
		t.Fatal(e)
	}
	if _, e := ReadFile(link); e == nil {
		t.Fatal("symlink accepted")
	}
	if _, e := ReadFile(path); e == nil {
		t.Fatal("non-root/writable-parent fixture accepted")
	}
}

func TestIdentityRotationAndScope(t *testing.T) {
	b := []byte(`{"schema_version":1,"enabled":true,"path_policy":{"enabled":true,"rules":[{"id":"first","stable_ids":["n1"],"allow":{"direct":false,"peer_relay":false,"derp":true},"prefer":["derp"]},{"id":"second","stable_ids":["n1","pending"],"allow":{"direct":true,"peer_relay":false,"derp":false},"prefer":["direct"]}]}}`)
	c, e := Parse(b)
	if e != nil {
		t.Fatal(e)
	}
	old := key.NewNode().Public()
	fresh := key.NewNode().Public()
	disco := key.NewDisco().Public()
	in := Inputs{ProfileID: "p", PeerIdentityEpoch: 1, Peers: []tailcfg.NodeView{(&tailcfg.Node{StableID: "n1", Key: old, DiscoKey: disco}).View()}}
	s, e := compile(c, in, 1)
	if e != nil {
		t.Fatal(e)
	}
	v, ok := s.NodeIdentity(old)
	if !ok || v.RuleID != "first" {
		t.Fatal("first match")
	}
	in.PeerIdentityEpoch++
	in.Peers = []tailcfg.NodeView{(&tailcfg.Node{StableID: "n1", Key: fresh}).View()}
	s, e = compile(c, in, 2)
	if e != nil {
		t.Fatal(e)
	}
	if _, ok = s.NodeIdentity(old); ok {
		t.Fatal("old key authorized")
	}
	if _, ok = s.DiscoIdentity(disco); ok {
		t.Fatal("old disco authorized")
	}
	if _, ok = s.NodeIdentity(fresh); !ok {
		t.Fatal("rotation lost rule")
	}
	in.Peers = []tailcfg.NodeView{(&tailcfg.Node{StableID: "new-registration", Key: fresh}).View()}
	s, e = compile(c, in, 3)
	if e != nil {
		t.Fatal(e)
	}
	if _, ok = s.NodeIdentity(fresh); ok {
		t.Fatal("new identity inherited")
	}
	c.Enabled = false
	s, e = compile(c, in, 4)
	if e != nil {
		t.Fatal(e)
	}
	if _, ok = s.NodeIdentity(fresh); ok || s.OwnershipEnabled() {
		t.Fatal("default off")
	}
	c, e = Parse([]byte(`{"schema_version":1,"enabled":true,"dns_ipv4_only":{"enabled":true,"targets":["*.example.com"]}}`))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = compile(c, Inputs{}, 1); e == nil {
		t.Fatal("unassigned DNS activated")
	}
	s, e = compile(c, Inputs{AssignedDomains: []string{"*.example.com"}}, 1)
	if e != nil {
		t.Fatal(e)
	}
	if s.DNSMatches("example.com") || s.DNSMatches("evil-example.com") || !s.DNSMatches("A.example.com.") {
		t.Fatal("domain boundary")
	}
}

func TestStartupCheckRejectsInvalidSource(t *testing.T) {
	if err := CheckStartup(nil, "", func() ([]byte, error) { return []byte(`bad`), nil }); err == nil {
		t.Fatal("bad first file accepted")
	}
	if err := CheckStartup(nil, "", func() ([]byte, error) { return nil, fs.ErrNotExist }); err != nil {
		t.Fatal(err)
	}
}
