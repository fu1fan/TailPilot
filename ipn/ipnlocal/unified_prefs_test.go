package ipnlocal

import (
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"sync/atomic"
	"tailscale.com/featurepolicy"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnauth"
	"tailscale.com/ipn/store/mem"
	"testing"
	"testing/synctest"
)

type unifiedFailStore struct {
	mem.Store
	fail bool
}

func TestUnifiedIdenticalCommittedPrefsDoNotRepublish(t *testing.T) {
	b := newTestLocalBackend(t)
	b.stopUnifiedPolicy()
	b.mu.Lock()
	defer b.mu.Unlock()
	var notifications int
	b.pm.StateChangeHook = func(_ ipn.LoginProfileView, _ ipn.PrefsView, _ bool) {
		notifications++
	}
	old := b.pm.CurrentPrefs()
	for range 3 {
		if got := b.installCommittedRoutePrefsLocked(old.AsStruct()); !got.Equals(old) {
			t.Fatal("identical commit changed prefs")
		}
	}
	if notifications != 0 {
		t.Fatalf("identical commits republished prefs %d times", notifications)
	}
	next := old.AsStruct()
	next.AdvertiseRoutes = append(next.AdvertiseRoutes, netip.MustParsePrefix("203.0.113.0/24"))
	b.installCommittedRoutePrefsLocked(next)
	if notifications != 1 || !slices.Contains(b.pm.CurrentPrefs().AdvertiseRoutes().AsSlice(), netip.MustParsePrefix("203.0.113.0/24")) {
		t.Fatal("changed committed routes were not published")
	}
}

func (s *unifiedFailStore) WriteState(k ipn.StateKey, b []byte) error {
	if s.fail {
		return errors.New("injected durable failure")
	}
	return s.Store.WriteState(k, b)
}

func TestUnifiedDurablePrefs(t *testing.T) {
	s := new(unifiedFailStore)
	old := ipn.NewPrefs()
	old.Hostname = "preserved"
	pm := &profileManager{store: s, logf: t.Logf, prefs: old.View(), currentProfile: (&ipn.LoginProfile{ID: "p", Key: "profile-p"}).View()}
	target := []netip.Prefix{netip.MustParsePrefix("192.0.2.1/32")}
	s.fail = true
	if _, err := pm.persistRouteCAS("p", nil, target); err == nil {
		t.Fatal("write failure lost")
	}
	if !pm.prefs.Equals(old.View()) {
		t.Fatal("failure changed memory")
	}
	s.fail = false
	next, err := pm.persistRouteCAS("p", nil, target)
	if err != nil {
		t.Fatal(err)
	}
	if !pm.prefs.Equals(old.View()) {
		t.Fatal("persistence published early")
	}
	if next.Hostname() != "preserved" || !slices.Contains(next.AdvertiseRoutes().AsSlice(), target[0]) {
		t.Fatal("bad durable prefs")
	}
	pm.prefs = next
	if _, err := pm.persistRouteCAS("p", nil, nil); err == nil {
		t.Fatal("stale CAS accepted")
	}
	if _, err := pm.persistRouteCAS("foreign", target, nil); err == nil {
		t.Fatal("foreign profile accepted")
	}
	raw, err := s.ReadState("profile-p")
	if err != nil {
		t.Fatal(err)
	}
	var saved ipn.Prefs
	if err := json.Unmarshal(raw, &saved); err != nil {
		t.Fatal(err)
	}
	if saved.Hostname != "preserved" || len(saved.AdvertiseRoutes) != 1 {
		t.Fatal("durable prefs mismatch")
	}
}

// This uses the actual backend installer and fake userspace engine. It requires
// the local socket permission available in Lead's non-sandbox test environment.
func TestUnifiedBackendDurableRoutes(t *testing.T) {
	b := newTestLocalBackend(t)
	b.stopUnifiedPolicy()
	s := new(unifiedFailStore)
	b.mu.Lock()
	b.pm.store = s
	b.pm.currentProfile = (&ipn.LoginProfile{ID: "p", Key: "profile-p"}).View()
	b.unifiedProfileID = "p"
	b.pm.prefs = ipn.NewPrefs().View()
	manager := featurepolicy.NewManager(UnifiedPolicyStore{Store: s, ProfileID: "p", ProfileKey: "profile-p"})
	_, err := manager.Start(featurepolicy.Inputs{ProfileID: "p"}, func() ([]byte, error) {
		return []byte(`{"schema_version":1,"enabled":true,"lease":{"enabled":true}}`), nil
	})
	if err != nil {
		b.mu.Unlock()
		t.Fatal(err)
	}
	b.unifiedSnapshot = manager.Current()
	b.unifiedPublishedRevision = b.unifiedRevision
	f := b.unifiedSnapshot.Fence()
	b.mu.Unlock()
	b.mu.Lock()
	s.fail = true
	b.mu.Unlock()
	routes := []netip.Prefix{netip.MustParsePrefix("192.0.2.10/32")}
	if err := b.applyUnifiedRoutes(f, nil, routes); err == nil {
		t.Fatal("failed store acknowledged")
	}
	b.mu.Lock()
	if b.pm.CurrentPrefs().AdvertiseRoutes().Len() != 0 {
		t.Fatal("failed write published")
	}
	s.fail = false
	b.mu.Unlock()
	if err := b.applyUnifiedRoutes(f, nil, routes); err != nil {
		t.Fatal(err)
	}
	b.mu.Lock()
	got := slices.Clone(b.pm.CurrentPrefs().AdvertiseRoutes().AsSlice())
	b.mu.Unlock()
	if !slices.Equal(got, routes) {
		t.Fatal("backend did not install durable routes")
	}
	if err := b.applyUnifiedRoutes(f, nil, nil); err == nil {
		t.Fatal("stale CAS accepted")
	}
}

func TestUnifiedDurableRoutesDisabled(t *testing.T) {
	s := featurepolicy.NewManager(nil).Current()
	b := &LocalBackend{unifiedSnapshot: s}
	if err := b.applyUnifiedRoutes(s.Fence(), nil, []netip.Prefix{netip.MustParsePrefix("192.0.2.1/32")}); err == nil {
		t.Fatal("default-off route write accepted")
	}
}

type unifiedBlockingStore struct {
	mem.Store
	block   atomic.Bool
	entered chan struct{}
	release chan struct{}
	fail    bool
}

func (s *unifiedBlockingStore) WriteState(k ipn.StateKey, data []byte) error {
	if k == "profile-p" && s.block.CompareAndSwap(true, false) {
		close(s.entered)
		<-s.release
		if s.fail {
			return errors.New("injected blocked write failure")
		}
	}
	return s.Store.WriteState(k, data)
}

func prepareUnifiedTransactionTest(t *testing.T, b *LocalBackend, fail bool) (*unifiedBlockingStore, featurepolicy.Fence) {
	t.Helper()
	s := &unifiedBlockingStore{entered: make(chan struct{}), release: make(chan struct{}), fail: fail}
	s.block.Store(true)
	m := featurepolicy.NewManager(UnifiedPolicyStore{Store: s, ProfileID: "p", ProfileKey: "profile-p"})
	if _, err := m.Start(featurepolicy.Inputs{ProfileID: "p"}, func() ([]byte, error) {
		return []byte(`{"schema_version":1,"enabled":true,"lease":{"enabled":true}}`), nil
	}); err != nil {
		t.Fatal(err)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.pm == nil {
		b.pm = &profileManager{logf: t.Logf}
	}
	b.pm.store = s
	b.store = s
	b.pm.currentProfile = (&ipn.LoginProfile{ID: "p", Key: "profile-p"}).View()
	b.pm.prefs = ipn.NewPrefs().View()
	b.unifiedSnapshot = m.Current()
	b.unifiedPublishedRevision = b.unifiedRevision
	return s, m.Current().Fence()
}

// This executes the actual route commit and EditPrefsAs validation on a backend
// without an engine. The forced persistence failure returns before data-plane
// installation. synctest proves writers are blocked, without sleep assertions.
func TestUnifiedPrefsTransactionFailure(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		b := &LocalBackend{logf: t.Logf}
		s, f := prepareUnifiedTransactionTest(t, b, true)
		routes := []netip.Prefix{netip.MustParsePrefix("192.0.2.42/32")}
		committed, edited := make(chan error, 1), make(chan error, 1)
		go func() { committed <- b.applyUnifiedRoutes(f, nil, routes) }()
		<-s.entered
		go func() {
			_, err := b.EditPrefsAs(&ipn.MaskedPrefs{HostnameSet: true, Prefs: ipn.Prefs{Hostname: "badhostname.tailscale."}}, ipnauth.Self)
			edited <- err
		}()
		synctest.Wait()
		select {
		case err := <-edited:
			t.Fatalf("EditPrefs passed in-flight transaction: %v", err)
		default:
		}
		// Read-only operations must not wait on disk, nor see prepared prefs.
		if b.Prefs().AdvertiseRoutes().Len() != 0 {
			t.Fatal("uncommitted routes exposed")
		}
		close(s.release)
		if err := <-committed; err == nil {
			t.Fatal("failed write acknowledged")
		}
		if err := <-edited; err == nil {
			t.Fatal("validation was bypassed")
		}
		if b.Prefs().AdvertiseRoutes().Len() != 0 || b.unifiedPrefsPending != nil {
			t.Fatal("failure published prefs or left barrier closed")
		}
	})
}

// Lead runs this with sockets. Both the writer and installer are real backend
// entry points; the store only controls I/O completion to expose stale snapshots.
func TestUnifiedBackendPrefsTransaction(t *testing.T) {
	b := newTestLocalBackend(t)
	b.stopUnifiedPolicy()
	s, f := prepareUnifiedTransactionTest(t, b, false)
	routes := []netip.Prefix{netip.MustParsePrefix("192.0.2.42/32")}
	committed, edited := make(chan error, 1), make(chan error, 1)
	go func() { committed <- b.applyUnifiedRoutes(f, nil, routes) }()
	<-s.entered
	go func() {
		_, err := b.EditPrefsAs(&ipn.MaskedPrefs{HostnameSet: true, Prefs: ipn.Prefs{Hostname: "external-edit"}}, ipnauth.Self)
		edited <- err
	}()
	if b.Prefs().AdvertiseRoutes().Len() != 0 {
		t.Fatal("uncommitted routes exposed")
	}
	close(s.release)
	if err := <-committed; err != nil {
		t.Fatal(err)
	}
	if err := <-edited; err != nil {
		t.Fatal(err)
	}
	p := b.Prefs()
	if p.Hostname() != "external-edit" || !slices.Equal(p.AdvertiseRoutes().AsSlice(), routes) {
		t.Fatal("concurrent edit lost committed routes or hostname")
	}
	raw, err := s.ReadState("profile-p")
	if err != nil {
		t.Fatal(err)
	}
	var durable ipn.Prefs
	if err := json.Unmarshal(raw, &durable); err != nil {
		t.Fatal(err)
	}
	if durable.Hostname != "external-edit" || !slices.Equal(durable.AdvertiseRoutes, routes) {
		t.Fatal("durable state lost concurrent edit")
	}
}
