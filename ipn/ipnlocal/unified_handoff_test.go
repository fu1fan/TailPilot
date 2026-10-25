package ipnlocal

import (
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"tailscale.com/featurepolicy"
	"tailscale.com/ipn"
	"tailscale.com/types/appctype"
)

func TestUnifiedCompatibilityExclusiveOnly(t *testing.T) {
	auto, shared, unknown := prefix("192.0.2.1/32"), prefix("192.0.2.2/32"), prefix("192.0.2.3/32")
	owners := map[netip.Prefix]PrefixOwners{
		auto:    {CreatedByModule: true, Auto: map[string]bool{"dns/example.test/example.test/192.0.2.1": true}},
		shared:  {CreatedByModule: true, Manual: true, Auto: map[string]bool{"dns/example.test/example.test/192.0.2.2": true}},
		unknown: {LegacyUnknown: true, Auto: map[string]bool{"dns/example.test/example.test/192.0.2.3": true}},
	}
	ri := compatibilityRouteInfo(owners, []netip.Prefix{auto, shared, unknown}, []string{"example.test"}, nil, nil)
	if !slices.Equal(ri.Domains["example.test"], []netip.Addr{auto.Addr()}) {
		t.Fatal("handoff exported shared/unknown", ri)
	}
	if len(compatibilityRouteInfo(owners, []netip.Prefix{auto}, nil, nil, nil).Domains) != 0 {
		t.Fatal("revoked domain exported")
	}
}

func TestUnifiedHandoffBackendPreservesPrefs(t *testing.T) {
	for _, point := range []string{"none", "route-before", "route-after", "complete-before", "complete-after"} {
		t.Run(point, func(t *testing.T) { testUnifiedHandoffRecovery(t, point) })
	}
}
func testUnifiedHandoffRecovery(t *testing.T, point string) {
	b := &LocalBackend{logf: t.Logf}
	store, _ := prepareUnifiedTransactionTest(t, b, false)
	store.block.Store(false)
	m := featurepolicy.NewManager(UnifiedPolicyStore{Store: store, ProfileID: "p", ProfileKey: "profile-p"})
	if _, err := m.Start(featurepolicy.Inputs{ProfileID: "p"}, func() ([]byte, error) { return []byte(`{"schema_version":1}`), nil }); err != nil {
		t.Fatal(err)
	}
	b.unifiedSnapshot = m.Current()
	failing := &handoffWriteFailure{StateStore: store, point: point}
	b.pm.store = failing
	b.unifiedOwnership = true
	b.unifiedDomains = []string{"example.test"}
	route := prefix("192.0.2.1/32")
	prefs := ipn.NewPrefs()
	prefs.AdvertiseRoutes = []netip.Prefix{route}
	b.pm.prefs = prefs.View()
	fixture := &ledgerFixture{}
	l := newLedgerTest(t, fixture)
	f := b.unifiedSnapshot.Fence()
	l.fence = f
	l.state.Fence = f
	if err := l.Update(appctype.RouteOwnerEvent{Fence: f, Sequence: 1, Source: appctype.RouteOwnerAuto, OwnerID: "dns/example.test/example.test/192.0.2.1", Prefixes: []netip.Prefix{route}}); err != nil {
		t.Fatal(err)
	}
	if err := store.WriteState("profile-p||_unifiedRouteLedgerV1", fixture.data); err != nil {
		t.Fatal(err)
	}
	if err := store.WriteState("profile-p||_unifiedHandoffV1", []byte("pending")); err != nil {
		t.Fatal(err)
	}
	err := b.handoffUnifiedOwnership(b.unifiedSnapshot)
	if point != "none" {
		if err == nil || !b.unifiedOwnership {
			t.Fatal("interrupted handoff reported complete")
		}
		// Recreate the backend ownership flag as the worker does from durable intent.
		// A write-then-error completion has durable RouteInfo and needs no replay.
		pending, readErr := (UnifiedPolicyStore{Store: store, ProfileKey: "profile-p"}).HandoffPending()
		if readErr != nil {
			t.Fatal(readErr)
		}
		if point == "complete-after" && pending {
			t.Fatal("completion not durable")
		}
		failing.point = "none"
		if err = b.handoffUnifiedOwnership(b.unifiedSnapshot); err != nil {
			t.Fatal(err)
		}
	} else if err != nil {
		t.Fatal(err)
	}
	if b.unifiedOwnership || !slices.Equal(b.Prefs().AdvertiseRoutes().AsSlice(), []netip.Prefix{route}) {
		t.Fatal("disable changed routes or failed to release")
	}
	raw, err := store.ReadState("profile-p||_routeInfo")
	if err != nil {
		t.Fatal(err)
	}
	var ri appctype.RouteInfo
	if err := json.Unmarshal(raw, &ri); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(ri.Domains["example.test"], []netip.Addr{route.Addr()}) {
		t.Fatal("compatibility not durable")
	}
	raw, err = store.ReadState("profile-p||_unifiedRouteLedgerV1")
	if err != nil || !slices.Equal(raw, fixture.data) {
		t.Fatal("disable rewrote ledger")
	}
}

type handoffWriteFailure struct {
	ipn.StateStore
	point string
}

func (s *handoffWriteFailure) WriteState(k ipn.StateKey, data []byte) error {
	match := (k == "profile-p||_routeInfo" && strings.HasPrefix(s.point, "route-")) || (k == "profile-p||_unifiedHandoffV1" && string(data) == "complete" && strings.HasPrefix(s.point, "complete-"))
	if match && strings.HasSuffix(s.point, "before") {
		return errors.New("power cut before write")
	}
	if err := s.StateStore.WriteState(k, data); err != nil {
		return err
	}
	if match {
		return errors.New("power cut after write")
	}
	return nil
}
