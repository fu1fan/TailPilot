package ipnlocal

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/net/dns/dnsmessage"
	"net/netip"
	"slices"
	"tailscale.com/appc"
	"tailscale.com/featurepolicy"
	"testing"
	"testing/synctest"

	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnauth"
	"tailscale.com/types/appctype"
)

func TestUnifiedOwnerTransactionFailure(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		b := &LocalBackend{logf: t.Logf}
		store, f := prepareUnifiedTransactionTest(t, b, true)
		route := prefix("192.0.2.70/32")
		result := make(chan error, 1)
		go func() {
			result <- b.ApplyUnifiedOwner(appctype.RouteOwnerEvent{Fence: f, Source: appctype.RouteOwnerAuto, OwnerID: "test", Prefixes: []netip.Prefix{route}})
		}()
		<-store.entered
		if b.Prefs().AdvertiseRoutes().Len() != 0 {
			t.Fatal("intent published before durable prefs")
		}
		raw, err := store.ReadState("profile-p||_unifiedRouteLedgerV1")
		if err != nil {
			t.Fatal(err)
		}
		var env ledgerEnvelope
		if err := json.Unmarshal(raw, &env); err != nil {
			t.Fatal(err)
		}
		var pending routeLedgerState
		if err := json.Unmarshal(env.Payload, &pending); err != nil {
			t.Fatal(err)
		}
		if !pending.Pending || pending.Applied != 0 {
			t.Fatal("missing pending intent")
		}
		edited := make(chan error, 1)
		go func() {
			_, err := b.EditPrefsAs(&ipn.MaskedPrefs{AdvertiseRoutesSet: true, Prefs: ipn.Prefs{AdvertiseRoutes: []netip.Prefix{prefix("192.0.2.1/24")}}}, ipnauth.Self)
			edited <- err
		}()
		synctest.Wait()
		select {
		case <-edited:
			t.Fatal("manual edit passed transaction")
		default:
		}
		close(store.release)
		if err := <-result; err == nil {
			t.Fatal("write failure acknowledged")
		}
		if err := <-edited; err == nil {
			t.Fatal("manual validation bypassed")
		}
		if b.Prefs().AdvertiseRoutes().Len() != 0 || b.UnifiedPolicyState().Applied.Generation != 0 {
			t.Fatal("failed write applied")
		}
	})
}

// Lead executes the real installer/engine case outside the socket sandbox.
func TestUnifiedBackendOwnerUnion(t *testing.T) {
	b := newTestLocalBackend(t)
	b.stopUnifiedPolicy()
	store, f := prepareUnifiedTransactionTest(t, b, false)
	store.block.Store(false)
	b.unifiedProfileID = "p"
	route := prefix("192.0.2.70/32")
	auto := func(ps ...netip.Prefix) {
		t.Helper()
		if err := b.ApplyUnifiedOwner(appctype.RouteOwnerEvent{Fence: f, Source: appctype.RouteOwnerAuto, OwnerID: "test-auto", Prefixes: ps}); err != nil {
			t.Fatal(err)
		}
	}
	manual := func(ps ...netip.Prefix) {
		t.Helper()
		if _, err := b.EditPrefsAs(&ipn.MaskedPrefs{AdvertiseRoutesSet: true, Prefs: ipn.Prefs{AdvertiseRoutes: ps}}, ipnauth.Self); err != nil {
			t.Fatal(err)
		}
	}
	auto(route)
	manual()
	if !slices.Contains(b.Prefs().AdvertiseRoutes().AsSlice(), route) {
		t.Fatal("manual full-list cleared automatic owner")
	}
	manual(route)
	auto()
	if !slices.Contains(b.Prefs().AdvertiseRoutes().AsSlice(), route) {
		t.Fatal("automatic removal cleared manual owner")
	}
	manual()
	if b.Prefs().AdvertiseRoutes().Len() != 0 {
		t.Fatal("manual clear retained exclusive module route")
	}
	auto(route)
	rawBefore, err := store.ReadState("profile-p||_unifiedRouteLedgerV1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.EditPrefs(&ipn.MaskedPrefs{HostnameSet: true, Prefs: ipn.Prefs{Hostname: "unrelated"}}); err != nil {
		t.Fatal(err)
	}
	rawAfter, err := store.ReadState("profile-p||_unifiedRouteLedgerV1")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(rawBefore, rawAfter) || !slices.Contains(b.Prefs().AdvertiseRoutes().AsSlice(), route) {
		t.Fatal("upstream writer overwrote ledger/union")
	}
	f.Generation++
	if err := b.ApplyUnifiedOwner(appctype.RouteOwnerEvent{Fence: f, Source: appctype.RouteOwnerAuto, OwnerID: "late"}); err == nil {
		t.Fatal("late event accepted")
	}
}

func TestUnifiedOwnerRejectManualAndDefaultOff(t *testing.T) {
	b := &LocalBackend{}
	if err := b.ApplyUnifiedOwner(appctype.RouteOwnerEvent{Source: appctype.RouteOwnerManual}); err == nil {
		t.Fatal("manual bypass accepted")
	}
	if err := b.ApplyUnifiedOwner(appctype.RouteOwnerEvent{Source: appctype.RouteOwnerAuto, OwnerID: "a"}); err == nil {
		t.Fatal("default-off write accepted")
	}
}

func TestUnifiedMigrationBackendDryRun(t *testing.T) {
	b := &LocalBackend{logf: t.Logf}
	store, f := prepareUnifiedTransactionTest(t, b, false)
	store.block.Store(false)
	route := prefix("2001:db8::1/128")
	prefs := ipn.NewPrefs()
	prefs.AdvertiseRoutes = []netip.Prefix{route}
	b.pm.prefs = prefs.View()
	ri := appctype.RouteInfo{Domains: map[string][]netip.Addr{"example.test": {route.Addr()}}}
	data, _ := json.Marshal(ri)
	if err := store.WriteState("profile-p||_routeInfo", data); err != nil {
		t.Fatal(err)
	}
	plan, err := b.UnifiedMigrationDryRun()
	if err != nil {
		t.Fatal(err)
	}
	want := MigrationDryRun(f, []netip.Prefix{route}, ri)
	if plan.SnapshotHash != want.SnapshotHash || !slices.Contains(plan.Unknown, route) {
		t.Fatal("dry run changed evidence")
	}
	if _, err := store.ReadState("profile-p||_unifiedRouteLedgerV1"); err != ipn.ErrStateNotExist {
		t.Fatal("dry run wrote ledger", err)
	}
	if err := plan.ValidateClaims("stale", []netip.Prefix{route}); err == nil {
		t.Fatal("unbound claim accepted")
	}
}

func TestUnifiedAutomaticClearPreview(t *testing.T) {
	b := &LocalBackend{logf: t.Logf}
	store, f := prepareUnifiedTransactionTest(t, b, false)
	store.block.Store(false)
	exclusive, shared := prefix("192.0.2.1/32"), prefix("192.0.2.2/32")
	b.unifiedOwnersProfile = f.ProfileID
	b.unifiedOwners = map[netip.Prefix]PrefixOwners{exclusive: {CreatedByModule: true, Auto: map[string]bool{"a": true}}, shared: {CreatedByModule: true, Manual: true, Auto: map[string]bool{"a": true}}}
	plan, err := b.PreviewUnifiedAutomaticClear()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(plan.Withdraw, []netip.Prefix{exclusive}) || !slices.Equal(plan.Retain, []netip.Prefix{shared}) {
		t.Fatal("clear preview lost owner distinction")
	}
	if _, err := store.ReadState("profile-p||_unifiedRouteLedgerV1"); err != ipn.ErrStateNotExist {
		t.Fatal("preview wrote ledger")
	}
	o := b.unifiedOwners[exclusive]
	o.Manual = true
	b.unifiedOwners[exclusive] = o
	changed, err := b.PreviewUnifiedAutomaticClear()
	if err != nil {
		t.Fatal(err)
	}
	if changed.SnapshotHash == plan.SnapshotHash {
		t.Fatal("preview not bound to owner snapshot")
	}
}

func TestUnifiedBackendOwnerIPv6(t *testing.T) {
	b := newTestLocalBackend(t)
	b.stopUnifiedPolicy()
	store, _ := prepareUnifiedTransactionTest(t, b, false)
	store.block.Store(false)
	b.unifiedProfileID = "p"
	m := featurepolicy.NewManager(UnifiedPolicyStore{Store: store, ProfileID: "p", ProfileKey: "profile-p"})
	config := []byte(`{"schema_version":1,"enabled":true,"auto_ipv6":{"enabled":true,"publish":true}}`)
	if _, err := m.Start(featurepolicy.Inputs{ProfileID: "p"}, func() ([]byte, error) { return config, nil }); err != nil {
		t.Fatal(err)
	}
	b.unifiedSnapshot = m.Current()
	v6, shared, v4, def := prefix("2001:db8::1/128"), prefix("2001:db8::2/128"), prefix("192.0.2.1/32"), prefix("::/0")
	if err := b.ApplyUnifiedOwner(appctype.RouteOwnerEvent{Fence: m.Current().Fence(), Source: appctype.RouteOwnerAuto, OwnerID: "auto", Prefixes: []netip.Prefix{v6, shared, v4}}); err != nil {
		t.Fatal(err)
	}
	if _, err := b.EditPrefs(&ipn.MaskedPrefs{AdvertiseRoutesSet: true, Prefs: ipn.Prefs{AdvertiseRoutes: []netip.Prefix{shared, def}}}); err != nil {
		t.Fatal(err)
	}
	config = []byte(`{"schema_version":1,"enabled":true,"auto_ipv6":{"enabled":true,"publish":false}}`)
	if err := m.Reload(config, m.Current().Fence().Generation, fmt.Sprintf("%x", sha256.Sum256(config))); err != nil {
		t.Fatal(err)
	}
	b.unifiedSnapshot = m.Current()
	if err := b.ApplyUnifiedOwner(appctype.RouteOwnerEvent{Fence: m.Current().Fence(), Source: appctype.RouteOwnerReadvertise}); err != nil {
		t.Fatal(err)
	}
	got := b.Prefs().AdvertiseRoutes().AsSlice()
	if slices.Contains(got, v6) {
		t.Fatal("backend retained exclusive IPv6")
	}
	for _, p := range []netip.Prefix{shared, v4, def} {
		if !slices.Contains(got, p) {
			t.Fatal("backend withdrew protected route", p)
		}
	}
	retained, _ := b.UnifiedIPv6Diagnostics()
	if !slices.Contains(retained, shared) {
		t.Fatal("shared retention not diagnosed")
	}
}

func TestUnifiedBackendLeaseConsumer(t *testing.T) {
	b := newTestLocalBackend(t)
	b.stopUnifiedPolicy()
	store, _ := prepareUnifiedTransactionTest(t, b, false)
	store.block.Store(false)
	b.unifiedProfileID = "p"
	b.unifiedDomains = []string{"example.test"}
	b.appConnector = appc.NewAppConnector(appc.Config{Logf: t.Logf, EventBus: b.sys.Bus.Get(), SourceID: 99})
	r := newUnifiedPolicyRuntime(nil)
	if err := b.reconcileUnifiedOwnerConsumer(r, b.unifiedSnapshot); err != nil {
		t.Fatal(err)
	}
	wire := func(last byte) []byte {
		name := dnsmessage.MustNewName("example.test.")
		msg := dnsmessage.Message{Header: dnsmessage.Header{Response: true}, Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}, Answers: []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.AResource{A: [4]byte{192, 0, 2, last}}}}}
		data, err := msg.Pack()
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	if err := b.ObserveDNSResponse(wire(1)); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(b.Prefs().AdvertiseRoutes().AsSlice(), prefix("192.0.2.1/32")) {
		t.Fatal("DNS sink did not durably advertise")
	}
	if _, err := store.ReadState("profile-p||_unifiedLeasesV1"); err != nil {
		t.Fatal("missing durable lease", err)
	}
	store.fail = true
	store.block.Store(true)
	close(store.release)
	err := b.ObserveDNSResponse(wire(2))
	var leaseErr *appc.LeaseObservationError
	if !errors.As(err, &leaseErr) {
		t.Fatal("durable failure did not reach SERVFAIL contract", err)
	}
	if slices.Contains(b.Prefs().AdvertiseRoutes().AsSlice(), prefix("192.0.2.2/32")) {
		t.Fatal("failed DNS route published")
	}
}
