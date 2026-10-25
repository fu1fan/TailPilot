package ipnlocal

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"tailscale.com/appc"
	"tailscale.com/featurepolicy"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnauth"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/types/appctype"
)

type connectorDaemonStore struct {
	mem.Store
	calls            atomic.Int64
	nth              atomic.Int64
	after            bool
	block            atomic.Bool
	entered, release chan struct{}
}

func (s *connectorDaemonStore) WriteState(k ipn.StateKey, v []byte) error {
	if k == "profile-p" && s.block.CompareAndSwap(true, false) {
		close(s.entered)
		<-s.release
	}
	n := s.calls.Add(1)
	fail := n == s.nth.Load()
	if fail && !s.after {
		return fmt.Errorf("injected power cut before write")
	}
	if err := s.Store.WriteState(k, v); err != nil {
		return err
	}
	if fail {
		return fmt.Errorf("injected power cut after write")
	}
	return nil
}

func newConnectorDaemon(t *testing.T, n int) (*LocalBackend, *unifiedPolicyRuntime, *connectorDaemonStore) {
	return newConnectorDaemonMode(t, n, false)
}
func newConnectorDaemonMode(t *testing.T, n int, controlOnly bool) (*LocalBackend, *unifiedPolicyRuntime, *connectorDaemonStore) {
	t.Helper()
	b := newTestLocalBackend(t)
	b.stopUnifiedPolicy()
	_, _ = prepareUnifiedTransactionTest(t, b, false)
	st := new(connectorDaemonStore)
	b.pm.store = st
	b.store = st
	b.unifiedProfileID = "p"
	b.unifiedDomains = []string{"*.example.test"}
	b.appConnector = appc.NewAppConnector(appc.Config{SourceID: 99, Logf: t.Logf, EventBus: b.sys.Bus.Get()})
	t.Cleanup(b.appConnector.Close)
	ri := appctype.RouteInfo{SourceID: 77, Domains: map[string][]netip.Addr{}}
	prefs := b.pm.CurrentPrefs().AsStruct()
	for i := 0; i < n; i++ {
		ip := netip.AddrFrom4([4]byte{192, 0, byte(i/250 + 1), byte(i%250 + 1)})
		if controlOnly {
			ri.Control = append(ri.Control, netip.PrefixFrom(ip, 32))
		} else {
			ri.Domains[fmt.Sprintf("d%d.example.test", i)] = []netip.Addr{ip}
		}
		prefs.AdvertiseRoutes = append(prefs.AdvertiseRoutes, netip.PrefixFrom(ip, 32))
	}
	b.pm.prefs = prefs.View()
	mustTakeover(t, st.WriteState("profile-p", prefs.ToBytes()))
	raw, _ := json.Marshal(ri)
	mustTakeover(t, st.WriteState("profile-p||_routeInfo", raw))
	r := newUnifiedPolicyRuntime(nil)
	r.manager = featurepolicy.NewManager(UnifiedPolicyStore{Store: st, ProfileID: "p", ProfileKey: "profile-p"})
	_, e := r.manager.Start(featurepolicy.Inputs{ProfileID: "p"}, func() ([]byte, error) {
		return []byte(`{"schema_version":2,"enabled":true,"app_connector_ttl":{"enabled":true}}`), nil
	})
	mustTakeover(t, e)
	b.unifiedSnapshot = r.manager.Current()
	b.unifiedOwnership = true
	mustTakeover(t, b.reconcileUnifiedOwnerConsumer(r, r.manager.Current()))
	r.ownerSnapshot = r.manager.Current()
	return b, r, st
}
func daemonPreview(t *testing.T, b *LocalBackend, r *unifiedPolicyRuntime, kind string, req UnifiedDebugRequest) (ConnectorRoutePlan, UnifiedDebugRequest) {
	t.Helper()
	p, e := b.connectorAction(r, kind+"-preview", req)
	mustTakeover(t, e)
	req.ExpectSHA256 = p.SnapshotHash
	req.ExpectGeneration = p.Fence.Generation
	req.ExpectSourceID = p.SourceID
	return p, req
}
func TestConnectorDaemonImport810RollbackRelearn(t *testing.T) {
	b, r, st := newConnectorDaemonMode(t, 810, true)
	v, e := readConnectorIntent(st, "profile-p")
	mustTakeover(t, e)
	// RouteInfo.SourceID is runtime-only (json:"-"): persisted upstream
	// history has source zero, not the in-memory fixture's source 77.
	// Bind the manifest to the daemon preview, exactly as an operator must.
	initial, _ := daemonPreview(t, b, r, "appc-route-adopt", UnifiedDebugRequest{Source: "review"})
	if initial.LegacySourceID != 0 || len(v.Unclaimed.Control) != 810 || len(v.Unclaimed.Domains) != 0 {
		t.Fatal("expected persisted Control-only history with no source lifetime")
	}
	manifest := &appc.ControlProofManifest{SchemaVersion: 1, ProfileID: initial.Fence.ProfileID, LegacySourceID: initial.LegacySourceID, Source: "reviewed-offline"}
	for i, p := range v.Unclaimed.Control {
		manifest.Entries = append(manifest.Entries, appc.ControlProofEntry{Reference: appc.LegacyDNSReference{AssignedRoot: "*.example.test", Domain: fmt.Sprintf("d%d.example.test", i), IP: p.Addr()}, Reviewed: true, ReviewedBy: "reviewer", Evidence: "offline record", EvidenceSHA256: fmt.Sprintf("%064x", 1)})
	}
	// A runtime source lifetime must still fail the exact historical binding.
	wrongSource := *manifest
	wrongSource.LegacySourceID = 77
	if _, err := b.connectorAction(r, "appc-route-adopt-preview", UnifiedDebugRequest{Source: "review", Manifest: &wrongSource}); err == nil {
		t.Fatal("runtime source accepted as persisted historical source")
	}
	p, req := daemonPreview(t, b, r, "appc-route-adopt", UnifiedDebugRequest{Source: "review", Manifest: manifest})
	for _, entry := range p.Entries {
		if entry.Eligible {
			req.Claims = append(req.Claims, entry.Reference)
		}
	}
	if len(req.Claims) != 810 {
		t.Fatal("incomplete adoption")
	}
	stale := req
	stale.ExpectSHA256 = "stale"
	if _, e = b.connectorAction(r, "appc-route-adopt", stale); e == nil {
		t.Fatal("stale proof accepted")
	}
	_, e = b.connectorAction(r, "appc-route-adopt", req)
	mustTakeover(t, e)
	v, e = readConnectorIntent(st, "profile-p")
	mustTakeover(t, e)
	if v.ApprovalHash != req.ExpectSHA256 {
		t.Fatal("review hash not recorded")
	}
	p, req = daemonPreview(t, b, r, "appc-route-reset", UnifiedDebugRequest{Source: "reset"})
	if len(p.Withdraw) != 810 {
		t.Fatalf("Withdraw=%d", len(p.Withdraw))
	}
	_, e = b.connectorAction(r, "appc-route-reset", req)
	mustTakeover(t, e)
	if b.Prefs().AdvertiseRoutes().Len() != 0 {
		t.Fatal("reset failed")
	}
	_, req = daemonPreview(t, b, r, "appc-route-reset", UnifiedDebugRequest{Source: "rollback"})
	_, e = b.connectorAction(r, "appc-route-reset-rollback", req)
	mustTakeover(t, e)
	if b.Prefs().AdvertiseRoutes().Len() != 810 {
		t.Fatal("rollback failed")
	}
	_, req = daemonPreview(t, b, r, "appc-route-reset", UnifiedDebugRequest{Source: "reset-again"})
	_, e = b.connectorAction(r, "appc-route-reset", req)
	mustTakeover(t, e)
	mustTakeover(t, r.connector.ObserveDNSResponse(takeoverWire(t, "d0.example.test", [4]byte{192, 0, 1, 1})))
	if b.Prefs().AdvertiseRoutes().Len() != 1 {
		t.Fatal("relearn failed")
	}
	_, req = daemonPreview(t, b, r, "appc-route-reset", UnifiedDebugRequest{Source: "stale-rollback"})
	if _, e = b.connectorAction(r, "appc-route-reset-rollback", req); e == nil {
		t.Fatal("rollback overwrote newer DNS")
	}
}

func TestConnectorDaemonDisableAndProfileHandoff(t *testing.T) {
	for _, mode := range []string{"all-off", "ttl-off", "profile"} {
		t.Run(mode, func(t *testing.T) {
			b, r, st := newConnectorDaemon(t, 0)
			mustTakeover(t, r.connector.ObserveDNSResponse(takeoverWire(t, "www.example.test", [4]byte{192, 0, 2, 7})))
			before := slices.Clone(b.Prefs().AdvertiseRoutes().AsSlice())
			profile, key := "p", ipn.StateKey("profile-p")
			config := `{"schema_version":2,"enabled":false}`
			if mode == "ttl-off" {
				config = `{"schema_version":2,"enabled":true,"auto_ipv6":{"enabled":true},"app_connector_ttl":{"enabled":false}}`
			}
			if mode == "profile" {
				profile, key = "q", "profile-q"
				b.pm.currentProfile = (&ipn.LoginProfile{ID: "q", Key: key}).View()
				prefs := ipn.NewPrefs()
				prefs.Hostname = "profile-q"
				b.pm.prefs = prefs.View()
				mustTakeover(t, st.WriteState(key, prefs.ToBytes()))
			}
			m := featurepolicy.NewManager(UnifiedPolicyStore{Store: st, ProfileID: profile, ProfileKey: key})
			_, e := m.Start(featurepolicy.Inputs{ProfileID: profile}, func() ([]byte, error) { return []byte(config), nil })
			mustTakeover(t, e)
			r.manager = m
			b.unifiedSnapshot = m.Current()
			mustTakeover(t, b.reconcileUnifiedOwnerConsumer(r, m.Current()))
			if r.connector != nil {
				t.Fatal("TTL authority still active")
			}
			v, e := readConnectorIntent(st, "profile-p")
			mustTakeover(t, e)
			if !v.Complete || !v.Handoff {
				t.Fatal("handoff not durable")
			}
			if mode == "profile" {
				if b.Prefs().Hostname() != "profile-q" || b.Prefs().AdvertiseRoutes().Len() != 0 {
					t.Fatal("old profile leaked")
				}
			} else if !slices.Equal(before, b.Prefs().AdvertiseRoutes().AsSlice()) {
				t.Fatal("handoff removed advertisements")
			}
		})
	}
}

func TestConnectorDaemonResetPowerCuts(t *testing.T) {
	for n := 1; n <= 6; n++ {
		for _, after := range []bool{false, true} {
			t.Run(fmt.Sprintf("write-%d-after-%t", n, after), func(t *testing.T) {
				b, r, st := newConnectorDaemon(t, 0)
				mustTakeover(t, r.connector.ObserveDNSResponse(takeoverWire(t, "www.example.test", [4]byte{192, 0, 2, 7})))
				_, req := daemonPreview(t, b, r, "appc-route-reset", UnifiedDebugRequest{Source: "power-test"})
				st.after = after
				st.nth.Store(st.calls.Load() + int64(n))
				if _, e := b.connectorAction(r, "appc-route-reset", req); e == nil {
					t.Fatal("failed write acknowledged")
				}
				if !b.unifiedTTLBlocked {
					t.Fatal("backend not quarantined")
				}
				if e := r.connector.ObserveDNSResponse(takeoverWire(t, "later.example.test", [4]byte{192, 0, 2, 8})); e == nil {
					t.Fatal("DNS entered failed lifecycle")
				}
				st.nth.Store(0)
				// Recreate the consumer over persisted prefs, as startup recovery does.
				raw, e := st.ReadState("profile-p")
				mustTakeover(t, e)
				prefs := ipn.NewPrefs()
				mustTakeover(t, ipn.PrefsFromBytes(raw, prefs))
				b.pm.prefs = prefs.View()
				b.unifiedTTLBlocked = false
				b.appConnector = appc.NewAppConnector(appc.Config{SourceID: 100, Logf: t.Logf, EventBus: b.sys.Bus.Get()})
				t.Cleanup(b.appConnector.Close)
				r.connector = nil
				r.connectorAdapter = nil
				mustTakeover(t, b.reconcileUnifiedOwnerConsumer(r, r.manager.Current()))
				want := 0
				if n == 1 && !after {
					want = 1
				}
				if b.Prefs().AdvertiseRoutes().Len() != want {
					t.Fatalf("recovery routes=%d want=%d", b.Prefs().AdvertiseRoutes().Len(), want)
				}
			})
		}
	}
}

func TestConnectorDaemonConcurrentDNSPrefsNetmap(t *testing.T) {
	b, r, st := newConnectorDaemon(t, 0)
	st.entered = make(chan struct{})
	st.release = make(chan struct{})
	st.block.Store(true)
	dns, prefs, netmapDone := make(chan error, 1), make(chan error, 1), make(chan bool, 1)
	go func() {
		dns <- r.connector.ObserveDNSResponse(takeoverWire(t, "www.example.test", [4]byte{192, 0, 2, 7}))
	}()
	select {
	case <-st.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("DNS did not reach durable prefs barrier")
	}
	go func() {
		_, e := b.EditPrefsAs(&ipn.MaskedPrefs{HostnameSet: true, Prefs: ipn.Prefs{Hostname: "concurrent-edit"}}, ipnauth.Self)
		prefs <- e
	}()
	go func() { netmapDone <- b.UpdateNetmapDelta(nil) }()
	if b.Prefs().AdvertiseRoutes().Len() != 0 {
		t.Fatal("uncommitted DNS visible")
	}
	close(st.release)
	for _, ch := range []chan error{dns, prefs} {
		select {
		case e := <-ch:
			mustTakeover(t, e)
		case <-time.After(5 * time.Second):
			t.Fatal("writer deadlock")
		}
	}
	select {
	case <-netmapDone:
	case <-time.After(5 * time.Second):
		t.Fatal("netmap deadlock")
	}
	p := b.Prefs()
	if p.Hostname() != "concurrent-edit" || p.AdvertiseRoutes().Len() != 1 {
		t.Fatal("concurrent change lost")
	}
	raw, e := st.ReadState("profile-p")
	mustTakeover(t, e)
	saved := ipn.NewPrefs()
	mustTakeover(t, ipn.PrefsFromBytes(raw, saved))
	if saved.Hostname != p.Hostname() || !slices.Equal(saved.AdvertiseRoutes, p.AdvertiseRoutes().AsSlice()) {
		t.Fatal("durable/live divergence")
	}
}
