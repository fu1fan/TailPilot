package ipnlocal

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/appc"
	"tailscale.com/featurepolicy"
	"tailscale.com/ipn"
	"tailscale.com/types/appctype"
	"tailscale.com/util/eventbus/eventbustest"
)

// Uses the production projection, journal and recovery functions with a real
// StateStore and fake prefs surface. No socket/engine or production host.
type takeoverHarness struct {
	t        *testing.T
	st       *clearFaultStore
	key      ipn.StateKey
	f        featurepolicy.Fence
	adapter  UnifiedLedgerStore
	manifest *appc.ControlProofManifest
	claims   []appc.LegacyDNSReference
	ac       *appc.AppConnector
}

func newTakeoverHarness(t *testing.T, n int) *takeoverHarness {
	h := &takeoverHarness{t: t, st: new(clearFaultStore), key: "p", f: featurepolicy.Fence{ProfileID: "p", Generation: 1}}
	h.adapter = UnifiedLedgerStore{Store: h.st, ProfileKey: h.key, ReadPrefs: func() ([]netip.Prefix, error) {
		raw, e := h.st.ReadState(h.key)
		var ps []netip.Prefix
		if e == nil {
			e = json.Unmarshal(raw, &ps)
		}
		return ps, e
	}, ApplyPrefs: func(before, desired []netip.Prefix) error {
		cur, e := h.adapter.Current()
		if e != nil {
			return e
		}
		if !slices.Equal(sortedRoutes(cur), sortedRoutes(before)) {
			return fmt.Errorf("prefs CAS")
		}
		raw, _ := json.Marshal(desired)
		return h.st.WriteState(h.key, raw)
	}}
	ri := appctype.RouteInfo{Domains: map[string][]netip.Addr{}, Control: []netip.Prefix{prefix("203.0.113.0/24")}}
	current := []netip.Prefix{prefix("0.0.0.0/0"), prefix("::/0"), prefix("203.0.113.0/24"), prefix("198.51.100.200/32")}
	for i := 0; i < n; i++ {
		ip := netip.AddrFrom4([4]byte{192, 0, byte(i/250 + 1), byte(i%250 + 1)})
		ri.Domains[fmt.Sprintf("d%d.example.test", i)] = []netip.Addr{ip}
		current = append(current, netip.PrefixFrom(ip, 32))
	}
	raw, _ := json.Marshal(sortedRoutes(current))
	mustTakeover(t, h.st.WriteState(h.key, raw))
	raw, _ = json.Marshal(ri)
	mustTakeover(t, h.st.WriteState(h.key+"||_routeInfo", raw))
	h.install(nil)
	return h
}
func mustTakeover(t *testing.T, e error) {
	t.Helper()
	if e != nil {
		t.Fatal(e)
	}
}
func (h *takeoverHarness) install(saved *connectorIntent) {
	h.t.Helper()
	ac := appc.NewAppConnector(appc.Config{SourceID: uint64(h.st.calls + 1), Logf: h.t.Logf, EventBus: eventbustest.NewBus(h.t)})
	cfg := appc.ConnectorTTLConfig{Fence: h.f, Roots: []string{"*.example.test"}, Control: []netip.Prefix{prefix("203.0.113.0/24")}, Options: appc.LeaseOptions{MaxEntries: 2000, TimeTrusted: true, ClockJump: time.Hour}, Commit: h.commit}
	if saved != nil {
		cfg.Restore = saved.Transition.AfterLeaseState
		cfg.Legacy = saved.Transition.After.Legacy
		cfg.Revision = saved.Transition.After.Revision
	}
	mustTakeover(h.t, ac.InstallTTLTakeover(cfg))
	h.ac = ac
	h.t.Cleanup(ac.Close)
}
func (h *takeoverHarness) commit(tr appc.ConnectorTTLTransition) error {
	v, e := readConnectorIntent(h.st, h.key)
	if e != nil {
		return e
	}
	if v.Schema == 0 {
		raw, e := h.st.ReadState(h.key + "||_routeInfo")
		if e != nil {
			return e
		}
		if e = json.Unmarshal(raw, &v.Unclaimed); e != nil {
			return e
		}
	}
	l, e := NewRouteLedger(h.f, h.adapter)
	if e != nil {
		return e
	}
	current, e := h.adapter.Current()
	if e != nil {
		return e
	}
	next, e := prepareConnectorImport(v, l, current, tr, h.claims, "review-hash", h.f, h.manifest)
	if e != nil {
		return e
	}
	if e = writeConnectorIntent(h.st, h.key, *next); e != nil {
		return e
	}
	return applyConnectorIntent(h.st, h.key, *next, h.adapter)
}
func (h *takeoverHarness) plan(adopt bool) ConnectorRoutePlan {
	v, e := readConnectorIntent(h.st, h.key)
	mustTakeover(h.t, e)
	l, e := NewRouteLedger(h.f, h.adapter)
	mustTakeover(h.t, e)
	current, e := h.adapter.Current()
	mustTakeover(h.t, e)
	return planConnector(v, l, current, "test-review", adopt)
}
func (h *takeoverHarness) adopt() {
	plan := h.plan(true)
	h.claims = nil
	for _, e := range plan.Entries {
		if e.Eligible {
			h.claims = append(h.claims, e.Reference)
		}
	}
	mustTakeover(h.t, h.ac.AdoptTTL(plan.ConnectorHash, "test-review", h.claims))
	h.claims = nil
}
func takeoverWire(t *testing.T, d string, ip [4]byte) []byte {
	n := dnsmessage.MustNewName(d + ".")
	m := dnsmessage.Message{Header: dnsmessage.Header{Response: true}, Questions: []dnsmessage.Question{{Name: n, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}, Answers: []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: n, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.AResource{A: ip}}}}
	raw, e := m.Pack()
	mustTakeover(t, e)
	return raw
}
func TestConnectorBackendAdopt810ResetRelearn(t *testing.T) {
	h := newTakeoverHarness(t, 810)
	if p := h.plan(false); len(p.Withdraw) != 0 {
		t.Fatal("unreviewed routes withdrawable")
	}
	p := h.plan(true)
	if len(p.Entries) != 810 {
		t.Fatal(len(p.Entries))
	}
	h.adopt()
	p = h.plan(false)
	if len(p.Withdraw) != 810 || len(p.Retain) != 4 {
		t.Fatal(len(p.Withdraw), p.Retain)
	}
	mustTakeover(t, h.ac.ResetTTL(p.ConnectorHash, h.f.Generation, "test-review"))
	current, e := h.adapter.Current()
	mustTakeover(t, e)
	if len(current) != 4 {
		t.Fatal(current)
	}
	state, e := h.ac.TTLState()
	mustTakeover(t, e)
	if len(state.Roots) != 1 || len(state.Control) != 1 {
		t.Fatal("configuration lost")
	}
	mustTakeover(t, h.ac.ObserveDNSResponse(takeoverWire(t, "d0.example.test", [4]byte{192, 0, 1, 1})))
	if p = h.plan(false); len(p.Withdraw) != 1 {
		t.Fatal("cannot relearn", p)
	}
	v, e := readConnectorIntent(h.st, h.key)
	mustTakeover(t, e)
	if v.Reset != nil {
		t.Fatal("DNS failed to invalidate rollback")
	}
}
func TestConnectorBackendResetPowerCuts(t *testing.T) {
	for n := 1; n <= 6; n++ {
		for _, after := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d/after=%v", n, after), func(t *testing.T) {
				h := newTakeoverHarness(t, 2)
				h.adopt()
				p := h.plan(false)
				h.st.calls = 0
				h.st.nth = n
				h.st.after = after
				if e := h.ac.ResetTTL(p.ConnectorHash, h.f.Generation, "test-review"); e == nil {
					t.Fatal("failed write acknowledged")
				}
				if _, e := h.ac.PreviewTTLReset(); e == nil {
					t.Fatal("failed lifecycle not quarantined")
				}
				h.st.nth = 0
				v, e := readConnectorIntent(h.st, h.key)
				mustTakeover(t, e)
				mustTakeover(t, applyConnectorIntent(h.st, h.key, v, h.adapter))
				v, e = readConnectorIntent(h.st, h.key)
				mustTakeover(t, e)
				if !v.Complete {
					t.Fatal("pending after recovery")
				}
				current, e := h.adapter.Current()
				mustTakeover(t, e)
				want := 4
				if n == 1 && !after {
					want = 6
				}
				if len(current) != want {
					t.Fatal(current)
				}
				h.install(&v)
				state, e := h.ac.TTLState()
				mustTakeover(t, e)
				if len(state.Legacy) != want-4 {
					t.Fatal("restart resurrected learning")
				}
			})
		}
	}
}
func TestConnectorBackendRestartRollbackCAS(t *testing.T) {
	h := newTakeoverHarness(t, 2)
	h.adopt()
	p := h.plan(false)
	mustTakeover(t, h.ac.ResetTTL(p.ConnectorHash, h.f.Generation, "test-review"))
	v, e := readConnectorIntent(h.st, h.key)
	mustTakeover(t, e)
	h.install(&v)
	v, e = readConnectorIntent(h.st, h.key)
	mustTakeover(t, e)
	l, e := NewRouteLedger(h.f, h.adapter)
	mustTakeover(t, e)
	if v.Reset == nil || connectorOwnershipHash(l.state) != v.ResetLedgerHash {
		t.Fatal("restart invalidated unchanged checkpoint")
	}
	s, e := h.ac.TTLState()
	mustTakeover(t, e)
	mustTakeover(t, h.ac.RestoreTTLReset(s.Hash(), "test-review", v.Reset.Before, v.Reset.BeforeLeaseState))
	if p = h.plan(false); len(p.Withdraw) != 2 {
		t.Fatal("rollback did not restore old learning")
	}
	p = h.plan(false)
	mustTakeover(t, h.ac.ResetTTL(p.ConnectorHash, h.f.Generation, "test-review"))
	v, e = readConnectorIntent(h.st, h.key)
	mustTakeover(t, e)
	l, e = NewRouteLedger(h.f, h.adapter)
	mustTakeover(t, e)
	mustTakeover(t, l.Update(appctype.RouteOwnerEvent{Fence: h.f, Sequence: l.state.Sequence + 1, Source: appctype.RouteOwnerManual, Prefixes: []netip.Prefix{prefix("192.0.1.1/32")}}))
	if connectorOwnershipHash(l.state) == v.ResetLedgerHash {
		t.Fatal("manual edit did not invalidate rollback")
	}
}

func TestConnectorBackendSharedAndProtected(t *testing.T) {
	h := newTakeoverHarness(t, 2)
	// Add a second domain reference to the same old address before approval.
	v, e := readConnectorIntent(h.st, h.key)
	mustTakeover(t, e)
	ip := netip.MustParseAddr("192.0.1.1")
	v.Unclaimed.Domains["shared.example.test"] = []netip.Addr{ip}
	mustTakeover(t, writeConnectorIntent(h.st, h.key, v))
	p := h.plan(true)
	h.claims = []appc.LegacyDNSReference{{AssignedRoot: "*.example.test", Domain: "d0.example.test", IP: ip}}
	mustTakeover(t, h.ac.AdoptTTL(p.ConnectorHash, "partial-review", h.claims))
	h.claims = nil
	if p = h.plan(false); len(p.Withdraw) != 0 {
		t.Fatal("partial shared provenance withdrew unclaimed domain")
	}
	h.adopt()
	l, e := NewRouteLedger(h.f, h.adapter)
	mustTakeover(t, e)
	mustTakeover(t, l.Update(appctype.RouteOwnerEvent{Fence: h.f, Sequence: l.state.Sequence + 1, Source: appctype.RouteOwnerManual, Prefixes: []netip.Prefix{prefix("192.0.1.1/32"), prefix("0.0.0.0/0"), prefix("::/0")}}))
	p = h.plan(false)
	if len(p.Withdraw) != 1 || !slices.Contains(p.Retain, prefix("192.0.1.1/32")) {
		t.Fatal("manual/shared lost", p)
	}
	mustTakeover(t, h.ac.ResetTTL(p.ConnectorHash, h.f.Generation, "test-review"))
	current, e := h.adapter.Current()
	mustTakeover(t, e)
	for _, want := range []string{"192.0.1.1/32", "203.0.113.0/24", "198.51.100.200/32", "0.0.0.0/0", "::/0"} {
		if !slices.Contains(current, prefix(want)) {
			t.Fatal("protected route lost", want)
		}
	}
}
func TestConnectorBackendRecoveryRejectsExternalChanges(t *testing.T) {
	h := newTakeoverHarness(t, 2)
	h.adopt()
	p := h.plan(false)
	h.st.calls = 0
	h.st.nth = 3
	if h.ac.ResetTTL(p.ConnectorHash, h.f.Generation, "test-review") == nil {
		t.Fatal("no injected fault")
	}
	h.st.nth = 0
	current, e := h.adapter.Current()
	mustTakeover(t, e)
	current = append(current, prefix("198.51.100.222/32"))
	raw, _ := json.Marshal(sortedRoutes(current))
	mustTakeover(t, h.st.WriteState(h.key, raw))
	v, e := readConnectorIntent(h.st, h.key)
	mustTakeover(t, e)
	if applyConnectorIntent(h.st, h.key, v, h.adapter) == nil {
		t.Fatal("external prefs overwritten")
	}
	after, e := h.adapter.Current()
	mustTakeover(t, e)
	if !slices.Equal(sortedRoutes(current), after) {
		t.Fatal("conflict changed routes")
	}
}
func TestConnectorBackendHandoff(t *testing.T) {
	h := newTakeoverHarness(t, 2)
	h.adopt()
	before, e := h.adapter.Current()
	mustTakeover(t, e)
	mustTakeover(t, h.ac.HandoffTTL("all-off"))
	v, e := readConnectorIntent(h.st, h.key)
	mustTakeover(t, e)
	if !v.Handoff || !v.Complete {
		t.Fatal("handoff not durable")
	}
	after, e := h.adapter.Current()
	mustTakeover(t, e)
	if !slices.Equal(before, after) {
		t.Fatal("handoff changed advertisements")
	}
	ri := connectorCompatibility(v)
	if len(ri.Domains["d0.example.test"]) != 1 || len(ri.Wildcards) != 1 || len(ri.Control) != 1 {
		t.Fatal("handoff lost learning or configuration")
	}
	if _, e = h.ac.TTLState(); e == nil {
		t.Fatal("authority not detached")
	}
}

// Exercises the actual LocalBackend barrier/installer with the standard fake
// userspace engine. Requires local sockets; no production host or network E2E.
func TestConnectorDaemonReset(t *testing.T) {
	b := newTestLocalBackend(t)
	b.stopUnifiedPolicy()
	store, _ := prepareUnifiedTransactionTest(t, b, false)
	store.block.Store(false)
	b.unifiedProfileID = "p"
	b.unifiedDomains = []string{"*.example.test"}
	b.appConnector = appc.NewAppConnector(appc.Config{SourceID: 99, Logf: t.Logf, EventBus: b.sys.Bus.Get()})
	t.Cleanup(b.appConnector.Close)
	r := newUnifiedPolicyRuntime(nil)
	r.manager = featurepolicy.NewManager(UnifiedPolicyStore{Store: store, ProfileID: "p", ProfileKey: "profile-p"})
	_, e := r.manager.Start(featurepolicy.Inputs{ProfileID: "p"}, func() ([]byte, error) {
		return []byte(`{"schema_version":2,"enabled":true,"app_connector_ttl":{"enabled":true}}`), nil
	})
	mustTakeover(t, e)
	b.unifiedSnapshot = r.manager.Current()
	b.unifiedOwnership = true
	mustTakeover(t, b.reconcileUnifiedOwnerConsumer(r, r.manager.Current()))
	r.ownerSnapshot = r.manager.Current()
	mustTakeover(t, r.connector.ObserveDNSResponse(takeoverWire(t, "www.example.test", [4]byte{192, 0, 2, 77})))
	req := UnifiedDebugRequest{Source: "daemon-test"}
	p, e := b.connectorAction(r, "appc-route-reset-preview", req)
	mustTakeover(t, e)
	if len(p.Withdraw) != 1 {
		t.Fatal(p)
	}
	req.ExpectGeneration = p.Fence.Generation
	req.ExpectSourceID = p.SourceID
	req.ExpectSHA256 = p.SnapshotHash
	_, e = b.connectorAction(r, "appc-route-reset", req)
	mustTakeover(t, e)
	if b.Prefs().AdvertiseRoutes().Len() != 0 {
		t.Fatal("prefs not cleared")
	}
	mustTakeover(t, r.connector.ObserveDNSResponse(takeoverWire(t, "www.example.test", [4]byte{192, 0, 2, 77})))
	if b.Prefs().AdvertiseRoutes().Len() != 1 {
		t.Fatal("did not relearn")
	}
}

func TestConnectorBackendPreviewBindings(t *testing.T) {
	h := newTakeoverHarness(t, 2)
	h.adopt()
	v, e := readConnectorIntent(h.st, h.key)
	mustTakeover(t, e)
	l, e := NewRouteLedger(h.f, h.adapter)
	mustTakeover(t, e)
	current, e := h.adapter.Current()
	mustTakeover(t, e)
	baseline := planConnector(v, l, current, "reviewer", false)
	if planConnector(v, l, current, "other-reviewer", false).SnapshotHash == baseline.SnapshotHash {
		t.Fatal("source not bound")
	}
	v.ObservedPrefsSHA256 = "hostname-change"
	if planConnector(v, l, current, "reviewer", false).SnapshotHash == baseline.SnapshotHash {
		t.Fatal("full prefs not bound")
	}
	v.ObservedPrefsSHA256 = ""
	v.Transition.After.SourceID++
	if planConnector(v, l, current, "reviewer", false).SnapshotHash == baseline.SnapshotHash {
		t.Fatal("source lifetime not bound")
	}
	v.Transition.After.SourceID--
	v.Transition.After.Fence.Generation++
	if planConnector(v, l, current, "reviewer", false).SnapshotHash == baseline.SnapshotHash {
		t.Fatal("generation not bound")
	}
}
