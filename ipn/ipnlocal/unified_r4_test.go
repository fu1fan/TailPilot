package ipnlocal

import (
	"context"
	"encoding/json"
	"net/netip"
	"tailscale.com/featurepolicy"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnauth"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/netmap"
	"testing"
)

func TestR4OffClearRestartEnableDoesNotResurrect(t *testing.T) {
	b, r, st := newConnectorDaemon(t, 1)
	mustTakeover(t, r.connector.ObserveDNSResponse(takeoverWire(t, "www.example.test", [4]byte{192, 0, 2, 7})))
	old := netip.MustParsePrefix("192.0.2.7/32")
	setPolicy := func(raw string) {
		m := featurepolicy.NewManager(UnifiedPolicyStore{Store: st, ProfileID: "p", ProfileKey: "profile-p"})
		_, e := m.Start(featurepolicy.Inputs{ProfileID: "p"}, func() ([]byte, error) { return []byte(raw), nil })
		mustTakeover(t, e)
		r.manager = m
		b.mu.Lock()
		b.unifiedSnapshot = m.Current()
		b.mu.Unlock()
		mustTakeover(t, b.reconcileUnifiedOwnerConsumer(r, m.Current()))
		r.ownerSnapshot = m.Current()
	}
	setPolicy(`{"schema_version":2,"enabled":false}`)
	legacyBytes := []byte(`{"SourceID":77,"Domains":{"d0.example.test":["192.0.1.1"]}}`)
	keep := []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0"), netip.MustParsePrefix("10.44.0.0/16")}
	mp := &ipn.MaskedPrefs{Prefs: ipn.Prefs{AdvertiseRoutes: keep}, AdvertiseRoutesSet: true}
	mustTakeover(t, b.MaybeClearAppConnector(mp))
	_, e := b.EditPrefsAs(mp, ipnauth.Self)
	mustTakeover(t, e)
	// Legacy RouteInfo storage is best-effort and may be disabled by the
	// control knob or have an older asynchronous write still pending.
	mustTakeover(t, st.WriteState("profile-p||_routeInfo", legacyBytes))
	// Simulate fresh lifecycle installation after reload: all state is read from
	// persisted namespaces, not by mutating in-memory owners to hide the bug.
	setPolicy(`{"schema_version":2,"enabled":true,"app_connector_ttl":{"enabled":true}}`)
	for _, p := range b.Prefs().AdvertiseRoutes().All() {
		if p == old {
			t.Fatal("cleared route resurrected")
		}
	}
	v, e := readConnectorIntent(st, "profile-p")
	mustTakeover(t, e)
	if _, ok := v.Ledger.Owners[old]; ok {
		t.Fatal("stale owner survived")
	}
	for _, want := range keep {
		found := false
		for _, p := range v.Desired {
			found = found || p == want
		}
		if !found {
			t.Fatalf("lost retained %s", want)
		}
	}
	// Cleared legacy provenance must not make a freshly relearned address
	// permanently protected from TTL expiry.
	legacy := netip.MustParsePrefix("192.0.1.1/32")
	if _, ok := v.Ledger.Owners[legacy]; ok {
		t.Fatal("cleared legacy owner survived")
	}
	r.connector.UpdateDomains([]string{"*.example.test"})
	r.connector.Wait(context.Background())
	mustTakeover(t, r.connector.ObserveDNSResponse(takeoverWire(t, "d0.example.test", [4]byte{192, 0, 1, 1})))
	// A different address forces the next durable transaction instead of a
	// coalesced refresh of the first lease.
	mustTakeover(t, r.connector.ObserveDNSResponse(takeoverWire(t, "other.example.test", [4]byte{192, 0, 2, 91})))
	v, e = readConnectorIntent(st, "profile-p")
	mustTakeover(t, e)
	if _, ok := v.Ledger.Owners[legacy]; !ok {
		t.Fatal("fresh DNS did not relearn the cleared address")
	}
	if v.Ledger.Owners[legacy].LegacyUnknown {
		t.Fatal("fresh lease inherited cleared legacy protection")
	}
	// Reopen persisted journal to prove the committed representation stays clean.
	raw, e := st.ReadState(connectorKey("profile-p"))
	mustTakeover(t, e)
	var env ledgerEnvelope
	mustTakeover(t, json.Unmarshal(raw, &env))
}

func TestR4DNSBatchColdBurst(t *testing.T) {
	b, r, _ := newConnectorDaemon(t, 0)
	r.dns = make(chan unifiedDNSCall, 64)
	batch := r.connector.CaptureDNSBatchObserver()
	f := r.manager.Current().Fence()
	calls := make([]unifiedDNSCall, 64)
	for i := range calls {
		wire := takeoverWire(t, "www.example.test", [4]byte{192, 0, 2, byte(i + 1)})
		calls[i] = unifiedDNSCall{ctx: context.Background(), fence: f, batch: unifiedDNSBatch{wire: wire, observe: batch}, reply: make(chan error, 1)}
		if i > 0 {
			r.dns <- calls[i]
		}
	}
	b.handleUnifiedDNSBatch(r, calls[0])
	for i, c := range calls {
		select {
		case e := <-c.reply:
			if e != nil {
				t.Fatalf("reply %d: %v", i, e)
			}
		default:
			t.Fatal("missing durable reply")
		}
	}
	s, e := r.connector.TTLState()
	mustTakeover(t, e)
	if len(s.Leases) != 64 {
		t.Fatalf("leases=%d", len(s.Leases))
	}
}

func TestR4DNSBatchMalformedDoesNotPoisonPeers(t *testing.T) {
	b, r, _ := newConnectorDaemon(t, 0)
	batch := r.connector.CaptureDNSBatchObserver()
	good := takeoverWire(t, "www.example.test", [4]byte{192, 0, 2, 9})
	errs := batch([][]byte{{1, 2}, good})
	if errs[0] == nil || errs[1] != nil {
		t.Fatalf("per-query errors: %v", errs)
	}
	found := false
	for _, p := range b.Prefs().AdvertiseRoutes().All() {
		found = found || p == netip.MustParsePrefix("192.0.2.9/32")
	}
	if !found {
		t.Fatal("valid lease not committed")
	}
}

func TestR4RouteEchoDoesNotInvalidateIdentity(t *testing.T) {
	b := newTestLocalBackend(t)
	b.stopUnifiedPolicy()
	peer := &tailcfg.Node{ID: 1, StableID: "peer", Key: key.NewNode().Public(), DiscoKey: key.NewDisco().Public()}
	self := &tailcfg.Node{ID: 2, StableID: "self", Key: key.NewNode().Public()}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.setNetMapLocked(&netmap.NetworkMap{SelfNode: self.View(), Peers: []tailcfg.NodeView{peer.View()}})
	before := b.unifiedRevision
	self = self.Clone()
	self.AllowedIPs = []netip.Prefix{netip.MustParsePrefix("192.0.2.7/32")}
	b.setNetMapLocked(&netmap.NetworkMap{SelfNode: self.View(), Peers: []tailcfg.NodeView{peer.View()}})
	if b.unifiedRevision != before {
		t.Fatal("route echo invalidates identity")
	}
	peer = peer.Clone()
	peer.Key = key.NewNode().Public()
	b.setNetMapLocked(&netmap.NetworkMap{SelfNode: self.View(), Peers: []tailcfg.NodeView{peer.View()}})
	if b.unifiedRevision == before {
		t.Fatal("key rotation did not invalidate identity")
	}
}

func TestR4DNSCacheRejectsChangedDurableJournal(t *testing.T) {
	_, r, st := newConnectorDaemon(t, 0)
	wire := takeoverWire(t, "www.example.test", [4]byte{192, 0, 2, 7})
	mustTakeover(t, r.connector.ObserveDNSResponse(wire))
	if len(r.connectorAdapter.dnsCache.raw) == 0 {
		t.Fatal("cache not exercised")
	}
	mustTakeover(t, st.WriteState(connectorKey("profile-p"), []byte("corrupt")))
	if err := r.connector.ObserveDNSResponse(takeoverWire(t, "next.example.test", [4]byte{192, 0, 2, 8})); err == nil {
		t.Fatal("cached journal masked changed durable bytes")
	}
}

func TestR4DNSBatchDuplicateQueries(t *testing.T) {
	_, r, _ := newConnectorDaemon(t, 0)
	wire := takeoverWire(t, "www.example.test", [4]byte{192, 0, 2, 7})
	errs := r.connector.CaptureDNSBatchObserver()([][]byte{wire, wire, wire})
	for _, err := range errs {
		mustTakeover(t, err)
	}
	s, err := r.connector.TTLState()
	mustTakeover(t, err)
	if len(s.Leases) != 1 {
		t.Fatalf("duplicate queries created %d leases", len(s.Leases))
	}
}
