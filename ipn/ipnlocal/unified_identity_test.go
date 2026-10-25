package ipnlocal

import (
	"tailscale.com/featurepolicy"
	"tailscale.com/ipn"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/netmap"
	"tailscale.com/util/eventbus"
	"testing"
)

// Uses the real nodeBackend full-map and delta indexes; no fake engine/socket.
// The LocalBackend input capture must use Peers(), not the stale full-map slice.
func TestUnifiedPolicyNetmapIdentity(t *testing.T) {
	b := &LocalBackend{pm: &profileManager{currentProfile: (&ipn.LoginProfile{}).View()}, unifiedWake: make(chan struct{}, 1)}
	nb := newNodeBackend(t.Context(), t.Logf, eventbus.New())
	b.currentNodeAtomic.Store(nb)
	t.Cleanup(func() { nb.shutdown(nil) })
	testUnifiedIdentityChanges(t, b, func(nm *netmap.NetworkMap) { nb.SetNetMap(nm); b.signalUnifiedPolicyLocked() }, func(m []netmap.NodeMutation) { nb.UpdateNetmapDelta(m); b.signalUnifiedPolicyLocked() })
}

// Lead must run this non-sandbox: it uses the real LocalBackend full-map/delta
// entry points (including invalidation), and the existing fake userspace engine.
func TestUnifiedBackendNetmapIdentity(t *testing.T) {
	b := newTestLocalBackend(t)
	b.stopUnifiedPolicy()
	testUnifiedIdentityChanges(t, b, func(nm *netmap.NetworkMap) { b.setNetMapLocked(nm) }, func(m []netmap.NodeMutation) {
		b.mu.Unlock()
		b.UpdateNetmapDelta(m)
		b.mu.Lock()
	})
}

func testUnifiedIdentityChanges(t *testing.T, b *LocalBackend, full func(*netmap.NetworkMap), delta func([]netmap.NodeMutation)) {
	t.Helper()
	b.mu.Lock()
	b.store = new(mem.Store)
	b.pm.store = b.store
	b.pm.currentProfile = (&ipn.LoginProfile{ID: "identity-test", Key: "profile-identity-test"}).View()
	b.mu.Unlock()
	r := newUnifiedPolicyRuntime(func() ([]byte, error) {
		return []byte(`{"schema_version":1,"enabled":true,"path_policy":{"enabled":true,"rules":[{"id":"one","stable_ids":["stable-one"],"allow":{"direct":false,"peer_relay":false,"derp":true},"prefer":["derp"]}]}}`), nil
	})
	peer := &tailcfg.Node{ID: 1, StableID: "stable-one", Key: key.NewNode().Public(), DiscoKey: key.NewDisco().Public()}
	oldKey, oldDisco := peer.Key, peer.DiscoKey
	capture := func() *featurepolicy.PolicySnapshot {
		t.Helper()
		b.mu.Lock()
		in, store, _ := b.unifiedInputsLocked()
		b.mu.Unlock()
		if err := r.refresh(in, store); err != nil {
			t.Fatal(err)
		}
		return r.manager.Current()
	}
	b.mu.Lock()
	full(&netmap.NetworkMap{SelfNode: (&tailcfg.Node{ID: 99, StableID: "self", Key: key.NewNode().Public()}).View(), Peers: []tailcfg.NodeView{peer.View()}})
	b.mu.Unlock()
	s := capture()
	if _, ok := s.NodeIdentity(oldKey); !ok {
		t.Fatal("full map identity missing")
	}
	before := s.Fence()
	peer = peer.Clone()
	peer.Key, peer.DiscoKey = key.NewNode().Public(), key.NewDisco().Public()
	b.mu.Lock()
	delta([]netmap.NodeMutation{netmap.NodeMutationUpsert{Node: peer.View()}})
	b.mu.Unlock()
	s = capture()
	if s.Fence().PeerIdentityEpoch == before.PeerIdentityEpoch {
		t.Fatal("delta did not invalidate epoch")
	}
	if _, ok := s.NodeIdentity(oldKey); ok {
		t.Fatal("rotated node key retained")
	}
	if _, ok := s.DiscoIdentity(oldDisco); ok {
		t.Fatal("rotated disco key retained")
	}
	if id, ok := s.NodeIdentity(peer.Key); !ok || id.StableID != peer.StableID {
		t.Fatal("stable identity lost on rotation")
	}
	b.mu.Lock()
	delta([]netmap.NodeMutation{netmap.MakeNodeMutationRemove(peer.ID)})
	b.mu.Unlock()
	if _, ok := capture().NodeIdentity(peer.Key); ok {
		t.Fatal("removed peer retained")
	}
	peer = peer.Clone()
	peer.StableID = "registered-again"
	b.mu.Lock()
	delta([]netmap.NodeMutation{netmap.NodeMutationUpsert{Node: peer.View()}})
	b.mu.Unlock()
	if _, ok := capture().NodeIdentity(peer.Key); ok {
		t.Fatal("new stable ID inherited rule")
	}
	b.mu.Lock()
	full(nil)
	b.mu.Unlock()
	if _, ok := capture().NodeIdentity(peer.Key); ok {
		t.Fatal("cleared map retained peer")
	}
}
