// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package magicsock

import (
	"context"
	"encoding/binary"
	"fmt"
	"io/fs"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/tailscale/wireguard-go/conn"
	"github.com/tailscale/wireguard-go/device"
	"tailscale.com/disco"
	"tailscale.com/featurepolicy"
	"tailscale.com/net/stun"
	"tailscale.com/tailcfg"
	"tailscale.com/tstime/mono"
	"tailscale.com/types/key"
)

func policyFixture(t *testing.T, bits int) (*Conn, *endpoint) {
	t.Helper()
	c, ep := pathTestConn(t)
	c.privateKey = key.NewNode()
	ep.sentPing = map[stun.TxID]sentPing{}
	ep.endpointState = map[netip.AddrPort]*endpointState{}
	ep.derpAddr = netip.AddrPortFrom(tailcfg.DerpMagicIPAddr, 900)
	c.peersByID = map[tailcfg.NodeID]tailcfg.NodeView{1: (&tailcfg.Node{ID: 1, StableID: "target", Key: ep.publicKey, DiscoKey: ep.disco.Load().key}).View()}
	c.authenticatedPathGate.Store(&authenticatedPathGate{allow: c.allowPolicyAuthenticated, livePolicy: true})
	setPolicyBits(t, c, bits)
	t.Cleanup(func() {
		ep.mu.Lock()
		if ep.policyWGTimer != nil {
			ep.policyWGTimer.Stop()
		}
		for id, p := range ep.sentPing {
			p.timer.Stop()
			delete(ep.sentPing, id)
		}
		ep.mu.Unlock()
	})
	return c, ep
}
func setPolicyBits(t *testing.T, c *Conn, bits int) {
	t.Helper()
	raw := fmt.Sprintf(`{"schema_version":1,"enabled":true,"path_policy":{"enabled":true,"rules":[{"id":"r","stable_ids":["target"],"allow":{"direct":%v,"peer_relay":%v,"derp":%v},"prefer":%s,"allow_blackhole":true}]},"observability":{"log_decisions":false}}`, bits&4 != 0, bits&2 != 0, bits&1 != 0, preferJSON(bits))
	m := featurepolicy.NewManager(&pathTestStore{})
	_, err := m.Start(featurepolicy.Inputs{}, func() ([]byte, error) { return []byte(raw), nil })
	if err != nil {
		t.Fatal(err)
	}
	if err := c.SetPathPolicy(m.Current()); err != nil {
		t.Fatal(err)
	}
}
func preferJSON(bits int) string {
	s := "["
	for i, p := range []string{"direct", "peer_relay", "derp"} {
		if bits&(4>>i) != 0 {
			if len(s) > 1 {
				s += ","
			}
			s += fmt.Sprintf("%q", p)
		}
	}
	return s + "]"
}

func TestPathPolicyReceiveAndEpoch(t *testing.T) {
	for bits := 0; bits < 8; bits++ {
		t.Run(fmt.Sprint(bits), func(t *testing.T) {
			c, ep := policyFixture(t, bits)
			g := c.pathGeneration()
			for i, kind := range []conn.TransportKind{conn.TransportDirect, conn.TransportRelay, conn.TransportDERP} {
				ctx := conn.TransportContext{Kind: kind, Generation: g, RelayVerified: true, RelayPeer: ep.publicKey.Raw32(), DERPSource: ep.publicKey.Raw32()}
				if kind == conn.TransportRelay {
					a := epAddr{ap: netip.MustParseAddrPort("192.0.2.24:40000")}
					a.vni.Set(7)
					server := key.NewDisco().Public()
					publishRelayBinding(c.pathPeer(ep.publicKey), addrQuality{epAddr: a, relaySession: 1, relayServerDisco: server})
					ctx.Endpoint = a.ap
					ctx.RelayVNI = 7
					ctx.RelaySession = 1
					ctx.RelayServer = server.Raw32()
				}
				for _, packet := range []conn.PacketKind{conn.PacketInitiation, conn.PacketResponse, conn.PacketTransport, conn.PacketKeepalive} {
					got := c.allowPolicyAuthenticated(ep.publicKey.Raw32(), packet, ctx)
					if got != (bits&(4>>i) != 0) {
						t.Fatalf("bits=%d kind=%v allow=%v", bits, kind, got)
					}
				}
				ctx.Generation--
				if c.allowPolicyAuthenticated(ep.publicKey.Raw32(), conn.PacketTransport, ctx) {
					t.Fatal("stale ingress")
				}
			}
			if c.allowPolicyAuthenticated(key.NewNode().Public().Raw32(), conn.PacketTransport, conn.TransportContext{Kind: conn.TransportDirect, Generation: g}) {
				t.Fatal("unknown key")
			}
		})
	}
}

func TestPathPolicyDERPIndependentAndHotDeny(t *testing.T) {
	c, ep := policyFixture(t, 1)
	g := c.pathGeneration()
	direct := epAddr{ap: netip.MustParseAddrPort("192.0.2.1:1234")}
	ep.mu.Lock()
	ep.bestAddr = addrQuality{epAddr: direct}
	ep.trustBestAddrUntil = mono.Now().Add(time.Minute)
	ep.observePathLocked(epAddr{ap: ep.derpAddr}, true, g)
	udp, derp, _ := ep.addrForSendLocked(mono.Now())
	ep.mu.Unlock()
	if udp.ap.IsValid() || derp != ep.derpAddr {
		t.Fatal("healthy forbidden direct hid peer home DERP", udp, derp)
	}
	old := pathSendContext{peer: ep.publicKey, generation: g, purpose: featurepolicy.PathSend}
	setPolicyBits(t, c, 4)
	if c.allowPathSend(old, featurepolicy.DERP) || c.allowPathSend(old, featurepolicy.Direct) {
		t.Fatal("queued old send")
	}
	if ep.bestAddr.ap.IsValid() || ep.trustBestAddrUntil != 0 {
		t.Fatal("cache not cleared")
	}
	if c.pathPeer(ep.publicKey).status.Load().Reason != "POLICY_NO_PATH" {
		t.Fatal("silent fallback")
	}
	if err := ep.send(nil, 0); err != errPolicyNoPath {
		t.Fatalf("no route: %v", err)
	}
}

func TestPathPolicyLateRelayAndProbe(t *testing.T) {
	c, ep := policyFixture(t, 2)
	old := c.pathGeneration()
	w := endpointWithLastBest{ep: ep, policyGeneration: old}
	setPolicyBits(t, c, 1)
	if w.policyAllowed() || c.allowPathSend(w.sendContext(), featurepolicy.Direct) {
		t.Fatal("late relay work authorized")
	}
	a := epAddr{ap: netip.MustParseAddrPort("192.0.2.2:40000")}
	a.vni.Set(7)
	ep.udpRelayEndpointReady(addrQuality{epAddr: a, relaySession: 1, policyGeneration: old})
	if ep.bestAddr.ap.IsValid() || len(ep.policyCandidates) != 0 {
		t.Fatal("late relay installed")
	}
	ep.mu.Lock()
	ep.startDiscoPingLocked(a, mono.Now(), pingHeartbeat, 0, nil)
	ep.mu.Unlock()
	if len(ep.sentPing) != 0 {
		t.Fatal("denied probe queued")
	}
	ep.handleCallMeMaybePolicy(&disco.CallMeMaybe{MyNumber: []netip.AddrPort{a.ap}}, old)
	if len(ep.endpointState) != 0 {
		t.Fatal("late CMM installed")
	}
}

func TestPathPolicyPongBindingAndReplay(t *testing.T) {
	c, ep := policyFixture(t, 4)
	g := c.pathGeneration()
	a := epAddr{ap: netip.MustParseAddrPort("192.0.2.3:1234")}
	ep.endpointState[a.ap] = &endpointState{}
	tx := stun.NewTxID()
	ep.sentPing[tx] = sentPing{to: a, at: mono.Now(), timer: time.NewTimer(time.Hour), policyGeneration: g}
	di := &discoInfo{discoKey: ep.disco.Load().key}
	c.mu.Lock()
	ep.handlePongConnLocked(&disco.Pong{TxID: tx}, di, a)
	c.mu.Unlock()
	if len(ep.sentPing) != 0 || ep.c.pathPeer(ep.publicKey).status.Load().Active != featurepolicy.Direct {
		t.Fatal("accepted pong")
	}
	before := ep.lastRecvUDPAny.LoadAtomic()
	c.mu.Lock()
	known := ep.handlePongConnLocked(&disco.Pong{TxID: tx}, di, a)
	c.mu.Unlock()
	if known || ep.lastRecvUDPAny.LoadAtomic() != before {
		t.Fatal("replay updated health")
	}
	tx = stun.NewTxID()
	ep.sentPing[tx] = sentPing{to: a, at: mono.Now(), timer: time.NewTimer(time.Hour), policyGeneration: g}
	setPolicyBits(t, c, 1)
	c.mu.Lock()
	ep.handlePongConnLocked(&disco.Pong{TxID: tx}, di, a)
	c.mu.Unlock()
	if ep.bestAddr.ap.IsValid() || ep.lastRecvUDPAny.LoadAtomic() != before {
		t.Fatal("late pong")
	}
}

func TestPathPolicyGateLockOrder(t *testing.T) {
	c, ep := policyFixture(t, 1)
	g := c.pathGeneration()
	done := make(chan struct{})
	c.mu.Lock()
	ep.mu.Lock()
	go func() {
		defer close(done)
		for range 1000 {
			c.allowPolicyAuthenticated(ep.publicKey.Raw32(), conn.PacketTransport, conn.TransportContext{Kind: conn.TransportDERP, Generation: g})
		}
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Error("WG predicate acquired Conn/endpoint lock")
	}
	ep.mu.Unlock()
	c.mu.Unlock()
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			for range 1000 {
				g := c.pathGeneration()
				c.decidePath(ep.publicKey, featurepolicy.Direct, featurepolicy.PathProbe, g)
				c.PathPolicyState()
			}
		})
	}
	for i := 0; i < 20; i++ {
		setPolicyBits(t, c, i%8)
	}
	wg.Wait()
}

func TestPathPolicyDefaultOff(t *testing.T) {
	c, ep := pathTestConn(t)
	for _, p := range []featurepolicy.Path{featurepolicy.Direct, featurepolicy.PeerRelay, featurepolicy.DERP} {
		if !c.decidePath(ep.publicKey, p, featurepolicy.PathSend, 999) {
			t.Fatal("default off")
		}
	}
	m := featurepolicy.NewManager(nil)
	c.SetPathPolicy(m.Current())
	if c.pathPolicy.Load() != nil {
		t.Fatal("off created active runtime")
	}
}

type pathTestStore struct{ b []byte }

func (s *pathTestStore) Load(string) ([]byte, error) {
	if s.b == nil {
		return nil, fs.ErrNotExist
	}
	return append([]byte(nil), s.b...), nil
}
func (s *pathTestStore) Save(_ string, b []byte) error { s.b = append([]byte(nil), b...); return nil }

func TestPathPolicyWireGuardOnlyBootstrap(t *testing.T) {
	c, ep := policyFixture(t, 4)
	ep.isWireguardOnly = true
	a := netip.MustParseAddrPort("192.0.2.17:1234")
	ep.endpointState[a] = &endpointState{}
	handshake := make([]byte, device.MessageInitiationSize)
	binary.LittleEndian.PutUint32(handshake, device.MessageInitiationType)
	policy := c.newPathSend(ep.publicKey, featurepolicy.PathSend)
	ep.mu.Lock()
	probe, ok := ep.policyWGHandshakeLocked([][]byte{handshake}, 0, mono.Now(), &policy)
	ep.mu.Unlock()
	if !ok || probe.ap != a || policy.purpose != featurepolicy.PathProbe {
		t.Fatal("no authenticated bootstrap probe")
	}
	// The ICMP address choice itself must not activate business traffic.
	if c.decidePath(ep.publicKey, featurepolicy.Direct, featurepolicy.PathSend, c.pathGeneration()) {
		t.Fatal("unverified path active")
	}
	rx := c.authenticatedUDPEndpoint(epAddr{ap: a}, c.authenticatedPathGate.Load()).(*authenticatedEndpoint)
	if !conn.AllowAuthenticatedPeer(rx, ep.publicKey.Raw32(), conn.PacketResponse) {
		t.Fatal("response gate")
	}
	rx.FromPeer(ep.publicKey.Raw32()) // R7 invokes this only after AEAD/replay acceptance.
	if !c.decidePath(ep.publicKey, featurepolicy.Direct, featurepolicy.PathSend, c.pathGeneration()) {
		t.Fatal("authenticated direct not activated")
	}
	setPolicyBits(t, c, 1)
	ep.mu.Lock()
	udp, derp, _ := ep.addrForSendLocked(mono.Now())
	ep.mu.Unlock()
	if udp.ap.IsValid() || derp.IsValid() {
		t.Fatal("WG-only silently used unsupported DERP")
	}
}

func TestPathPolicyUnrelatedUpdateKeepsWork(t *testing.T) {
	c, ep := policyFixture(t, 2)
	g := c.pathGeneration()
	peer := c.pathPeer(ep.publicKey)
	work := endpointWithLastBest{ep: ep, policyGeneration: g}
	a := epAddr{ap: netip.MustParseAddrPort("192.0.2.20:40000")}
	a.vni.Set(12)
	ep.udpRelayEndpointReady(addrQuality{epAddr: a, relaySession: 1, policyGeneration: g})
	c.mu.Lock()
	c.peersByID[2] = (&tailcfg.Node{ID: 2, StableID: "unrelated", Key: key.NewNode().Public(), DiscoKey: key.NewDisco().Public()}).View()
	c.refreshPathPolicyLocked()
	c.mu.Unlock()
	if c.pathGeneration() == g || c.pathPeer(ep.publicKey) != peer || !work.policyAllowed() || !work.acceptsGeneration(c.pathGeneration()) {
		t.Fatal("unrelated update cancelled target work")
	}
	if !ep.bestAddr.ap.IsValid() || !c.decidePath(ep.publicKey, featurepolicy.PeerRelay, featurepolicy.PathSend, c.pathGeneration()) {
		t.Fatal("unrelated update reset active path")
	}
	// Only an explicitly affected peer delta invalidates its old work.
	c.mu.Lock()
	c.refreshPathPolicyLocked(ep.nodeID)
	c.mu.Unlock()
	if work.policyAllowed() || ep.bestAddr.ap.IsValid() {
		t.Fatal("affected peer did not invalidate old work")
	}
}

func TestPathPolicyRelayTimeout(t *testing.T) {
	c, ep := policyFixture(t, 2)
	w := endpointWithLastBest{ep: ep, policyGeneration: c.pathGeneration()}
	if got := w.policyTimeout(30 * time.Second); got != 3*time.Second {
		t.Fatal(got)
	}
	if got := w.policyTimeout(time.Second); got != time.Second {
		t.Fatal("extended server lifetime", got)
	}
	m := featurepolicy.NewManager(nil)
	if err := c.SetPathPolicy(m.Current()); err != nil {
		t.Fatal(err)
	}
	if got := w.policyTimeout(30 * time.Second); got != 30*time.Second {
		t.Fatal("default-off timeout changed", got)
	}
}

func TestPathPolicyWarmRelayOnlyBootstrap(t *testing.T) {
	c, ep := policyFixture(t, 0)
	m := featurepolicy.NewManager(nil)
	if err := c.SetPathPolicy(m.Current()); err != nil {
		t.Fatal(err)
	}
	a := epAddr{ap: netip.MustParseAddrPort("192.0.2.22:40000")}
	a.vni.Set(3)
	ep.bestAddr = addrQuality{epAddr: a, relaySession: 77, relayServerDisco: key.NewDisco().Public()}
	ep.trustBestAddrUntil = mono.Now().Add(time.Minute)
	c.peerMap.setNodeKeyForEpAddr(a, ep.publicKey)
	setPolicyBits(t, c, 2)
	if got := ep.policyCandidates[featurepolicy.PeerRelay]; got.relaySession != 77 || got.epAddr != a {
		t.Fatal("discarded verified warm relay grant")
	}
	if c.decidePath(ep.publicKey, featurepolicy.PeerRelay, featurepolicy.PathSend, c.pathGeneration()) {
		t.Fatal("old grant immediately promoted without new observation")
	}
	tx := stun.NewTxID()
	ep.sentPing[tx] = sentPing{to: a, at: mono.Now(), timer: time.NewTimer(time.Hour), policyGeneration: c.pathGeneration(), policyRelaySession: 77}
	c.mu.Lock()
	ep.handlePongConnLocked(&disco.Pong{TxID: tx}, &discoInfo{discoKey: ep.disco.Load().key}, a)
	c.mu.Unlock()
	if !c.decidePath(ep.publicKey, featurepolicy.PeerRelay, featurepolicy.PathSend, c.pathGeneration()) {
		t.Fatal("warm relay could not activate")
	}
	if c.decidePath(ep.publicKey, featurepolicy.DERP, featurepolicy.PathProbe, c.pathGeneration()) {
		t.Fatal("bootstrap opened forbidden DERP")
	}
}

func TestPathPolicyCancelledRelaySend(t *testing.T) {
	c, ep := policyFixture(t, 2)
	ctx, cancel := context.WithCancel(t.Context())
	w := &relayHandshakeWork{wlb: endpointWithLastBest{ep: ep, policyGeneration: c.pathGeneration()}, ctx: ctx}
	if !c.allowPathSend(w.sendContext(), featurepolicy.PeerRelay) {
		t.Fatal("live relay work denied")
	}
	cancel()
	if c.allowPathSend(w.sendContext(), featurepolicy.PeerRelay) {
		t.Fatal("cancelled relay work sent")
	}
}

// Reproduce the G4 run3 ordering: warm direct traffic, DERP-only reload,
// then idle status polling. No socket or inbound payload is proof of a completed
// probe. Exercise the real probe creation and Pong handler without network I/O.
func TestPathPolicyOnlyDERPIdleReloadBootstrap(t *testing.T) {
	c, ep := policyFixture(t, 4)
	if err := c.SetPathPolicy(featurepolicy.NewManager(nil).Current()); err != nil {
		t.Fatal(err)
	}
	ep.lastSendExt = mono.Now()
	ep.bestAddr = addrQuality{epAddr: epAddr{ap: netip.MustParseAddrPort("192.0.2.3:41641")}}
	setPolicyBits(t, c, 1)
	ep.heartbeat() // resetLocked cleared activity; heartbeat cannot bootstrap idle peers.
	_, states, _ := c.PathPolicyState()
	if st := states["target"]; st.State != featurepolicy.Probing || st.Reason != "POLICY_NO_PATH" || st.Active != "" {
		t.Fatalf("idle reload unexpectedly converged: %+v", st)
	}
	if !ep.lastSendExt.IsZero() || len(ep.sentPing) != 0 || ep.bestAddr.ap.IsValid() {
		t.Fatal("reload did not reset activity and probes")
	}
	ep.mu.Lock()
	ep.policyProbeLocked(mono.Now())
	if len(ep.sentPing) != 1 {
		ep.mu.Unlock()
		t.Fatal("DERP-only bootstrap must create exactly one probe")
	}
	var tx stun.TxID
	var probe sentPing
	for id, sp := range ep.sentPing {
		tx, probe = id, sp
		sp.timer.Stop()
		delete(ep.sentPing, id) // async sender will see no outstanding work
	}
	if probe.to.ap != ep.derpAddr || probe.policyGeneration != c.pathGeneration() {
		ep.mu.Unlock()
		t.Fatal("probe did not use independent peer DERP address/current epoch")
	}
	ep.mu.Unlock()
	// Use a separate TxID so the queued sender above cannot see synthetic work.
	tx = stun.NewTxID()
	ep.mu.Lock()
	probe.timer = time.NewTimer(time.Hour)
	ep.sentPing[tx] = probe
	ep.mu.Unlock()
	c.mu.Lock()
	ep.handlePongConnLocked(&disco.Pong{TxID: tx}, &discoInfo{discoKey: ep.disco.Load().key}, probe.to)
	c.mu.Unlock()
	st := c.pathPeer(ep.publicKey).status.Load()
	if st.State != featurepolicy.Active || st.Active != featurepolicy.DERP || st.Reason != "ACTIVE" {
		t.Fatalf("valid DERP probe did not converge: %+v", st)
	}
	ep.mu.Lock()
	udp, derp := ep.policyAddrLocked()
	ep.mu.Unlock()
	if udp.ap.IsValid() || derp != ep.derpAddr {
		t.Fatal("DERP-only selected wrong transport")
	}
	if c.decidePath(ep.publicKey, featurepolicy.Direct, featurepolicy.PathProbe, c.pathGeneration()) ||
		c.decidePath(ep.publicKey, featurepolicy.PeerRelay, featurepolicy.PathProbe, c.pathGeneration()) {
		t.Fatal("bootstrap relaxed forbidden paths")
	}
}
