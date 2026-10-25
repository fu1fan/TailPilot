// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package magicsock

import (
	"net/netip"
	"testing"
	"time"

	"github.com/tailscale/wireguard-go/conn"
	"tailscale.com/disco"
	"tailscale.com/featurepolicy"
	"tailscale.com/net/stun"
	"tailscale.com/tailcfg"
	"tailscale.com/tstime/mono"
	"tailscale.com/types/key"
)

func TestPathPolicyEncryptedDiscoDenyAndForgery(t *testing.T) {
	c, ep := policyFixture(t, 1)
	sender := key.NewDisco()
	old := ep.disco.Load().key
	ep.disco.Store(&endpointDisco{key: sender.Public()})
	c.peerMap.upsertEndpoint(ep, old)
	src := epAddr{ap: netip.MustParseAddrPort("192.0.2.10:1234")}
	c.peerMap.setNodeKeyForEpAddr(src, ep.publicKey)
	payload := (&disco.Ping{NodeKey: ep.publicKey, TxID: stun.NewTxID()}).AppendMarshal(nil)
	msg := append([]byte(disco.Magic), sender.Public().AppendTo(nil)...)
	msg = append(msg, sender.Shared(c.discoAtomic.Public()).Seal(payload)...)
	forged := append([]byte(nil), msg...)
	forged[len(forged)-1] ^= 1
	for _, pkt := range [][]byte{forged, msg, msg} {
		c.handleDiscoMessage(pkt, src, false, key.NodePublic{}, discoRXPathUDP)
		if ep.lastRecvUDPAny.LoadAtomic() != 0 || len(ep.endpointState) != 0 || ep.bestAddr.ap.IsValid() {
			t.Fatal("disco deny/forgery updated health or candidate")
		}
	}
}

func TestPathPolicySharedDiscoAmbiguity(t *testing.T) {
	c, ep := policyFixture(t, 4)
	other := &endpoint{c: c, nodeID: 2, publicKey: key.NewNode().Public()}
	other.disco.Store(&endpointDisco{key: ep.disco.Load().key})
	c.peerMap.upsertEndpoint(other, key.DiscoPublic{})
	c.peersByID[2] = (&tailcfg.Node{ID: 2, StableID: "other", Key: other.publicKey, DiscoKey: other.disco.Load().key}).View()
	c.mu.Lock()
	c.refreshPathPolicyLocked()
	c.mu.Unlock()
	a := epAddr{ap: netip.MustParseAddrPort("192.0.2.11:1234")}
	di := &discoInfo{discoKey: ep.disco.Load().key}
	ping := &disco.Ping{TxID: stun.NewTxID()}
	c.mu.Lock()
	_, ok := c.policyPingLocked(ping, a, di, key.NodePublic{})
	if ok {
		t.Error("ambiguous shared disco confirmed")
	}
	ping.NodeKey = ep.publicKey
	nk, ok := c.policyPingLocked(ping, a, di, key.NodePublic{})
	if !ok || nk != ep.publicKey {
		t.Error("control-bound ping failed")
	}
	before := ep.lastRecvUDPAny.LoadAtomic()
	if _, ok := c.policyPingLocked(ping, a, di, key.NodePublic{}); ok {
		t.Error("replay confirmed")
	}
	c.mu.Unlock()
	if ep.lastRecvUDPAny.LoadAtomic() != before || other.lastRecvUDPAny.LoadAtomic() != 0 {
		t.Fatal("replay/shared key updated health")
	}
}

func TestPathPolicyReceiveContextAndHealthFence(t *testing.T) {
	c, ep := policyFixture(t, 4)
	a := epAddr{ap: netip.MustParseAddrPort("192.0.2.12:1234")}
	rx := c.authenticatedUDPEndpoint(a, c.authenticatedPathGate.Load()).(*authenticatedEndpoint)
	if !conn.AllowAuthenticatedPeer(rx, ep.publicKey.Raw32(), conn.PacketTransport) {
		t.Fatal("initial allow")
	}
	setPolicyBits(t, c, 1)
	if conn.AllowAuthenticatedPeer(rx, ep.publicKey.Raw32(), conn.PacketTransport) {
		t.Fatal("old queued packet accepted")
	}
	rx.FromPeer(ep.publicKey.Raw32())
	if ep.lastRecvUDPAny.LoadAtomic() != 0 || ep.lastRecvWG.LoadAtomic() != 0 {
		t.Fatal("post-WG stale health")
	}
	if _, ok := c.peerMap.endpointForEpAddr(a); ok {
		t.Fatal("stale cache association")
	}
	derp := &authenticatedEndpoint{c: c, gate: c.authenticatedPathGate.Load(), context: conn.TransportContext{Kind: conn.TransportDERP, Generation: c.pathGeneration(), DERPSource: key.NewNode().Public().Raw32()}}
	if conn.AllowAuthenticatedPeer(derp, ep.publicKey.Raw32(), conn.PacketTransport) {
		t.Fatal("DERP source spoof")
	}
}

func TestPathPolicyRelayProvenance(t *testing.T) {
	c, ep := policyFixture(t, 2)
	a := epAddr{ap: netip.MustParseAddrPort("192.0.2.13:40000")}
	a.vni.Set(9)
	unverified := c.authenticatedUDPEndpoint(a, c.authenticatedPathGate.Load())
	if conn.AllowAuthenticatedPeer(unverified, ep.publicKey.Raw32(), conn.PacketTransport) {
		t.Fatal("bare VNI authorized")
	}
	ep.udpRelayEndpointReady(addrQuality{epAddr: a, relaySession: 1, relayServerDisco: key.NewDisco().Public(), policyGeneration: c.pathGeneration()})
	verified := c.authenticatedUDPEndpoint(a, c.authenticatedPathGate.Load())
	if !conn.AllowAuthenticatedPeer(verified, ep.publicKey.Raw32(), conn.PacketTransport) {
		t.Fatal("verified terminal session rejected")
	}
	if conn.AllowAuthenticatedPeer(verified, key.NewNode().Public().Raw32(), conn.PacketTransport) {
		t.Fatal("wrong terminal")
	}
	setPolicyBits(t, c, 1)
	if conn.AllowAuthenticatedPeer(verified, ep.publicKey.Raw32(), conn.PacketTransport) {
		t.Fatal("revoked session")
	}
}

func TestPathPolicyIdentityRemovalAndUnmatched(t *testing.T) {
	c, ep := policyFixture(t, 4)
	other := key.NewNode().Public()
	c.mu.Lock()
	c.peersByID[2] = (&tailcfg.Node{ID: 2, StableID: "other", Key: other, DiscoKey: key.NewDisco().Public()}).View()
	c.refreshPathPolicyLocked()
	c.mu.Unlock()
	if !c.decidePath(other, featurepolicy.PeerRelay, featurepolicy.PathSend, c.pathGeneration()) {
		t.Fatal("unmatched peer changed")
	}
	c.mu.Lock()
	delete(c.peersByID, 1)
	c.refreshPathPolicyLocked()
	c.mu.Unlock()
	if c.decidePath(ep.publicKey, featurepolicy.Direct, featurepolicy.PathReceive, c.pathGeneration()) {
		t.Fatal("deleted key retained")
	}
	c.mu.Lock()
	c.peersByID[1] = (&tailcfg.Node{ID: 1, StableID: "new-registration", Key: ep.publicKey, DiscoKey: ep.disco.Load().key}).View()
	c.refreshPathPolicyLocked()
	c.mu.Unlock()
	if c.pathPeer(ep.publicKey) != nil {
		t.Fatal("new registration inherited rule")
	}
}

func TestPathPolicyProbeSweepCountsOnce(t *testing.T) {
	c, ep := policyFixture(t, 5)
	g := c.pathGeneration()
	now := mono.Now()
	a := epAddr{ap: netip.MustParseAddrPort("192.0.2.14:1234")}
	ep.mu.Lock()
	defer ep.mu.Unlock()
	ep.observePathLocked(a, true, g)
	for range 4 {
		ep.observeProbeLocked(sentPing{to: a, at: now, policyGeneration: g}, false)
	}
	if got := c.pathPeer(ep.publicKey).status.Load(); got.State != featurepolicy.Suspect || got.Active != featurepolicy.Direct {
		t.Fatal("one sweep counted multiple failures", got)
	}
	ep.observeProbeLocked(sentPing{to: a, at: now.Add(time.Second), policyGeneration: g}, true)
	ep.observeProbeLocked(sentPing{to: a, at: now.Add(time.Second), policyGeneration: g}, false)
	if c.pathPeer(ep.publicKey).status.Load().State != featurepolicy.Active {
		t.Fatal("failed sibling overrode success")
	}
}

func TestPathPolicyDefaultOffReceiveAndQueuedEnable(t *testing.T) {
	c, ep := pathTestConn(t)
	c.authenticatedPathGate.Store(&authenticatedPathGate{allow: c.allowPolicyAuthenticated, livePolicy: true})
	a := epAddr{ap: netip.MustParseAddrPort("192.0.2.16:1234")}
	c.peerMap.setNodeKeyForEpAddr(a, ep.publicKey)
	rx, _, _, ok := c.receiveIP(make([]byte, 148), a.ap, &epAddrEndpointCache{})
	if !ok {
		t.Fatal("receive")
	}
	if _, ok := rx.(*policyPassthroughEndpoint); !ok {
		t.Fatalf("no default-off context: %T", rx)
	}
	if ep.lastRecvUDPAny.LoadAtomic() == 0 || ep.lastRecvWG.LoadAtomic() == 0 {
		t.Fatal("default-off upstream activity lost")
	}
	if !conn.AllowAuthenticatedPeer(rx, ep.publicKey.Raw32(), conn.PacketTransport) {
		t.Fatal("default-off denied")
	}
	c.peersByID = map[tailcfg.NodeID]tailcfg.NodeView{1: (&tailcfg.Node{ID: 1, StableID: "target", Key: ep.publicKey, DiscoKey: ep.disco.Load().key}).View()}
	setPolicyBits(t, c, 1)
	before := ep.lastRecvUDPAny.LoadAtomic()
	if conn.AllowAuthenticatedPeer(rx, ep.publicKey.Raw32(), conn.PacketTransport) {
		t.Fatal("queued default-off packet survived enable")
	}
	rx.(conn.InitiationAwareEndpoint).InitiationMessagePublicKey(ep.publicKey.Raw32())
	rx.(conn.PeerAwareEndpoint).FromPeer(ep.publicKey.Raw32())
	if ep.lastRecvUDPAny.LoadAtomic() != before {
		t.Fatal("old pre-auth callback updated enabled health")
	}
}

func TestPathPolicyDefaultOffCacheAllocations(t *testing.T) {
	c, ep := pathTestConn(t)
	c.authenticatedPathGate.Store(&authenticatedPathGate{allow: c.allowPolicyAuthenticated, livePolicy: true})
	a := epAddr{ap: netip.MustParseAddrPort("192.0.2.18:1234")}
	c.peerMap.setNodeKeyForEpAddr(a, ep.publicKey)
	cache := &epAddrEndpointCache{}
	packet := make([]byte, 148)
	first, _, _, _ := c.receiveIP(packet, a.ap, cache)
	context := first.(conn.AuthenticatedPathEndpoint).TransportContext()
	if n := testing.AllocsPerRun(100, func() { c.receiveIP(packet, a.ap, cache) }); n != 0 {
		t.Fatalf("steady default-off receive allocated %v", n)
	}
	// Changing the cache source replaces a wrapper; it never mutates the old one.
	other := epAddr{ap: netip.MustParseAddrPort("192.0.2.19:1234")}
	c.peerMap.setNodeKeyForEpAddr(other, ep.publicKey)
	c.receiveIP(packet, other.ap, cache)
	if first.(conn.AuthenticatedPathEndpoint).TransportContext() != context {
		t.Fatal("cached ingress context mutated")
	}
}

func TestPathPolicyBareVNIDiscoPingNoHealth(t *testing.T) {
	c, ep := policyFixture(t, 2)
	src := epAddr{ap: netip.MustParseAddrPort("192.0.2.21:40000")}
	src.vni.Set(7)
	di := &discoInfo{discoKey: ep.disco.Load().key}
	c.mu.Lock()
	c.handlePingLocked(&disco.Ping{NodeKey: ep.publicKey, TxID: stun.NewTxID()}, src, di, key.NodePublic{})
	c.mu.Unlock()
	select {
	case <-c.relayManager.runLoopStoppedCh:
	case <-time.After(time.Second):
		t.Fatal("unverified relay work did not stop")
	}
	if !di.lastPingTime.IsZero() || ep.lastRecvUDPAny.LoadAtomic() != 0 || len(ep.policyPingIDs) != 0 {
		t.Fatal("bare VNI authenticated relay health")
	}
}

func TestPathPolicyReRegistrationCannotReauthorizeQueuedIdentity(t *testing.T) {
	c, ep := policyFixture(t, 4)
	old := c.pathGeneration()
	c.mu.Lock()
	delete(c.peersByID, 1)
	c.refreshPathPolicyLocked()
	c.peersByID[1] = (&tailcfg.Node{ID: 1, StableID: "new-registration", Key: ep.publicKey, DiscoKey: ep.disco.Load().key}).View()
	c.refreshPathPolicyLocked()
	c.mu.Unlock()
	if c.pathPeer(ep.publicKey) != nil {
		t.Fatal("new registration inherited rule")
	}
	if c.decidePath(ep.publicKey, featurepolicy.Direct, featurepolicy.PathReceive, old) {
		t.Fatal("queued old identity became authorized as unmatched")
	}
	if !c.decidePath(ep.publicKey, featurepolicy.Direct, featurepolicy.PathReceive, c.pathGeneration()) {
		t.Fatal("current unmatched identity denied")
	}
}

func TestPathPolicyRelayGrantOutlivesProbeInterval(t *testing.T) {
	c, ep := policyFixture(t, 2)
	a := epAddr{ap: netip.MustParseAddrPort("192.0.2.23:40000")}
	a.vni.Set(13)
	ep.udpRelayEndpointReady(addrQuality{epAddr: a, relaySession: 2, policyGeneration: c.pathGeneration(), policyRelayLifetime: 5 * time.Minute})
	candidate := ep.policyCandidates[featurepolicy.PeerRelay]
	if candidate.policyTrustUntil.Sub(mono.Now()) < time.Minute {
		t.Fatal("used UDP trust window instead of server grant lifetime")
	}
	// UDP bestAddr trust expiration does not revoke a still-valid authenticated
	// relay grant between 10-second policy probes.
	ep.trustBestAddrUntil = mono.Now().Add(-time.Second)
	rx := c.authenticatedUDPEndpoint(a, c.authenticatedPathGate.Load())
	if !conn.AllowAuthenticatedPeer(rx, ep.publicKey.Raw32(), conn.PacketTransport) {
		t.Fatal("periodic relay receive hole")
	}
	candidate.policyTrustUntil = mono.Now().Add(-time.Second)
	ep.policyCandidates[featurepolicy.PeerRelay] = candidate
	expired := c.authenticatedUDPEndpoint(a, c.authenticatedPathGate.Load())
	if conn.AllowAuthenticatedPeer(expired, ep.publicKey.Raw32(), conn.PacketTransport) {
		t.Fatal("expired grant authorized")
	}
}

func TestPathPolicyReplacedRelaySessionRejectsQueuedPacket(t *testing.T) {
	c, ep := policyFixture(t, 2)
	a := epAddr{ap: netip.MustParseAddrPort("192.0.2.25:40000")}
	a.vni.Set(14)
	server := key.NewDisco().Public()
	g := c.pathGeneration()
	ep.udpRelayEndpointReady(addrQuality{epAddr: a, relaySession: 1, relayServerDisco: server, policyGeneration: g, policyRelayLifetime: time.Minute})
	old := c.authenticatedUDPEndpoint(a, c.authenticatedPathGate.Load()).(*authenticatedEndpoint)
	if !conn.AllowAuthenticatedPeer(old, ep.publicKey.Raw32(), conn.PacketTransport) {
		t.Fatal("initial session")
	}
	ep.udpRelayEndpointReady(addrQuality{epAddr: a, relaySession: 2, relayServerDisco: server, policyGeneration: g, policyRelayLifetime: time.Minute})
	if conn.AllowAuthenticatedPeer(old, ep.publicKey.Raw32(), conn.PacketTransport) {
		t.Fatal("replaced relay session still authorized")
	}
	before := ep.lastRecvUDPAny.LoadAtomic()
	old.FromPeer(ep.publicKey.Raw32())
	if ep.lastRecvUDPAny.LoadAtomic() != before {
		t.Fatal("late accepted callback refreshed old session")
	}
	fresh := c.authenticatedUDPEndpoint(a, c.authenticatedPathGate.Load())
	if !conn.AllowAuthenticatedPeer(fresh, ep.publicKey.Raw32(), conn.PacketTransport) {
		t.Fatal("replacement session rejected")
	}
}

func TestPathPolicyReplacedRelayRejectsOldPongAndSend(t *testing.T) {
	c, ep := policyFixture(t, 2)
	a := epAddr{ap: netip.MustParseAddrPort("192.0.2.26:40000")}
	a.vni.Set(15)
	g := c.pathGeneration()
	ep.udpRelayEndpointReady(addrQuality{epAddr: a, relaySession: 2, policyGeneration: g, policyRelayLifetime: time.Minute})
	tx := stun.NewTxID()
	sp := sentPing{to: a, at: mono.Now(), timer: time.NewTimer(time.Hour), policyGeneration: g, policyRelaySession: 1}
	ep.sentPing[tx] = sp
	before := ep.lastRecvUDPAny.LoadAtomic()
	c.mu.Lock()
	ep.handlePongConnLocked(&disco.Pong{TxID: tx}, &discoInfo{discoKey: ep.disco.Load().key}, a)
	c.mu.Unlock()
	if ep.lastRecvUDPAny.LoadAtomic() != before {
		t.Fatal("old session Pong updated health")
	}
	if c.allowPathSend(pathSendContext{peer: ep.publicKey, generation: g, purpose: featurepolicy.PathProbe, relaySession: 1}, featurepolicy.PeerRelay) {
		t.Fatal("old session probe sent")
	}
	ep.discoPingTimeout(tx)
	if c.pathPeer(ep.publicKey).status.Load().State != featurepolicy.Active {
		t.Fatal("old session timeout damaged new health")
	}
}
