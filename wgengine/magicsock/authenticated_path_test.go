// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"encoding/binary"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/tailscale/wireguard-go/conn"
	"github.com/tailscale/wireguard-go/device"
	"tailscale.com/health"
	"tailscale.com/net/packet"
	"tailscale.com/tstime/mono"
	"tailscale.com/types/key"
	"tailscale.com/util/eventbus/eventbustest"
)

func pathTestConn(t *testing.T) (*Conn, *endpoint) {
	t.Helper()
	c := newConn(t.Logf)
	c.metrics = &metrics{}
	c.havePrivateKey.Store(true)
	ep := &endpoint{c: c, nodeID: 1, publicKey: key.NewNode().Public(), nodeAddr: netip.MustParseAddr("100.64.0.1")}
	ep.disco.Store(&endpointDisco{key: key.NewDisco().Public()})
	c.peerMap.upsertEndpoint(ep, key.DiscoPublic{})
	return c, ep
}

func TestAuthenticatedPathUDPContext(t *testing.T) {
	c, peer := pathTestConn(t)
	addr := netip.MustParseAddrPort("192.0.2.1:40000")
	src := epAddr{ap: addr}
	c.peerMap.setNodeKeyForEpAddr(src, peer.publicKey)
	c.SetAuthenticatedPathGate(17, func([32]byte, conn.PacketKind, conn.TransportContext) bool { return false })
	packet := make([]byte, device.MessageInitiationSize)
	binary.LittleEndian.PutUint32(packet, device.MessageInitiationType)
	cache := &epAddrEndpointCache{epAddr: src, de: peer, gen: peer.numStopAndReset()}
	first, _, _, ok := c.receiveIP(packet, addr, cache)
	if !ok {
		t.Fatal("receive")
	}
	rx := first.(*authenticatedEndpoint)
	if _, ok := first.(conn.InitiationAwareEndpoint); ok {
		t.Fatal("pre-auth health callback exposed")
	}
	if !peer.lastRecvWG.IsZero() || !peer.lastRecvUDPAny.IsZero() {
		t.Fatal("pre-auth cached peer health update")
	}
	if conn.AllowAuthenticatedPeer(first, peer.publicKey.Raw32(), conn.PacketInitiation) {
		t.Fatal("deny ignored")
	}
	saved := rx.TransportContext()
	// Simulate subsequent batch slots and cache reuse while earlier packets are
	// still pending on wireguard's asynchronous queues.
	for i := range 128 {
		nextAddr := netip.AddrPortFrom(addr.Addr(), uint16(41000+i))
		next, _, _, ok := c.receiveIP(packet, nextAddr, cache)
		if !ok || next == first || next.(*authenticatedEndpoint).context.Endpoint != nextAddr {
			t.Fatal("context shared across slots")
		}
	}
	cache.epAddr = epAddr{}
	cache.de = nil
	copied := rx.TransportContext()
	copied.Generation++
	if rx.TransportContext() != saved || saved.Generation != 17 || saved.Endpoint != addr {
		t.Fatal("context mutated")
	}
	if !peer.lastRecvWG.IsZero() {
		t.Fatal("denied packet updated health")
	}
	// WireGuard invokes FromPeer after replay acceptance, outside handshake locks.
	rx.FromPeer(peer.publicKey.Raw32())
	if peer.lastRecvWG.IsZero() || peer.lastRecvUDPAny.IsZero() {
		t.Fatal("accepted packet lost legacy health behavior")
	}
}

func TestAuthenticatedPathRelayProvenance(t *testing.T) {
	c, peer := pathTestConn(t)
	c.SetAuthenticatedPathGate(3, func([32]byte, conn.PacketKind, conn.TransportContext) bool { return true })
	src := epAddr{ap: netip.MustParseAddrPort("192.0.2.2:40000")}
	src.vni.Set(9)
	raw := make([]byte, packet.GeneveFixedHeaderLength+device.MessageInitiationSize)
	h := packet.GeneveHeader{Protocol: packet.GeneveProtocolWireGuard, VNI: src.vni}
	if err := h.Encode(raw); err != nil {
		t.Fatal(err)
	}
	binary.LittleEndian.PutUint32(raw[packet.GeneveFixedHeaderLength:], device.MessageInitiationType)
	rx, _, encap, ok := c.receiveIP(append([]byte(nil), raw...), src.ap, &epAddrEndpointCache{})
	if !ok || !encap {
		t.Fatal("Geneve receive")
	}
	ctx := rx.(*authenticatedEndpoint).context
	if ctx.Kind != conn.TransportRelay || ctx.RelayVNI != 9 || ctx.RelayVerified {
		t.Fatal("untrusted VNI treated as verified session")
	}
	c.peerMap.setNodeKeyForEpAddr(src, peer.publicKey)
	peer.bestAddr = addrQuality{epAddr: src, relaySession: 42, relayServerDisco: key.NewDisco().Public()}
	peer.trustBestAddrUntil = mono.Now().Add(time.Minute)
	verified := c.authenticatedUDPEndpoint(src, c.authenticatedPathGate.Load()).(*authenticatedEndpoint)
	if !verified.context.RelayVerified || verified.context.RelaySession != 42 || verified.context.RelayPeer != peer.publicKey.Raw32() {
		t.Fatal("missing relay binding")
	}
	if conn.AllowAuthenticatedPeer(verified, [32]byte{1}, conn.PacketTransport) {
		t.Fatal("relay terminal peer spoof accepted")
	}
	peer.bestAddr = addrQuality{}
	if !verified.context.RelayVerified || verified.context.RelaySession != 42 {
		t.Fatal("inflight relay context changed")
	}
	fresh := c.authenticatedUDPEndpoint(src, c.authenticatedPathGate.Load()).(*authenticatedEndpoint)
	if fresh.context.RelayVerified {
		t.Fatal("stale best path reused")
	}
}

func TestAuthenticatedPathDERPSource(t *testing.T) {
	c, peer := pathTestConn(t)
	c.health = health.NewTracker(eventbustest.NewBus(t))
	c.derpRecvCh = make(chan derpReadResult, 1)
	c.SetAuthenticatedPathGate(23, func([32]byte, conn.PacketKind, conn.TransportContext) bool { return true })
	raw := make([]byte, device.MessageTransportSize)
	binary.LittleEndian.PutUint32(raw, device.MessageTransportType)
	c.derpRecvCh <- derpReadResult{regionID: 900, n: len(raw), src: peer.publicKey, copyBuf: func(dst []byte) int { return copy(dst, raw) }}
	bind := &connBind{Conn: c}
	eps := make([]conn.Endpoint, 1)
	if n, err := bind.receiveDERP([][]byte{make([]byte, 2048)}, make([]int, 1), eps); err != nil || n != 1 {
		t.Fatalf("receiveDERP: %d %v", n, err)
	}
	rx := eps[0].(*authenticatedEndpoint)
	if rx.context.DERPRegion != 900 || rx.context.Generation != 23 || !peer.lastRecvWG.IsZero() {
		t.Fatal("DERP pre-auth health/context")
	}
	if conn.AllowAuthenticatedPeer(rx, [32]byte{1}, conn.PacketKeepalive) {
		t.Fatal("DERP source impersonation accepted")
	}
	if !conn.AllowAuthenticatedPeer(rx, peer.publicKey.Raw32(), conn.PacketKeepalive) {
		t.Fatal("correct DERP identity rejected")
	}
	rx.FromPeer(peer.publicKey.Raw32())
	if peer.lastRecvWG.IsZero() || !peer.lastRecvUDPAny.IsZero() {
		t.Fatal("DERP health confused with UDP")
	}
}

func TestAuthenticatedPathPredicateDoesNotAcquireConnLocks(t *testing.T) {
	c, peer := pathTestConn(t)
	c.SetAuthenticatedPathGate(1, func([32]byte, conn.PacketKind, conn.TransportContext) bool { return true })
	rx := c.authenticatedUDPEndpoint(epAddr{ap: netip.MustParseAddrPort("192.0.2.3:1234")}, c.authenticatedPathGate.Load())
	c.mu.Lock()
	peer.mu.Lock()
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			for range 100 {
				if !conn.AllowAuthenticatedPeer(rx, peer.publicKey.Raw32(), conn.PacketTransport) {
					t.Error("gate")
				}
			}
		})
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Error("gate acquired Conn/endpoint lock")
	}
	peer.mu.Unlock()
	c.mu.Unlock()
}

func TestAuthenticatedPathInstallationFence(t *testing.T) {
	c, _ := pathTestConn(t)
	if err := c.SetAuthenticatedPathGate(1, func([32]byte, conn.PacketKind, conn.TransportContext) bool { return true }); err != nil {
		t.Fatal(err)
	}
	original := c.authenticatedPathGate.Load()
	// Equivalent to first Open's lifecycle marker, without opening host sockets.
	c.bind.mu.Lock()
	c.bind.everOpened = true
	c.bind.mu.Unlock()
	if err := c.SetAuthenticatedPathGate(2, nil); err == nil {
		t.Fatal("late disable accepted")
	}
	if original != c.authenticatedPathGate.Load() {
		t.Fatal("failed install changed gate")
	}
}
