// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package magicsock

import (
	"net/netip"
	"sync"
	"testing"

	"github.com/tailscale/wireguard-go/conn"
	"tailscale.com/disco"
	"tailscale.com/featurepolicy"
	"tailscale.com/net/stun"
	"tailscale.com/tailcfg"
	"tailscale.com/tstime/mono"
	"tailscale.com/types/key"
)

func TestPathEvidenceForbiddenAndControls(t *testing.T) {
	c, ep := policyFixture(t, 1)
	other := key.NewNode().Public()
	c.mu.Lock()
	c.peersByID[2] = (&tailcfg.Node{ID: 2, StableID: "control", Key: other}).View()
	c.refreshPathPolicyLocked()
	c.mu.Unlock()
	g := c.pathGeneration()
	for _, kind := range []conn.TransportKind{conn.TransportDirect, conn.TransportRelay} {
		p := transportEvidencePath(kind)
		a := epAddr{ap: netip.MustParseAddrPort("192.0.2.1:1234")}
		if kind == conn.TransportRelay {
			a.vni.Set(7)
		}
		ctx := conn.TransportContext{Kind: kind, Endpoint: a.ap, RelayVNI: 7, Generation: g}
		rx := &authenticatedEndpoint{c: c, gate: c.authenticatedPathGate.Load(), context: ctx}
		for _, packet := range []conn.PacketKind{conn.PacketInitiation, conn.PacketResponse, conn.PacketTransport, conn.PacketKeepalive} {
			if rx.AllowAuthenticatedPeer(ep.publicKey.Raw32(), packet, ctx) {
				t.Fatal("forbidden receive")
			}
		}
		rx.FromPeer(ep.publicKey.Raw32())
		for _, purpose := range []featurepolicy.PathPurpose{featurepolicy.PathSend, featurepolicy.PathProbe} {
			if c.allowPathSend(c.newPathSend(ep.publicKey, purpose), p) {
				t.Fatal("forbidden send")
			}
		}
		// Actual Pong handler must not confirm a forbidden or stale probe.
		tx := stun.NewTxID()
		ep.sentPing[tx] = sentPing{to: a, at: mono.Now(), policyGeneration: g}
		c.mu.Lock()
		ep.handlePongConnLocked(&disco.Pong{TxID: tx}, nil, a)
		c.mu.Unlock()
		delete(ep.sentPing, tx)
	}
	if !ep.lastRecvUDPAny.IsZero() || !ep.lastRecvWG.IsZero() {
		t.Fatal("forbidden lastRecv")
	}
	// Unmatched C2 retains default direct send and receive decisions.
	if !c.allowPathSend(c.newPathSend(other, featurepolicy.PathSend), featurepolicy.Direct) {
		t.Fatal("control send")
	}
	ctx := conn.TransportContext{Kind: conn.TransportDirect, Generation: g}
	rx := &authenticatedEndpoint{c: c, gate: c.authenticatedPathGate.Load(), context: ctx}
	if !rx.AllowAuthenticatedPeer(other.Raw32(), conn.PacketTransport, ctx) {
		t.Fatal("control receive")
	}
	// DERP accepted receive + actual post-acceptance activity callback.
	ctx = conn.TransportContext{Kind: conn.TransportDERP, Endpoint: ep.derpAddr, Generation: g, DERPSource: ep.publicKey.Raw32()}
	rx.context = ctx
	if !rx.AllowAuthenticatedPeer(ep.publicKey.Raw32(), conn.PacketTransport, ctx) {
		t.Fatal("DERP receive")
	}
	rx.FromPeer(ep.publicKey.Raw32())
	ep.mu.Lock()
	ep.observePathLocked(epAddr{ap: ep.derpAddr}, true, g)
	ep.mu.Unlock()
	if !c.allowPathSend(c.newPathSend(ep.publicKey, featurepolicy.PathSend), featurepolicy.DERP) {
		t.Fatal("DERP send")
	}
	out := c.PathPolicyEvidenceState()
	if out.MatchedPeers != 1 || out.UnmatchedPeers != 1 || len(out.Counters) != 144 {
		t.Fatal(out)
	}
	for _, p := range []string{"direct", "peer_relay"} {
		for _, e := range []string{"send/accepted", "probe/accepted", "receive/accepted", "health/confirmed", "last_recv/confirmed", "pong/confirmed"} {
			if out.Counters["matched/"+p+"/"+e] != 0 {
				t.Fatalf("forbidden %s %s", p, e)
			}
		}
		if out.Counters["matched/"+p+"/receive/rejected"] == 0 {
			t.Fatal("missing rejection")
		}
	}
	for _, cell := range []string{"matched/derp/send/accepted", "matched/derp/receive/accepted", "matched/derp/last_recv/confirmed", "matched/derp/health/confirmed", "unmatched/direct/send/accepted", "unmatched/direct/receive/accepted"} {
		if out.Counters[cell] == 0 {
			t.Fatal("missing positive control", cell)
		}
	}
}

func TestPathEvidenceResetOffAndConcurrent(t *testing.T) {
	c, ep := policyFixture(t, 1)
	old := c.pathPolicy.Load()
	old.countDecision(ep.publicKey, featurepolicy.Direct, 0, false)
	setPolicyBits(t, c, 1)
	if c.pathPolicy.Load() != old || c.PathPolicyEvidenceState().Counters["matched/direct/send/rejected"] != 1 {
		t.Fatal("no-op reset evidence")
	}
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			for range 1000 {
				c.allowPathSend(c.newPathSend(ep.publicKey, featurepolicy.PathProbe), featurepolicy.Direct)
				c.PathPolicyEvidenceState()
			}
		})
	}
	for i := 0; i < 10; i++ {
		setPolicyBits(t, c, 1+(i%2)*3)
	}
	wg.Wait()
	setPolicyBits(t, c, 1)
	setPolicyBits(t, c, 4)
	next := c.pathPolicy.Load()
	if next == old {
		t.Fatal("no publication")
	}
	for _, n := range c.PathPolicyEvidenceState().Counters {
		if n != 0 {
			t.Fatal("generation did not reset")
		}
	}
	old.countDecision(ep.publicKey, featurepolicy.Direct, 0, true)
	if c.PathPolicyEvidenceState().Counters["matched/direct/send/accepted"] != 0 {
		t.Fatal("old work polluted new generation")
	}
	// Verify the forbidden-confirmation audit is not itself a policy filter.
	next.countConfirmation(ep.publicKey, featurepolicy.DERP, evidenceHealth)
	if c.PathPolicyEvidenceState().Counters["matched/derp/health/forbidden"] != 1 {
		t.Fatal("audit filtered violation")
	}
	c.mu.Lock()
	c.pathConfig.Enabled = false
	c.rebuildPathPolicyLocked(false)
	c.mu.Unlock()
	c.allowPathSend(c.newPathSend(ep.publicKey, featurepolicy.PathSend), featurepolicy.Direct)
	c.pathPolicy.Load().countConfirmation(ep.publicKey, featurepolicy.Direct, evidenceLastRecv)
	out := c.PathPolicyEvidenceState()
	if out.Enabled {
		t.Fatal("off")
	}
	for _, n := range out.Counters {
		if n != 0 {
			t.Fatal("off recorded evidence")
		}
	}
}
