// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"errors"
	"github.com/tailscale/wireguard-go/conn"
	"go4.org/mem"
	"tailscale.com/featurepolicy"
	"tailscale.com/tstime/mono"
	"tailscale.com/types/key"
)

// AuthenticatedPathGate is an injection seam, not a path policy. The predicate
// must only read immutable/atomic state: no locks, IO, or health side effects.
// It can see authenticated replays (before replay acceptance). A transport
// claim is never the authenticated peer identity supplied in the first argument.
type AuthenticatedPathGate func([32]byte, conn.PacketKind, conn.TransportContext) bool

type authenticatedPathGate struct {
	allow      AuthenticatedPathGate
	generation uint64
	livePolicy bool
}

// SetAuthenticatedPathGate installs the receive seam before Bind.Open starts
// any receives. It is NOT a live enable/disable API: pre-existing queued packets
// cannot acquire context retroactively. R8 must install once at startup and
// atomically publish policy through the predicate, with its own epoch fencing.
// A nil predicate leaves the original upstream paths intact. Calls after the
// first Bind.Open fail, even after Close, because old queues may still exist.
func (c *Conn) SetAuthenticatedPathGate(generation uint64, allow AuthenticatedPathGate) error {
	c.bind.mu.Lock()
	defer c.bind.mu.Unlock()
	if c.bind.everOpened {
		return errors.New("magicsock: authenticated path gate must be installed before first Bind.Open")
	}
	if allow == nil {
		c.authenticatedPathGate.Store(nil)
		return nil
	}
	c.authenticatedPathGate.Store(&authenticatedPathGate{allow: allow, generation: generation})
	return nil
}

// authenticatedEndpoint is allocated per packet, never recycled with a receive
// batch. Its embedded Endpoint exists only for cookie addressing and legacy
// FromPeer handling. Neither the gate nor context reads shared endpoint state.
type authenticatedEndpoint struct {
	conn.Endpoint
	c       *Conn
	gate    *authenticatedPathGate
	context conn.TransportContext
}

var _ conn.AuthenticatedPathEndpoint = (*authenticatedEndpoint)(nil)
var _ conn.PeerAwareEndpoint = (*authenticatedEndpoint)(nil)

func (e *authenticatedEndpoint) TransportContext() conn.TransportContext { return e.context }

func (e *authenticatedEndpoint) allowAuthenticatedPeer(k [32]byte, kind conn.PacketKind, ctx conn.TransportContext) bool {
	return e.allowAuthenticatedPeerIn(e.c.pathPolicy.Load(), k, kind, ctx)
}

func (e *authenticatedEndpoint) allowAuthenticatedPeerIn(s *pathPolicyTable, k [32]byte, kind conn.PacketKind, ctx conn.TransportContext) bool {
	if e.gate.livePolicy && (s == nil || !s.enabled) {
		return true
	}
	if e.gate.livePolicy {
		pub := key.NodePublicFromRaw32(mem.B(k[:]))
		if s.pathPeer(pub) == nil {
			// Unmatched peers retain upstream transports. Still fence a removed or
			// re-registered identity before recording any activity for the real peer.
			return s.decidePath(pub, featurepolicy.Direct, featurepolicy.PathReceive, ctx.Generation)
		}
	}
	// The DERP server's source label must agree with the Noise identity. This
	// check is active only when the seam is installed; default-off is upstream.
	if ctx.Kind == conn.TransportDERP && ctx.DERPSource != k {
		return false
	}
	if ctx.RelayVerified && ctx.RelayPeer != k {
		return false
	}
	if e.gate.livePolicy {
		return s.allowPolicyAuthenticated(k, kind, ctx)
	}
	return e.gate.allow(k, kind, ctx)
}

// No InitiationAwareEndpoint implementation: lazyEndpoint's pre-auth callback
// updates health. JIT creation still happens in wireguard Device.LookupPeer.
// FromPeer is called only after authentication AND acceptance (including replay
// acceptance), outside WireGuard locks, and retains lazyEndpoint's association.
func (e *authenticatedEndpoint) FromPeer(k [32]byte) {
	if e.gate.livePolicy {
		e.c.mu.Lock()
		defer e.c.mu.Unlock()
		if !e.allowAuthenticatedPeer(k, conn.PacketTransport, e.context) {
			return
		}
		pub := key.NodePublicFromRaw32(mem.B(k[:]))
		ep, ok := e.c.peerMap.endpointForNodeKey(pub)
		if !ok {
			return
		}
		src := epAddr{ap: e.context.Endpoint}
		if e.context.Kind == conn.TransportRelay {
			src.vni.Set(e.context.RelayVNI)
		}
		now := mono.Now()
		e.c.pathPolicy.Load().countConfirmation(pub, transportEvidencePath(e.context.Kind), evidenceLastRecv)
		if e.context.Kind != conn.TransportDERP {
			e.c.peerMap.setNodeKeyForEpAddr(src, pub)
			ep.lastRecvUDPAny.StoreAtomic(now)
		}
		ep.policyWGAccepted(src, e.context.Generation)
		ep.noteRecvActivity(src, now)
		return
	}

	if e.gate.livePolicy && !e.allowAuthenticatedPeer(k, conn.PacketTransport, e.context) {
		return
	}
	if ep, ok := e.Endpoint.(conn.PeerAwareEndpoint); ok {
		ep.FromPeer(k)
	}
	pub := key.NodePublicFromRaw32(mem.B(k[:]))
	e.c.mu.Lock()
	ep, ok := e.c.peerMap.endpointForNodeKey(pub)
	e.c.mu.Unlock()
	if !ok {
		return
	}
	src := epAddr{ap: e.context.Endpoint}
	if e.context.Kind == conn.TransportRelay {
		src.vni.Set(e.context.RelayVNI)
	}
	now := mono.Now()
	if e.context.Kind != conn.TransportDERP {
		ep.lastRecvUDPAny.StoreAtomic(now)
	}
	ep.noteRecvActivity(src, now)
}

func (c *Conn) authenticatedUDPEndpoint(src epAddr, gate *authenticatedPathGate) conn.Endpoint {
	ctx := conn.TransportContext{Kind: conn.TransportDirect, Endpoint: src.ap, Generation: gate.generation}
	if gate.livePolicy {
		ctx.Generation = c.pathGeneration()
	}
	c.mu.Lock()
	ep, known := c.peerMap.endpointForEpAddr(src)
	c.mu.Unlock()
	if src.vni.IsSet() {
		ctx.Kind = conn.TransportRelay
		ctx.RelayVNI = src.vni.Get()
		// A Geneve VNI alone is untrusted. Capture provenance only when an
		// existing successful relay handshake matches this exact path.
		if known {
			ep.mu.Lock()
			best := ep.bestAddr
			trust := ep.trustBestAddrUntil
			if gate.livePolicy && c.pathPeer(ep.publicKey) != nil {
				best = ep.policyCandidates[featurepolicy.PeerRelay]
				trust = best.policyTrustUntil
			}
			if best.epAddr == src && best.relaySession != 0 && mono.Now().Before(trust) {
				ctx.RelayVerified = true
				ctx.RelaySession = best.relaySession
				ctx.RelayServer = best.relayServerDisco.Raw32()
				ctx.RelayPeer = ep.publicKey.Raw32()
			}
			ep.mu.Unlock()
		}
	}
	return &authenticatedEndpoint{Endpoint: &lazyEndpoint{c: c, maybeEP: ep, src: src}, c: c, gate: gate, context: ctx}
}

// policyPassthroughEndpoint retains the upstream default-off health callbacks
// while still owning an ingress context, so activation can reject queued packets.
// It is never created while path policy is enabled.
type policyPassthroughEndpoint struct {
	*authenticatedEndpoint
	legacyFromPeer bool   // upstream calls FromPeer only for transport
	source         epAddr // immutable; permits default-off cache reuse without changing context
}

func (e *policyPassthroughEndpoint) FromPeer(k [32]byte) {
	if e.c.pathEnabled() {
		e.authenticatedEndpoint.FromPeer(k)
		return
	}
	if !e.legacyFromPeer {
		return
	}
	// The default-off underlying lazyEndpoint only associates an authenticated
	// address; do it under the publication lock to prevent activation racing it.
	e.c.mu.Lock()
	defer e.c.mu.Unlock()
	if e.c.pathEnabled() {
		return
	}
	if le, ok := e.Endpoint.(*lazyEndpoint); ok {
		pub := key.NodePublicFromRaw32(mem.B(k[:]))
		if le.maybeEP != nil && le.maybeEP.publicKey == pub {
			return
		}
		if _, ok := e.c.peerMap.endpointForNodeKey(pub); ok {
			e.c.peerMap.setNodeKeyForEpAddr(le.src, pub)
		}
	}
}

func (e *policyPassthroughEndpoint) InitiationMessagePublicKey(k [32]byte) {
	le, ok := e.Endpoint.(*lazyEndpoint)
	if !ok {
		return
	}
	pub := key.NodePublicFromRaw32(mem.B(k[:]))
	if le.maybeEP != nil && le.maybeEP.publicKey == pub {
		return
	}
	e.c.mu.Lock()
	defer e.c.mu.Unlock()
	if e.c.pathEnabled() {
		return
	} // this is a pre-authentication callback
	ep, ok := e.c.peerMap.endpointForNodeKey(pub)
	if !ok {
		return
	}
	now := mono.Now()
	ep.lastRecvUDPAny.StoreAtomic(now)
	ep.noteRecvActivity(le.src, now)
}
