// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package magicsock

import (
	"sync/atomic"

	"github.com/tailscale/wireguard-go/conn"
	"go4.org/mem"
	"tailscale.com/featurepolicy"
	"tailscale.com/types/key"
	"tailscale.com/util/clientmetric"
)

// Fixed dimensions only. These are denied decisions, not unique packets:
// enqueue and final-send checks may both run, and authenticated rejects can
// include replay candidates. No replay acceptance or health claim is made.
var pathDropKinds = [3]string{"send", "probe", "receive"}
var pathDropPaths = [4]string{"direct", "peer_relay", "derp", "unknown"}
var pathDropMetrics = func() [3][4]*clientmetric.Metric {
	var metrics [3][4]*clientmetric.Metric
	for i, k := range pathDropKinds {
		for j, p := range pathDropPaths {
			metrics[i][j] = clientmetric.NewCounter("unified_path_" + k + "_" + p + "_policy_deny")
		}
	}
	return metrics
}()

type pathDropCounters [3][4]atomic.Uint64

func (c *Conn) countPathDeny(kind int, p featurepolicy.Path) {
	if c == nil {
		return
	}
	j := 3
	switch p {
	case featurepolicy.Direct:
		j = 0
	case featurepolicy.PeerRelay:
		j = 1
	case featurepolicy.DERP:
		j = 2
	}
	c.pathDrops[kind][j].Add(1)
	pathDropMetrics[kind][j].Add(1)
}
func (c *Conn) PathPolicyDropCounters() map[string]uint64 {
	out := make(map[string]uint64, 12)
	for i, k := range pathDropKinds {
		for j, p := range pathDropPaths {
			out[k+"/"+p+"/policy_deny"] = c.pathDrops[i][j].Load()
		}
	}
	return out
}

// Keep the policy predicate pure. Only its outer receive boundary counts
// decisions, using atomic increments; no locks, allocations, I/O or health writes.
func (e *authenticatedEndpoint) AllowAuthenticatedPeer(k [32]byte, kind conn.PacketKind, ctx conn.TransportContext) bool {
	s := e.c.pathPolicy.Load()
	allowed := e.allowAuthenticatedPeerIn(s, k, kind, ctx)
	if e.gate.livePolicy {
		s.countDecision(key.NodePublicFromRaw32(mem.B(k[:])), transportEvidencePath(ctx.Kind), 2, allowed)
	}
	if !allowed && e.gate.livePolicy {
		p := featurepolicy.Path("")
		switch ctx.Kind {
		case conn.TransportDirect:
			p = featurepolicy.Direct
		case conn.TransportDERP:
			p = featurepolicy.DERP
		case conn.TransportRelay:
			p = featurepolicy.PeerRelay
		}
		e.c.countPathDeny(2, p)
	}
	return allowed
}

// PathPolicyAvailable reports whether the permanent authenticated receive seam
// is installed. It does not change policy or establish transport health.
func (c *Conn) PathPolicyAvailable() bool {
	gate := c.authenticatedPathGate.Load()
	return gate != nil && gate.livePolicy
}
