// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"sync/atomic"

	"github.com/tailscale/wireguard-go/conn"
	"tailscale.com/featurepolicy"
	"tailscale.com/types/key"
)

// Fixed-size storage, owned by one published table, never shared with its
// successor (even when peer machines are retained). No peer/domain labels.
// Decisions count gate evaluations, NOT packets delivered or successful syscalls.
// WG receive acceptance precedes replay checking; confirmations are counted
// separately at post-acceptance callbacks and Disco/health mutation sites.
type pathEvidenceCounters [3][4][12]atomic.Uint64

const (
	evidenceHealth   = 6
	evidenceLastRecv = 8
	evidencePong     = 10
)

var evidenceScopes = [...]string{"matched", "unmatched", "unknown"}
var evidenceEvents = [...]string{
	"send/accepted", "send/rejected", "probe/accepted", "probe/rejected",
	"receive/accepted", "receive/rejected", "health/confirmed", "health/forbidden",
	"last_recv/confirmed", "last_recv/forbidden", "pong/confirmed", "pong/forbidden",
}

// PathPolicyEvidence is internal debug evidence, not a stable public API.
// Every field/cell is present, including zeroes. Readers must fence Generation
// across their entire observation window; a reset must never imply success.
// Individual cells are atomic; this is not a transaction across all cells.
type PathPolicyEvidence struct {
	Schema         int               `json:"schema"`
	Generation     uint64            `json:"generation"`
	Enabled        bool              `json:"enabled"`
	MatchedPeers   int               `json:"matchedPeers"`
	UnmatchedPeers int               `json:"unmatchedPeers"`
	Counters       map[string]uint64 `json:"counters"`
}

func (s *pathPolicyTable) pathPeer(k key.NodePublic) *pathPeerPolicy {
	if s == nil || !s.enabled {
		return nil
	}
	return s.peers[k]
}

func transportEvidencePath(k conn.TransportKind) featurepolicy.Path {
	switch k {
	case conn.TransportDirect:
		return featurepolicy.Direct
	case conn.TransportRelay:
		return featurepolicy.PeerRelay
	case conn.TransportDERP:
		return featurepolicy.DERP
	}
	return ""
}

func (s *pathPolicyTable) countEvidence(k key.NodePublic, p featurepolicy.Path, event int) {
	if s == nil || !s.enabled {
		return
	}
	scope := 2
	if s.peers[k] != nil {
		scope = 0
	} else if _, ok := s.known[k]; ok {
		scope = 1
	}
	path := 3
	switch p {
	case featurepolicy.Direct:
		path = 0
	case featurepolicy.PeerRelay:
		path = 1
	case featurepolicy.DERP:
		path = 2
	}
	s.evidence[scope][path][event].Add(1)
}

func (s *pathPolicyTable) countDecision(k key.NodePublic, p featurepolicy.Path, direction int, allowed bool) {
	event := 2 * direction
	if !allowed {
		event++
	}
	s.countEvidence(k, p, event)
}

// Called only for actual confirmation sites, never from the WG predicate.
// Count forbidden confirmations as well, so a misplaced gate cannot silently
// hide a regression by suppressing the very evidence the lab is checking.
func (s *pathPolicyTable) countConfirmation(k key.NodePublic, p featurepolicy.Path, event int) {
	s.countEvidence(k, p, event)
	if peer := s.pathPeer(k); peer != nil && !peer.rule.Allow.Allows(p) {
		s.countEvidence(k, p, event+1)
	}
}

func (c *Conn) PathPolicyEvidenceState() PathPolicyEvidence {
	out := PathPolicyEvidence{Schema: 1, Counters: make(map[string]uint64, 144)}
	s := c.pathPolicy.Load()
	if s != nil {
		out.Generation, out.Enabled = s.generation, s.enabled
		out.MatchedPeers = len(s.peers)
		out.UnmatchedPeers = len(s.known) - len(s.peers)
	}
	for i, scope := range evidenceScopes {
		for j, path := range pathDropPaths {
			for k, event := range evidenceEvents {
				var n uint64
				if s != nil && s.enabled {
					n = s.evidence[i][j][k].Load()
				}
				out.Counters[scope+"/"+path+"/"+event] = n
			}
		}
	}
	return out
}
