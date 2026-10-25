// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package featurepolicy

import (
	"fmt"
	"slices"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// Identity is a current control-authenticated peer and its first matching rule.
// It contains no IP or hostname selector.
type Identity struct {
	StableID tailcfg.StableNodeID
	RuleID   string
	Node     key.NodePublic
	Disco    key.DiscoPublic
}

// NodeIdentity resolves only current node keys. Recompilation replaces the
// entire index, so key rotation never leaves an old key authorized.
func (s *PolicySnapshot) NodeIdentity(k key.NodePublic) (Identity, bool) {
	v, ok := s.nodes[k]
	return v, ok
}

// DiscoIdentity resolves control-authenticated discovery keys, not self claims.
func (s *PolicySnapshot) DiscoIdentity(k key.DiscoPublic) (Identity, bool) {
	v, ok := s.discos[k]
	return v, ok
}

func (s *PolicySnapshot) compileIdentity(peers []tailcfg.NodeView) error {
	s.nodes = map[key.NodePublic]Identity{}
	s.discos = map[key.DiscoPublic]Identity{}
	ids := map[tailcfg.StableNodeID]bool{}
	nodes := map[key.NodePublic]bool{}
	discos := map[key.DiscoPublic]int{}
	for _, p := range peers {
		if p.Valid() && !p.DiscoKey().IsZero() {
			discos[p.DiscoKey()]++
		}
	}
	for _, p := range peers {
		if !p.Valid() || p.StableID() == "" || p.Key().IsZero() {
			return fmt.Errorf("identity: incomplete trusted peer")
		}
		if ids[p.StableID()] || nodes[p.Key()] {
			return fmt.Errorf("identity: ambiguous trusted peer")
		}
		ids[p.StableID()] = true
		nodes[p.Key()] = true
		if !s.config.Enabled || !s.config.PathPolicy.Enabled {
			continue
		}
		for _, r := range s.config.PathPolicy.Rules {
			if slices.Contains(r.StableIDs, string(p.StableID())) {
				v := Identity{p.StableID(), r.ID, p.Key(), p.DiscoKey()}
				s.nodes[v.Node] = v
				if !v.Disco.IsZero() && discos[v.Disco] == 1 {
					s.discos[v.Disco] = v
				}
				break
			}
		}
	}
	for _, r := range s.config.PathPolicy.Rules {
		for _, id := range r.StableIDs {
			if !ids[tailcfg.StableNodeID(id)] {
				s.pending = append(s.pending, r.ID+":"+id)
			}
		}
	}
	return nil
}

// PathRule returns the effective first-match rule, never a mutable snapshot alias.
func (s *PolicySnapshot) PathRule(k key.NodePublic) (Rule, bool) {
	id, ok := s.NodeIdentity(k)
	if !ok {
		return Rule{}, false
	}
	for _, r := range s.config.PathPolicy.Rules {
		if r.ID == id.RuleID {
			r.StableIDs = slices.Clone(r.StableIDs)
			r.Tags = slices.Clone(r.Tags)
			r.Prefer = slices.Clone(r.Prefer)
			return r, true
		}
	}
	return Rule{}, false
}

// PathIdentities returns only control-authenticated, matched identities.
func (s *PolicySnapshot) PathIdentities() []Identity {
	out := make([]Identity, 0, len(s.nodes))
	for _, id := range s.nodes {
		out = append(out, id)
	}
	return out
}
