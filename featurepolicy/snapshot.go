// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package featurepolicy

import (
	"fmt"
	"slices"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// Fence identifies a profile and all inputs to an asynchronous policy operation.
// Equality must be checked again immediately before committing a side effect.
type Fence struct {
	Generation           uint64
	ProfileID            string
	AssignedDomainsEpoch uint64
	PeerIdentityEpoch    uint64
}

// Inputs must come from the authenticated control netmap, never a DNS response
// or peer-provided names, addresses or discovery packets. A complete peer set
// is required even when the netmap update was delivered as a delta.
type Inputs struct {
	ProfileID            string
	AssignedDomainsEpoch uint64
	PeerIdentityEpoch    uint64
	AssignedDomains      []string
	Peers                []tailcfg.NodeView
}

// PolicySnapshot owns all its data. Accessors return values or defensive copies.
type PolicySnapshot struct {
	fence    Fence
	config   Config
	assigned []string
	nodes    map[key.NodePublic]Identity
	discos   map[key.DiscoPublic]Identity
	pending  []string
}

// Fence returns the immutable operation fence.
func (s *PolicySnapshot) Fence() Fence { return s.fence }

// Config returns an independent configuration copy.
func (s *PolicySnapshot) Config() Config { c, _ := Parse(s.config.JSON()); return c }

// Enabled reports the root opt-in switch.
func (s *PolicySnapshot) Enabled() bool { return s.config.Enabled }

// OwnershipEnabled reports whether ownership is needed by a selected module.
func (s *PolicySnapshot) OwnershipEnabled() bool {
	return s.config.Enabled && (s.config.Lease.Enabled || s.config.AutoIPv6.Enabled)
}

// PendingRules reports selectors not resolved in the current trusted peer set.
func (s *PolicySnapshot) PendingRules() []string { return slices.Clone(s.pending) }

// DNSMatches intersects configured targets with current control assignments.
func (s *PolicySnapshot) DNSMatches(name string) bool {
	if !s.config.Enabled || !s.config.DNSIPv4Only.Enabled {
		return false
	}
	n, e := NormalizeDomain(name)
	if e != nil {
		return false
	}
	a := false
	for _, p := range s.assigned {
		a = a || matches(p, n)
	}
	if !a {
		return false
	}
	for _, p := range s.config.DNSIPv4Only.Targets {
		if matches(p, n) {
			return true
		}
	}
	return false
}

func compile(c Config, in Inputs, g uint64) (*PolicySnapshot, error) {
	// Reparse to prevent mutable aliases or bypass of semantic validation.
	c, e := Parse(c.JSON())
	if e != nil {
		return nil, e
	}
	s := &PolicySnapshot{fence: Fence{g, in.ProfileID, in.AssignedDomainsEpoch, in.PeerIdentityEpoch}, config: c}
	for _, d := range in.AssignedDomains {
		n, e := NormalizeDomain(d)
		if e != nil {
			return nil, e
		}
		s.assigned = append(s.assigned, n)
	}
	if c.Enabled && c.DNSIPv4Only.Enabled {
		overlap := false
		for _, t := range c.DNSIPv4Only.Targets {
			for _, a := range s.assigned {
				overlap = overlap || t == a || matches(t, a) || matches(a, t)
			}
		}
		if !overlap {
			return nil, fmt.Errorf("dns_ipv4_only: no assigned target; runtime not ready")
		}
	}
	if e = s.compileIdentity(in.Peers); e != nil {
		return nil, e
	}
	return s, nil
}
