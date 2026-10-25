// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package featurepolicy

import (
	"fmt"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"testing"
	"time"
)

func pathFixture() (Rule, PathConfig, Fence) {
	c, _ := Parse([]byte(`{"schema_version":1}`))
	return Rule{ID: "r", Allow: Allow{true, true, true}, Prefer: []string{"direct", "peer_relay", "derp"}, Fallback: "allowed"}, c.PathPolicy, Fence{Generation: 1, PeerIdentityEpoch: 1}
}

func TestPathAllAllowCombinations(t *testing.T) {
	for bits := 0; bits < 8; bits++ {
		for _, strict := range []bool{false, true} {
			t.Run(fmt.Sprintf("%03b/strict=%v", bits, strict), func(t *testing.T) {
				r, c, f := pathFixture()
				r.Allow = Allow{bits&4 != 0, bits&2 != 0, bits&1 != 0}
				r.Prefer = nil
				for _, p := range []Path{Direct, PeerRelay, DERP} {
					if r.Allow.Allows(p) {
						r.Prefer = append(r.Prefer, string(p))
					}
				}
				if strict {
					r.Fallback = "strict"
				}
				m := NewPathMachine(r, c, f)
				now := time.Unix(100, 0)
				for _, p := range []Path{DERP, PeerRelay, Direct} {
					m.Observe(p, true, now, f)
				}
				for _, p := range []Path{Direct, PeerRelay, DERP} {
					for _, purpose := range []PathPurpose{PathSend, PathProbe, PathReceive, PathPromote} {
						if m.Decide(p, purpose, f) && !r.Allow.Allows(p) {
							t.Fatal("hard deny bypass")
						}
						stale := f
						stale.PeerIdentityEpoch++
						if m.Decide(p, purpose, stale) {
							t.Fatal("stale identity")
						}
					}
				}
				if bits == 0 && m.Status().Reason != "POLICY_NO_PATH" {
					t.Fatal(m.Status())
				}
				if strict && len(r.Prefer) > 0 && m.Status().Active != Path(r.Prefer[0]) {
					t.Fatal(m.Status())
				}
			})
		}
	}
}

func TestPathFailureRecoveryBoundaries(t *testing.T) {
	r, c, f := pathFixture()
	m := NewPathMachine(r, c, f)
	now := time.Unix(100, 0)
	if m.Status().State != Probing {
		t.Fatal(m.Status())
	}
	m.Observe(Direct, true, now, f)
	m.Observe(DERP, true, now, f)
	for i := 1; i <= 3; i++ {
		m.Observe(Direct, false, now.Add(time.Duration(i)*3*time.Second), f)
		if i < 3 && (m.Status().State != Suspect || m.Status().Active != Direct) {
			t.Fatal(m.Status())
		}
	}
	if m.Status().Active != DERP || m.Status().State != Fallback {
		t.Fatal(m.Status())
	}
	for _, sec := range []int{10, 20, 25, 38} {
		m.Observe(Direct, true, now.Add(time.Duration(sec)*time.Second), f)
	}
	if m.Status().Active != DERP || m.Status().State != Recovering {
		t.Fatal("cooldown", m.Status())
	}
	m.Observe(Direct, true, now.Add(39*time.Second), f)
	if m.Status().Active != Direct || m.Status().State != Active {
		t.Fatal(m.Status())
	}
	// Hard deny wins even immediately after promotion and before cooldown.
	r.Allow.Direct = false
	r.Prefer = []string{"peer_relay", "derp"}
	f.Generation++
	m.Reconfigure(r, c, f, now.Add(40*time.Second))
	if m.Status().Active != DERP || m.Decide(Direct, PathProbe, f) {
		t.Fatal(m.Status())
	}
}

func TestPathStrictNoFallbackAndRecoveryHold(t *testing.T) {
	r, c, f := pathFixture()
	r.Fallback = "strict"
	m := NewPathMachine(r, c, f)
	now := time.Unix(100, 0)
	m.Observe(DERP, true, now, f)
	if m.Decide(DERP, PathSend, f) || !m.Decide(DERP, PathProbe, f) {
		t.Fatal("strict")
	}
	if m.Status().Reason != "POLICY_NO_PATH" {
		t.Fatal(m.Status())
	}
	r.Fallback = "allowed"
	m = NewPathMachine(r, c, f)
	m.Observe(DERP, true, now, f)
	for _, sec := range []int{31, 32, 33, 45} {
		m.Observe(Direct, true, now.Add(time.Duration(sec)*time.Second), f)
	}
	if m.Status().Active != DERP {
		t.Fatal("hold", m.Status())
	}
	m.Observe(Direct, true, now.Add(46*time.Second), f)
	if m.Status().Active != Direct {
		t.Fatal(m.Status())
	}
}

func TestPathSharedDiscoAndRuleCopies(t *testing.T) {
	c, _ := Parse([]byte(`{"schema_version":1,"enabled":true,"path_policy":{"enabled":true,"rules":[{"id":"r","stable_ids":["a","pending"],"allow":{"direct":true,"peer_relay":false,"derp":false},"prefer":["direct"]}]}}`))
	dk := key.NewDisco().Public()
	a, b := key.NewNode().Public(), key.NewNode().Public()
	s, e := compile(c, Inputs{Peers: []tailcfg.NodeView{(&tailcfg.Node{StableID: "a", Key: a, DiscoKey: dk}).View(), (&tailcfg.Node{StableID: "b", Key: b, DiscoKey: dk}).View()}}, 1)
	if e != nil {
		t.Fatal(e)
	}
	if _, ok := s.DiscoIdentity(dk); ok {
		t.Fatal("shared disco resolved to matched peer")
	}
	if _, ok := s.NodeIdentity(a); !ok {
		t.Fatal("lost node")
	}
	if _, ok := s.NodeIdentity(b); ok {
		t.Fatal("unmatched inherited")
	}
	r, _ := s.PathRule(a)
	r.Prefer[0] = "derp"
	r.StableIDs[0] = "b"
	r, _ = s.PathRule(a)
	if r.Prefer[0] != "direct" || r.StableIDs[0] != "a" {
		t.Fatal("alias")
	}
	ids := s.PathIdentities()
	ids[0].RuleID = "bad"
	id, _ := s.NodeIdentity(a)
	if id.RuleID != "r" {
		t.Fatal("identity alias")
	}
	if len(s.PendingRules()) != 1 {
		t.Fatal(s.PendingRules())
	}
}

func TestPathRecoveryFromNoPath(t *testing.T) {
	r, c, f := pathFixture()
	r.Allow = Allow{Derp: true}
	r.Prefer = []string{"derp"}
	m := NewPathMachine(r, c, f)
	now := time.Unix(100, 0)
	m.Observe(DERP, true, now, f)
	for range 3 {
		m.Observe(DERP, false, now.Add(10*time.Second), f)
	}
	if m.Status().State != NoPath {
		t.Fatal(m.Status())
	}
	for _, sec := range []int{31, 32, 33, 45} {
		m.Observe(DERP, true, now.Add(time.Duration(sec)*time.Second), f)
	}
	if m.Status().State != Recovering || m.Decide(DERP, PathSend, f) {
		t.Fatal("recovery bypassed hold", m.Status())
	}
	m.Observe(DERP, true, now.Add(46*time.Second), f)
	if m.Status().Active != DERP || m.Status().State != Active {
		t.Fatal(m.Status())
	}
}

func TestPathRecoveryMinimumHold(t *testing.T) {
	r, c, f := pathFixture()
	r.Allow = Allow{Derp: true}
	r.Prefer = []string{"derp"}
	c.RecoveryHoldSeconds = 1 // Older schema-valid value cannot weaken the R8 floor.
	c.CooldownSeconds = 0
	m := NewPathMachine(r, c, f)
	now := time.Unix(100, 0)
	m.Observe(DERP, true, now, f)
	for range 3 {
		m.Observe(DERP, false, now.Add(time.Second), f)
	}
	for _, sec := range []int{2, 3, 4, 16} {
		m.Observe(DERP, true, now.Add(time.Duration(sec)*time.Second), f)
	}
	if m.Decide(DERP, PathSend, f) {
		t.Fatal("recovery hold shorter than 15 seconds")
	}
	m.Observe(DERP, true, now.Add(17*time.Second), f)
	if !m.Decide(DERP, PathSend, f) {
		t.Fatal(m.Status())
	}
}
