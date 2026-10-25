// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package magicsock

import (
	"github.com/tailscale/wireguard-go/conn"
	"tailscale.com/featurepolicy"
	"testing"
)

func TestPathPolicyDropMetrics(t *testing.T) {
	c := new(Conn)
	for i := 0; i < 3; i++ {
		c.countPathDeny(i, featurepolicy.Direct)
		c.countPathDeny(i, featurepolicy.Path("not-a-label"))
	}
	counts := c.PathPolicyDropCounters()
	if len(counts) != 12 || counts["send/direct/policy_deny"] != 1 || counts["receive/unknown/policy_deny"] != 1 {
		t.Fatal(counts)
	}
	if !c.allowPathSend(pathSendContext{}, featurepolicy.Direct) {
		t.Fatal("default-off rejected")
	}
	if c.PathPolicyDropCounters()["send/direct/policy_deny"] != 1 {
		t.Fatal("default-off counted as denial")
	}
}

func TestPathPolicyReceiveCountsOutsidePredicate(t *testing.T) {
	c, ep := policyFixture(t, 0)
	ctx := conn.TransportContext{Kind: conn.TransportDirect, Generation: c.pathGeneration()}
	endpoint := &authenticatedEndpoint{c: c, gate: c.authenticatedPathGate.Load()}
	if c.allowPolicyAuthenticated(ep.publicKey.Raw32(), conn.PacketTransport, ctx) {
		t.Fatal("blackhole accepted")
	}
	if c.PathPolicyDropCounters()["receive/direct/policy_deny"] != 0 {
		t.Fatal("pure predicate counted")
	}
	if endpoint.AllowAuthenticatedPeer(ep.publicKey.Raw32(), conn.PacketTransport, ctx) {
		t.Fatal("blackhole accepted")
	}
	if c.PathPolicyDropCounters()["receive/direct/policy_deny"] != 1 {
		t.Fatal("receive boundary not counted")
	}
}
