package ipnlocal

import "tailscale.com/tailcfg"

// Route advertisements and endpoint/online updates are not identity changes.
// Invalidating the lease fence for them creates a feedback loop: a new lease
// publishes a route, the echoed netmap invalidates the next DNS transaction.
// Membership, registration and cryptographic key changes still invalidate it.
func sameUnifiedPeerIdentities(a, b []tailcfg.NodeView) bool {
	if len(a) != len(b) {
		return false
	}
	byID := make(map[tailcfg.NodeID]tailcfg.NodeView, len(a))
	for _, n := range a {
		if !n.Valid() {
			return false
		}
		byID[n.ID()] = n
	}
	for _, n := range b {
		if !n.Valid() {
			return false
		}
		old, ok := byID[n.ID()]
		if !ok || old.StableID() != n.StableID() || old.Key() != n.Key() || old.DiscoKey() != n.DiscoKey() {
			return false
		}
		delete(byID, n.ID())
	}
	return len(byID) == 0
}
