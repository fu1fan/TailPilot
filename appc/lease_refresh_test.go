// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package appc

import (
	"net/netip"
	"testing"
	"time"
)

func netipMust(s string) netip.Addr { return netip.MustParseAddr(s) }

// A repeat DNS answer that only refreshes an already-healthy lease must not
// rewrite the whole durable ownership transaction on every query; the persisted
// expiry still has at least half the observed TTL left. A near-expiry refresh
// and any legacy-to-lease transition must still commit.
func TestTTLObserveRefreshWindowSkipsDurableWrite(t *testing.T) {
	ac, backend, now, f := ttlFixture(t, nil)
	wire := func() []byte { return ttlWire(t, "www.example.com", 300) }
	mustTTL(t, ac.ObserveDNSResponse(wire()))
	commits := backend.commits
	if commits == 0 {
		t.Fatal("new lease did not commit")
	}

	// Same answer inside the refresh window: no durable transaction.
	*now = now.Add(10 * time.Second)
	mustTTL(t, ac.ObserveDNSResponse(wire()))
	if backend.commits != commits {
		t.Fatalf("repeat answer rewrote the transaction: commits=%d want=%d", backend.commits, commits)
	}
	state, err := ac.TTLState()
	if err != nil || len(state.Leases) != 1 {
		t.Fatalf("lease disappeared on skipped refresh: %+v %v", state.Leases, err)
	}

	// Past half the TTL the answer is still refresh-only: it is deferred, then
	// merged into one durable transaction by the refresher.
	*now = now.Add(160 * time.Second)
	mustTTL(t, ac.ObserveDNSResponse(wire()))
	if backend.commits != commits {
		t.Fatalf("refresh committed inline: commits=%d want=%d", backend.commits, commits)
	}
	ac.ttl.Load().flushRefresh()
	if backend.commits != commits+1 {
		t.Fatalf("deferred refresh not merged: commits=%d want=%d", backend.commits, commits+1)
	}

	// No observations at all is never a durable transition.
	tl := ac.ttl.Load()
	commits = backend.commits
	mustTTL(t, tl.observe(f, tl.epoch, nil))
	if backend.commits != commits {
		t.Fatal("empty observation committed")
	}
}

// A legacy reference replaced by a real observation is a durable transition even
// when the resulting lease would otherwise be inside the refresh window.
func TestTTLObserveLegacyTransitionAlwaysCommits(t *testing.T) {
	old := LegacyDNSReference{"*.example.com", "www.example.com", netipMust("192.0.2.1")}
	ac, backend, _, _ := ttlFixture(t, []LegacyDNSReference{old})
	if !hasTTLRoute(backend) {
		t.Fatal("legacy fixture missing")
	}
	before := backend.commits
	mustTTL(t, ac.ObserveDNSResponse(ttlWire(t, "www.example.com", 300)))
	if backend.commits != before+1 {
		t.Fatalf("legacy transition not committed: %d -> %d", before, backend.commits)
	}
}

// A refresh deferred to the background refresher is merged into one durable
// transaction and still keeps the lease alive.
func TestTTLDeferredRefreshFlushes(t *testing.T) {
	ac, backend, now, _ := ttlFixture(t, nil)
	mustTTL(t, ac.ObserveDNSResponse(ttlWire(t, "www.example.com", 300)))
	commits := backend.commits
	*now = now.Add(10 * time.Second)
	mustTTL(t, ac.ObserveDNSResponse(ttlWire(t, "www.example.com", 300)))
	if backend.commits != commits {
		t.Fatal("deferred refresh committed inline")
	}
	tl := ac.ttl.Load()
	if len(tl.pending) == 0 {
		t.Fatal("refresh was not deferred")
	}
	tl.flushRefresh()
	if backend.commits != commits+1 {
		t.Fatalf("deferred refresh not flushed: commits=%d want=%d", backend.commits, commits+1)
	}
	state, err := ac.TTLState()
	if err != nil || len(state.Leases) != 1 {
		t.Fatalf("lease lost after deferred refresh: %+v %v", state.Leases, err)
	}
}
