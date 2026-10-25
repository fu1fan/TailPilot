// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package appc

import (
	"net/netip"
	"tailscale.com/featurepolicy"
	"testing"
	"time"
)

func TestLeaseDebugSummaryDoesNotSweep(t *testing.T) {
	now := time.Now()
	f := featurepolicy.Fence{Generation: 1, ProfileID: "p"}
	book := NewLeaseBook(f, LeaseOptions{MaxEntries: 10}, func() time.Time { return now })
	key := LeaseKey{ProfileID: "p", AssignedRoot: "private.invalid", QName: "private.invalid", Chain: "private.invalid", Source: "address", IP: netip.MustParseAddr("10.0.0.1")}
	if err := book.Observe(f, key, now, time.Second); err != nil {
		t.Fatal(err)
	}
	book.timeUncertain = true // model a restored, not-yet-confirmed clock
	c := &LeaseController{book: book}
	count, uncertain, age := c.DebugSummary(now.Add(3 * time.Second))
	if count != 1 || !uncertain || age != 2 || len(book.Snapshot()) != 1 {
		t.Fatalf("%d %v %v", count, uncertain, age)
	}
}
