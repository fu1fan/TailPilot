package appc

import (
	"errors"
	"net/netip"
	"slices"
	"tailscale.com/featurepolicy"
	"testing"
	"time"
)

func TestLeaseExplicitTimeConfirmation(t *testing.T) {
	now := time.Unix(1000, 0)
	f := featurepolicy.Fence{ProfileID: "p", Generation: 1}
	store := new(leaseMemoryStore)
	opts := LeaseOptions{MaxEntries: 10, ClockJump: time.Minute}
	c, err := NewLeaseController(f, opts, func() time.Time { return now }, store, func(featurepolicy.Fence, []Lease) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	obs := []DNSLeaseObservation{{AssignedRoot: "example.test", QName: "example.test", Chain: "example.test", IP: netip.MustParseAddr("192.0.2.1"), TTL: time.Second}}
	if err := c.ObserveDNS(obs); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Second)
	if err := c.Sweep(10, nil); err != nil {
		t.Fatal(err)
	}
	if len(c.Snapshot()) != 1 || !c.book.TimeUncertain() {
		t.Fatal("untrusted new book swept")
	}
	store.fail = true
	if err := c.ConfirmTrustedTime(f, "lead:test"); err == nil || !c.book.TimeUncertain() {
		t.Fatal("failed confirmation thawed")
	}
	store.fail = false
	if err := c.ConfirmTrustedTime(f, ""); err == nil {
		t.Fatal("missing source accepted")
	}
	if err := c.ConfirmTrustedTime(f, "lead:test"); err != nil {
		t.Fatal(err)
	}
	if c.book.TimeUncertain() || c.book.timeConfirmation.Source != "lead:test" {
		t.Fatal("confirmation missing")
	}
	restored, err := RestoreLeaseBook(store.data, f, opts, func() time.Time { return now })
	if err != nil || !restored.TimeUncertain() || restored.timeConfirmation.Source != "lead:test" {
		t.Fatal("restart reused trust or lost audit", err)
	}
	if err := c.Sweep(10, nil); err != nil || len(c.Snapshot()) != 0 {
		t.Fatal("confirmed sweep frozen", err)
	}
	for _, jump := range []time.Duration{-2 * time.Minute, 3 * time.Minute} {
		if err := c.ConfirmTrustedTime(f, "lead:test"); err != nil {
			t.Fatal(err)
		}
		now = now.Add(jump)
		if err := c.Sweep(10, nil); err != nil || !c.book.TimeUncertain() {
			t.Fatal("jump not frozen", err)
		}
	}
}

func TestLeaseClearEvidenceCASAndFailure(t *testing.T) {
	now := time.Unix(1000, 0)
	f := featurepolicy.Fence{ProfileID: "p", Generation: 1}
	st := new(leaseMemoryStore)
	c, err := NewLeaseController(f, LeaseOptions{MaxEntries: 10}, func() time.Time { return now }, st, func(featurepolicy.Fence, []Lease) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	obs := []DNSLeaseObservation{{AssignedRoot: "example.test", QName: "example.test", Chain: "example.test", IP: netip.MustParseAddr("192.0.2.1"), TTL: time.Second}}
	if err := c.ObserveDNS(obs); err != nil {
		t.Fatal(err)
	}
	hash := LeaseSnapshotHash(c.Snapshot())
	now = now.Add(time.Second)
	if err := c.ObserveDNS(obs); err != nil {
		t.Fatal(err)
	}
	called := false
	if err := c.ClearExclusive(f, nil, hash, func([]byte) error { called = true; return nil }); err == nil || called {
		t.Fatal("concurrent renewal accepted")
	}
	hash = LeaseSnapshotHash(c.Snapshot())
	if err := c.ClearExclusive(f, []netip.Prefix{netip.MustParsePrefix("192.0.2.1/32")}, hash, func(data []byte) error { return errors.New("interrupted transaction") }); err == nil {
		t.Fatal("failed transaction accepted")
	}
	now = now.Add(time.Second)
	if err := c.ObserveDNS(obs); err == nil {
		t.Fatal("quarantined controller accepted DNS")
	}
}

// Trust acknowledges a clock assessment, never renews evidence. Historical
// confirmation cannot authorize any later boot, including with identical time.
func TestLeaseTimeConfirmationDoesNotRenew(t *testing.T) {
	now := time.Unix(1000, 0)
	f := featurepolicy.Fence{ProfileID: "p", Generation: 1}
	st := new(leaseMemoryStore)
	opts := LeaseOptions{MaxEntries: 10, Grace: time.Second, MaxActiveRetention: time.Minute, ClockJump: time.Minute}
	c, err := NewLeaseController(f, opts, func() time.Time { return now }, st, func(featurepolicy.Fence, []Lease) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if err := c.ObserveDNS([]DNSLeaseObservation{{AssignedRoot: "example.test", QName: "example.test", Chain: "example.test", IP: netip.MustParseAddr("192.0.2.1"), TTL: time.Second}}); err != nil {
		t.Fatal(err)
	}
	before := c.Snapshot()
	for range 3 {
		now = now.Add(10 * time.Second)
		if err := c.ConfirmTrustedTime(f, "Lead-reviewed"); err != nil {
			t.Fatal(err)
		}
		if LeaseSnapshotHash(before) != LeaseSnapshotHash(c.Snapshot()) {
			t.Fatal("confirmation renewed deadlines")
		}
		raw := slices.Clone(st.data)
		stale := f
		stale.Generation++
		if err := c.ConfirmTrustedTime(stale, "Lead-reviewed"); err == nil || !slices.Equal(raw, st.data) {
			t.Fatal("stale confirmation persisted")
		}
		c, err = NewLeaseController(f, opts, func() time.Time { return now }, st, func(featurepolicy.Fence, []Lease) error { return nil })
		if err != nil {
			t.Fatal(err)
		}
		if !c.book.TimeUncertain() {
			t.Fatal("restart inherited trust")
		}
		if err := c.Sweep(10, nil); err != nil {
			t.Fatal(err)
		}
		if LeaseSnapshotHash(before) != LeaseSnapshotHash(c.Snapshot()) {
			t.Fatal("untrusted restart deleted evidence")
		}
	}
}
