package appc

import (
	"net/netip"
	"tailscale.com/featurepolicy"
	"testing"
	"time"
)

func TestLeaseRenewSweep(t *testing.T) {
	now := time.Unix(1000, 0)
	f := featurepolicy.Fence{ProfileID: "p", Generation: 1}
	book := NewLeaseBook(f, LeaseOptions{TimeTrusted: true, Grace: 2 * time.Second, MaxActiveRetention: 10 * time.Second, MaxEntries: 100, ClockJump: 5 * time.Minute}, func() time.Time { return now })
	a := LeaseKey{ProfileID: "p", AssignedRoot: "example.com", QName: "a.example.com", Chain: "a.example.com", IP: netip.MustParseAddr("192.0.2.1"), Source: "address"}
	b := a
	b.QName = "b.example.com"
	if e := book.Observe(f, a, now, time.Second); e != nil {
		t.Fatal(e)
	}
	if e := book.Observe(f, b, now, 10*time.Second); e != nil {
		t.Fatal(e)
	}
	now = now.Add(3 * time.Second)
	if got := book.Sweep(f, 128, nil); len(got) != 1 || got[0] != a {
		t.Fatalf("independent expiry: %v", got)
	}
	if e := book.Observe(f, b, now, 10*time.Second); e != nil {
		t.Fatal(e)
	}
	if e := book.Observe(f, b, now.Add(-time.Second), 0); e == nil {
		t.Fatal("stale observation")
	}
	now = now.Add(10 * time.Second)
	if len(book.Sweep(f, 128, nil)) != 0 {
		t.Fatal("missing grace")
	}
	now = now.Add(2 * time.Second)
	if len(book.Sweep(f, 128, nil)) != 1 {
		t.Fatal("expiry")
	}
	if e := book.Observe(featurepolicy.Fence{}, b, now, time.Second); e == nil {
		t.Fatal("stale fence")
	}
}
