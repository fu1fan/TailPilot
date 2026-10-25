package appc

import (
	"net/netip"
	"tailscale.com/featurepolicy"
	"testing"
	"time"
)

func TestLeaseRestartAndUncertainTime(t *testing.T) {
	now := time.Unix(10000, 0)
	f := featurepolicy.Fence{ProfileID: "p", Generation: 1}
	o := LeaseOptions{TimeTrusted: true, Grace: 2 * time.Second, MaxActiveRetention: 10 * time.Second, MaxEntries: 100, ClockJump: 5 * time.Minute}
	b := NewLeaseBook(f, o, func() time.Time { return now })
	k := LeaseKey{ProfileID: "p", AssignedRoot: "example.com", QName: "a.example.com", Chain: "a.example.com", IP: netip.MustParseAddr("192.0.2.1"), Source: "address"}
	if e := b.Observe(f, k, now, 10*time.Second); e != nil {
		t.Fatal(e)
	}
	now = now.Add(4 * time.Second)
	data, e := b.MarshalState()
	if e != nil {
		t.Fatal(e)
	}
	now = now.Add(4 * time.Second)
	b, e = RestoreLeaseBook(data, f, o, func() time.Time { return now })
	if e != nil {
		t.Fatal(e)
	}
	if got := b.leases[k].Expires.Sub(now); got != 2*time.Second {
		t.Fatalf("TTL extended on restart: %v", got)
	}
	now = now.Add(4 * time.Second)
	if len(b.Sweep(f, 128, nil)) != 1 {
		t.Fatal("restart grace extended")
	}
	now = now.Add(-time.Hour)
	b, e = RestoreLeaseBook(data, f, o, func() time.Time { return now })
	if e != nil {
		t.Fatal(e)
	}
	if !b.TimeUncertain() {
		t.Fatal("rollback unobserved")
	}
	data, e = b.MarshalState()
	if e != nil {
		t.Fatal(e)
	}
	for range 3 {
		b, e = RestoreLeaseBook(data, f, o, func() time.Time { return now })
		if e != nil {
			t.Fatal(e)
		}
		now = now.Add(time.Minute)
		if len(b.Sweep(f, 128, nil)) != 0 || !b.TimeUncertain() {
			t.Fatal("restart cleared uncertainty")
		}
		data, e = b.MarshalState()
		if e != nil {
			t.Fatal(e)
		}
	}
	data[len(data)/2] ^= 1
	if _, e = RestoreLeaseBook(data, f, o, func() time.Time { return now }); e == nil {
		t.Fatal("corrupt lease accepted")
	}
}

func TestLeaseBoundedUnknownAndDomainFence(t *testing.T) {
	now := time.Unix(1000, 0)
	f := featurepolicy.Fence{ProfileID: "p", Generation: 1}
	b := NewLeaseBook(f, LeaseOptions{TimeTrusted: true, Grace: time.Second, MaxActiveRetention: 5 * time.Second, BoundedActivity: true, MaxEntries: 1, ClockJump: time.Minute}, func() time.Time { return now })
	k := LeaseKey{ProfileID: "p", AssignedRoot: "example.com", QName: "a.example.com", Chain: "a.example.com", IP: netip.MustParseAddr("192.0.2.1"), Source: "address"}
	if e := b.Observe(f, k, now, 0); e != nil {
		t.Fatal(e)
	}
	other := k
	other.QName = "other.example.com"
	if e := b.Observe(f, other, now, time.Hour); e == nil {
		t.Fatal("capacity bypass")
	}
	now = now.Add(time.Second)
	if len(b.Sweep(f, 1, nil)) != 0 {
		t.Fatal("unknown not bounded-protected")
	}
	now = now.Add(4 * time.Second)
	if len(b.Sweep(f, 1, nil)) != 1 {
		t.Fatal("hard deadline moved by activity")
	}
	if e := b.Observe(f, k, now, time.Hour); e != nil {
		t.Fatal(e)
	}
	fresh := f
	fresh.Generation++
	fresh.AssignedDomainsEpoch++
	if e := b.AdvanceFence(fresh, func(string) bool { return false }); e != nil {
		t.Fatal(e)
	}
	if len(b.leases) != 0 {
		t.Fatal("revoked assignment retained")
	}
	if e := b.Observe(f, k, now, time.Hour); e == nil {
		t.Fatal("old epoch observation")
	}
}
