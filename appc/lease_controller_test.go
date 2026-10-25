package appc

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"net/netip"
	"tailscale.com/featurepolicy"
	"testing"
	"time"
)

type leaseMemoryStore struct {
	data []byte
	fail bool
}

func (s *leaseMemoryStore) Load() ([]byte, error) {
	if s.data == nil {
		return nil, fs.ErrNotExist
	}
	return append([]byte(nil), s.data...), nil
}
func (s *leaseMemoryStore) Save(b []byte) error {
	if s.fail {
		return errors.New("disk full")
	}
	s.data = append([]byte(nil), b...)
	return nil
}

func TestLeaseControllerDurability(t *testing.T) {
	now := time.Unix(1000, 0)
	f := featurepolicy.Fence{ProfileID: "p", Generation: 1}
	store := new(leaseMemoryStore)
	calls := 0
	c, err := NewLeaseController(f, LeaseOptions{TimeTrusted: true, MaxEntries: 10, ClockJump: time.Hour}, func() time.Time { return now }, store, func(_ featurepolicy.Fence, leases []Lease) error {
		calls++
		if len(store.data) == 0 {
			t.Fatal("reconcile before durable save")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	obs := []DNSLeaseObservation{{AssignedRoot: "example.com", QName: "example.com", Chain: "example.com", IP: netip.MustParseAddr("192.0.2.1"), TTL: time.Second}}
	store.fail = true
	if err := c.ObserveDNS(obs); err == nil {
		t.Fatal("failed save acknowledged")
	}
	if calls != 0 || len(c.book.leases) != 0 {
		t.Fatal("failed save published")
	}
	store.fail = false
	if err := c.ObserveDNS(obs); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Second)
	if err := c.Sweep(128, nil); err != nil {
		t.Fatal(err)
	}
	if len(c.book.leases) != 0 || calls != 2 {
		t.Fatal("sweep did not reconcile")
	}
}
func TestLeaseControllerBootUncertainty(t *testing.T) {
	f := featurepolicy.Fence{ProfileID: "p", Generation: 1}
	now := time.Unix(1000, 0)
	b := NewLeaseBook(f, LeaseOptions{MaxEntries: 2, BootID: "boot-a"}, func() time.Time { return now })
	data, err := b.MarshalState()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := RestoreLeaseBook(data, f, LeaseOptions{MaxEntries: 2, BootID: "boot-b"}, func() time.Time { return now })
	if err != nil || !restored.TimeUncertain() {
		t.Fatal("boot change lost uncertainty", err)
	}
}

func TestLeaseControllerAtomicCapacityAndRetry(t *testing.T) {
	now := time.Unix(1000, 0)
	f := featurepolicy.Fence{ProfileID: "p", Generation: 1}
	store := new(leaseMemoryStore)
	fail := true
	calls := 0
	c, err := NewLeaseController(f, LeaseOptions{MaxEntries: 2, ClockJump: time.Hour}, func() time.Time { return now }, store, func(_ featurepolicy.Fence, _ []Lease) error {
		calls++
		if fail {
			return errors.New("route persistence failed")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	obs := DNSLeaseObservation{AssignedRoot: "example.com", QName: "a.example.com", Chain: "a.example.com", IP: netip.MustParseAddr("192.0.2.1"), TTL: time.Hour}
	other := obs
	other.QName = "b.example.com"
	other.Chain = other.QName
	if err := c.ObserveDNS([]DNSLeaseObservation{obs, other}); err == nil {
		t.Fatal("route failure ignored")
	}
	if len(c.book.leases) != 2 || len(store.data) == 0 {
		t.Fatal("lost durable recovery evidence")
	}
	now = now.Add(time.Second)
	third := obs
	third.QName = "c.example.com"
	third.Chain = third.QName
	before := append([]byte(nil), store.data...)
	if err := c.ObserveDNS([]DNSLeaseObservation{obs, third}); err == nil {
		t.Fatal("capacity exceeded")
	}
	if !bytes.Equal(before, store.data) || calls != 1 {
		t.Fatal("partial observation published")
	}
	fail = false
	if err := c.Sweep(1, nil); err != nil || calls != 2 {
		t.Fatal("route reconciliation not retried", err)
	}
}
func TestLeaseControllerSchedule(t *testing.T) {
	f := featurepolicy.Fence{ProfileID: "p", Generation: 1}
	c, err := NewLeaseController(f, LeaseOptions{MaxEntries: 1}, time.Now, new(leaseMemoryStore), func(featurepolicy.Fence, []Lease) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	requested := make(chan time.Duration, 1)
	done := make(chan error, 1)
	ticks := make(chan time.Time)
	go func() {
		done <- c.Run(ctx, 30*time.Second, 5*time.Second, 128, nil, func(d time.Duration) <-chan time.Time { requested <- d; return ticks }, func(time.Duration) time.Duration { return 3 * time.Second }, nil)
	}()
	if got := <-requested; got != 33*time.Second {
		t.Fatal(got)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestLeaseControllerOldCallbackAfterReconfigure(t *testing.T) {
	f := featurepolicy.Fence{ProfileID: "p", Generation: 1}
	store := &reconfigureStore{}
	c, err := NewLeaseController(f, LeaseOptions{MaxEntries: 100}, time.Now, store, func(featurepolicy.Fence, []Lease) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	next := f
	next.Generation++
	if err := c.Reconfigure(next, LeaseOptions{MaxEntries: 100}, func(string) bool { return false }, store); err != nil {
		t.Fatal(err)
	}
	if err := c.ObserveDNSAt(f, nil); err == nil {
		t.Fatal("old callback rebound to new generation")
	}
	if err := c.ObserveDNSAt(next, nil); err != nil {
		t.Fatal(err)
	}
}

type reconfigureStore struct{ data []byte }

func (s *reconfigureStore) Load() ([]byte, error) {
	if s.data == nil {
		return nil, fs.ErrNotExist
	}
	return s.data, nil
}
func (s *reconfigureStore) Save(b []byte) error { s.data = append([]byte(nil), b...); return nil }
