// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package appc

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math/rand/v2"
	"net/netip"
	"slices"
	"sync"
	"time"

	"tailscale.com/featurepolicy"
)

// LeaseStateStore is a profile-captured sidecar. Save must be atomic/durable.
type LeaseStateStore interface {
	Load() ([]byte, error)
	Save([]byte) error
}

// LeaseReconcile receives the complete desired lease set, including independent
// references sharing an IP. It must fence and durably reconcile typed owners;
// success is local persistence, never evidence of remote route propagation.
type LeaseReconcile func(featurepolicy.Fence, []Lease) error

// LeaseController is a single writer for DNS renewal, persistence and sweeps.
// All I/O and callbacks occur without AppConnector.mu or LocalBackend.mu held.
// A failed route reconcile keeps durable lease evidence and is retried; DNS must
// not return a managed positive answer when ObserveDNS reports an error.
type LeaseController struct {
	mu        sync.Mutex
	blocked   error
	book      *LeaseBook
	store     LeaseStateStore
	reconcile LeaseReconcile
}

func NewLeaseController(f featurepolicy.Fence, o LeaseOptions, now func() time.Time, store LeaseStateStore, reconcile LeaseReconcile) (*LeaseController, error) {
	if store == nil || reconcile == nil {
		return nil, fmt.Errorf("lease controller requires durable store and reconcile")
	}
	data, err := store.Load()
	var b *LeaseBook
	if errors.Is(err, fs.ErrNotExist) {
		b = NewLeaseBook(f, o, now)
	} else if err == nil {
		b, err = RestoreLeaseBook(data, f, o, now)
	}
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	return &LeaseController{book: b, store: store, reconcile: reconcile}, nil
}

func (b *LeaseBook) clone() *LeaseBook {
	b.mu.Lock()
	defer b.mu.Unlock()
	c := NewLeaseBook(b.fence, b.opts, b.now)
	c.lastNow = b.lastNow
	c.timeUncertain = b.timeUncertain
	c.timeConfirmation = b.timeConfirmation
	for k, v := range b.leases {
		c.leases[k] = v
	}
	return c
}

// Snapshot returns a stable copy, suitable for complete owner reconciliation.
func (b *LeaseBook) Snapshot() []Lease {
	b.mu.Lock()
	defer b.mu.Unlock()
	// Precompute the stable ordering once per lease. Formatting both keys on
	// every comparison made cold DNS commits O(n log n) expensive allocations.
	type orderedKey struct {
		order string
		key   LeaseKey
	}
	keys := make([]orderedKey, 0, len(b.leases))
	for k := range b.leases {
		keys = append(keys, orderedKey{leaseOrder(k), k})
	}
	slices.SortFunc(keys, func(a, b orderedKey) int { return cmp.Compare(a.order, b.order) })
	result := make([]Lease, 0, len(keys))
	for _, k := range keys {
		result = append(result, b.leases[k.key])
	}
	return result
}

func (c *LeaseController) commit(candidate *LeaseBook) error {
	data, err := candidate.MarshalState()
	if err != nil {
		return err
	}
	if err = c.store.Save(data); err != nil {
		return err
	}
	c.book = candidate
	return c.reconcile(candidate.fence, candidate.Snapshot())
}

func (c *LeaseController) ObserveDNS(observations []DNSLeaseObservation) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.observeDNSLocked(observations)
}

func (c *LeaseController) observeDNSLocked(observations []DNSLeaseObservation) error {
	return c.recordDNSLocked(observations, false)
}
func (c *LeaseController) recordDNSLocked(observations []DNSLeaseObservation, queueOnly bool) error {
	if c.blocked != nil {
		return c.blocked
	}
	next := c.book.clone()
	now := next.now()
	for _, o := range observations {
		source := o.Source
		if source == "" {
			source = "peerapi-dns"
		}
		k := LeaseKey{ProfileID: next.fence.ProfileID, AssignedRoot: o.AssignedRoot, QName: o.QName, Chain: o.Chain, IP: o.IP, Source: source}
		if err := next.Observe(next.fence, k, now, o.TTL); err != nil {
			return err
		}
	}
	if queueOnly {
		data, err := next.MarshalState()
		if err != nil {
			return err
		}
		if err = c.store.Save(data); err != nil {
			return err
		}
		c.book = next
		return nil
	}
	return c.commit(next)
}

func (c *LeaseController) Sweep(limit int, activity ActivityProvider) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.blocked != nil {
		return c.blocked
	}
	next := c.book.clone()
	next.Sweep(next.fence, limit, activity)
	return c.commit(next)
}

// Run schedules bounded sweeps. Inject after and jitter for deterministic tests;
// production defaults use a monotonic timer and uniform [0,maxJitter] jitter.
// No immediate retry loop is used on storage failures.
func (c *LeaseController) Run(ctx context.Context, interval, maxJitter time.Duration, limit int, activity ActivityProvider, after func(time.Duration) <-chan time.Time, jitter func(time.Duration) time.Duration, report func(error)) error {
	if interval <= 0 || maxJitter < 0 || maxJitter >= time.Hour || limit <= 0 {
		return fmt.Errorf("lease sweep: invalid schedule")
	}
	if after == nil {
		after = time.After
	}
	if jitter == nil {
		jitter = func(max time.Duration) time.Duration { return time.Duration(rand.Int64N(int64(max) + 1)) }
	}
	for {
		delay := jitter(maxJitter)
		if delay < 0 || delay > maxJitter {
			return fmt.Errorf("lease sweep: invalid jitter")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-after(interval + delay):
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := c.Sweep(limit, activity); err != nil && report != nil {
				report(err)
			}
		}
	}
}

// ObserveDNSAt rejects callbacks captured by a previous policy generation,
// including when the same controller has since advanced to a newer fence.
func (c *LeaseController) ObserveDNSAt(f featurepolicy.Fence, observations []DNSLeaseObservation) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.book.fence != f {
		return fmt.Errorf("lease callback: stale fence")
	}
	return c.observeDNSLocked(observations)
}

// Reconfigure preserves monotonic deadlines across live reloads. Restoration is
// reserved for process/profile starts, where time trust must be established.
func (c *LeaseController) Reconfigure(f featurepolicy.Fence, o LeaseOptions, assigned func(string) bool, store LeaseStateStore) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.blocked != nil {
		return c.blocked
	}
	next := c.book.clone()
	next.opts = o
	if err := next.AdvanceFence(f, assigned); err != nil {
		return err
	}
	data, err := next.MarshalState()
	if err != nil {
		return err
	}
	if err := store.Save(data); err != nil {
		return err
	}
	c.store, c.book = store, next
	return c.reconcile(f, next.Snapshot())
}

func (c *LeaseController) Snapshot() []Lease {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.book.Snapshot()
}

// DebugSummary returns counts only; age is expired lease age, not work latency.
func (c *LeaseController) DebugSummary(now time.Time) (count int, uncertain bool, oldestExpiredSeconds float64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	leases := c.book.Snapshot()
	for _, l := range leases {
		oldestExpiredSeconds = max(oldestExpiredSeconds, now.Sub(l.Expires).Seconds())
	}
	return len(leases), c.book.TimeUncertain(), oldestExpiredSeconds
}

// TimeConfirmation is persisted audit evidence, not restart authorization.
type TimeConfirmation struct {
	Source      string
	ConfirmedAt time.Time
	Fence       featurepolicy.Fence
}

// ConfirmTrustedTime is called only after the administrative authorization and
// explicit Lead assertion. Failure leaves the live book frozen. Restart always
// requires a new confirmation; this record is historical evidence only.
func (c *LeaseController) ConfirmTrustedTime(f featurepolicy.Fence, source string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if f != c.book.fence || source == "" || len(source) > 256 {
		return fmt.Errorf("time confirmation: invalid source or fence")
	}
	if c.blocked != nil {
		return c.blocked
	}
	next := c.book.clone()
	next.ConfirmTime()
	next.timeConfirmation = TimeConfirmation{source, next.now(), f}
	data, err := next.MarshalState()
	if err != nil {
		return err
	}
	if err := c.store.Save(data); err != nil {
		return err
	}
	c.book = next
	return nil
}

// LeaseSnapshotHash binds a clear preview to evidence, including renewals that
// do not change the prefix set. MarshalState is unsuitable (SavedAt changes).
func LeaseSnapshotHash(leases []Lease) string {
	data, _ := json.Marshal(leases)
	return fmt.Sprintf("%x", sha256.Sum256(data))
}

// ClearExclusive holds the DNS/sweep writer while a coordinator commits the
// candidate with its owner journal. An interrupted transaction quarantines this
// controller; recovery must reload durable evidence before accepting more DNS.
func (c *LeaseController) ClearExclusive(f featurepolicy.Fence, prefixes []netip.Prefix, leaseHash string, transaction func([]byte) error) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.blocked != nil {
		return c.blocked
	}
	if f != c.book.fence || LeaseSnapshotHash(c.book.Snapshot()) != leaseHash {
		return fmt.Errorf("automatic clear: lease CAS conflict")
	}
	next := c.book.clone()
	for k := range next.leases {
		if slices.Contains(prefixes, netip.PrefixFrom(k.IP, k.IP.BitLen())) {
			delete(next.leases, k)
		}
	}
	data, err := next.MarshalState()
	if err != nil {
		return err
	}
	if err = transaction(data); err != nil {
		c.blocked = err
		return err
	}
	c.book = next
	return nil
}

// RecordDNSAt durably queues evidence without acknowledging route installation.
// Reconfigure/Sweep/ReconcileAt retry this complete desired set after failure
// or restart; there is no best-effort in-memory delivery after acknowledgement.
func (c *LeaseController) RecordDNSAt(f featurepolicy.Fence, observations []DNSLeaseObservation) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.book.fence != f {
		return fmt.Errorf("lease callback: stale fence")
	}
	return c.recordDNSLocked(observations, true)
}
func (c *LeaseController) ReconcileAt(f featurepolicy.Fence) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.blocked != nil {
		return c.blocked
	}
	if c.book.fence != f {
		return fmt.Errorf("lease reconcile: stale fence")
	}
	return c.reconcile(f, c.book.Snapshot())
}
