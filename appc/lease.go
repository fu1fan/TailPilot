// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package appc

import (
	"fmt"
	"net/netip"
	"sort"
	"sync"
	"tailscale.com/featurepolicy"
	"time"
)

// LeaseKey separates references sharing an address. Chain is the canonical,
// ordered alias-chain identity supplied by the DNS compiler (Patch 03/05).
type LeaseKey struct {
	ProfileID    string
	AssignedRoot string
	QName        string
	Chain        string
	IP           netip.Addr
	Source       string
}

// Lease stores route retention, not DNS cache entries. Zero TTL is never raised.
// In-process time.Time deadlines retain Go's monotonic component.
type Lease struct {
	Key                 LeaseKey
	LastObserved        time.Time
	Expires             time.Time
	GraceUntil          time.Time
	AbsoluteRetainUntil time.Time
	FirstAdvertised     time.Time
	EffectiveTTL        time.Duration
	Fence               featurepolicy.Fence
}

// LeaseOptions contains deterministic timing and capacity limits. Jitter and
// scheduling are owned by the caller; Sweep is a bounded deterministic step.
type LeaseOptions struct {
	// BootID binds persisted evidence to an OS boot. TimeTrusted must come from
	// an explicit trusted-time source, never merely the current wall clock.
	BootID             string
	TimeTrusted        bool
	Grace              time.Duration
	MinAdvertise       time.Duration
	MaxActiveRetention time.Duration
	BoundedActivity    bool
	MaxEntries         int
	ClockJump          time.Duration
}

// ActivityState distinguishes proven idle from active and unavailable evidence.
type ActivityState uint8

const (
	// ActivityUnknown protects only to the lease's fixed hard deadline.
	ActivityUnknown ActivityState = iota
	// ActivityIdle permits deletion after grace.
	ActivityIdle
	// ActivityActive protects only to the fixed hard deadline.
	ActivityActive
)

// ActivityProvider is the Patch 03 boundary. It must be nonblocking and scoped
// to the same profile; a nil provider is unknown, never proof of inactivity.
type ActivityProvider interface {
	Activity(profile string, ip netip.Addr) ActivityState
}

// LeaseBook owns independent references and accepts only its current fence.
// It does not advertise routes or perform DNS transformation itself.
type LeaseBook struct {
	mu               sync.Mutex
	fence            featurepolicy.Fence
	opts             LeaseOptions
	now              func() time.Time
	leases           map[LeaseKey]Lease
	lastNow          time.Time
	timeUncertain    bool
	timeConfirmation TimeConfirmation
}

// NewLeaseBook constructs a book with an injectable monotonic clock.
func NewLeaseBook(f featurepolicy.Fence, o LeaseOptions, now func() time.Time) *LeaseBook {
	if now == nil {
		now = time.Now
	}
	return &LeaseBook{fence: f, opts: o, now: now, leases: map[LeaseKey]Lease{}, timeUncertain: !o.TimeTrusted}
}

// Observe records the actual TTL returned to the client, after any safe cap.
// It never caps independently of DNS: doing so could withdraw a cached route.
// Renewal only extends a reference; delayed observations cannot shorten it.
func (b *LeaseBook) Observe(f featurepolicy.Fence, k LeaseKey, observed time.Time, returnedTTL time.Duration) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if f != b.fence || k.ProfileID != f.ProfileID {
		return fmt.Errorf("lease: stale fence")
	}
	if !k.IP.IsValid() || k.IP.Is4In6() || k.AssignedRoot == "" || k.QName == "" || k.Chain == "" || k.Source == "" || returnedTTL < 0 || returnedTTL > time.Duration(1<<32-1)*time.Second {
		return fmt.Errorf("lease: invalid observation")
	}
	now := b.now()
	if observed.After(now) {
		return fmt.Errorf("lease: future observation")
	}
	l, exists := b.leases[k]
	if exists && !observed.After(l.LastObserved) {
		return fmt.Errorf("lease: stale observation")
	}
	if !exists {
		if b.opts.MaxEntries <= 0 || len(b.leases) >= b.opts.MaxEntries {
			return fmt.Errorf("lease: capacity")
		}
		l = Lease{Key: k, FirstAdvertised: now}
	}
	expiry := observed.Add(returnedTTL)
	if !exists || expiry.After(l.Expires) {
		l.Expires = expiry
		l.GraceUntil = expiry.Add(b.opts.Grace)
		l.AbsoluteRetainUntil = expiry.Add(max(b.opts.Grace, b.opts.MaxActiveRetention))
	}
	l.LastObserved = observed
	l.EffectiveTTL = returnedTTL
	l.Fence = f
	b.leases[k] = l
	return nil
}

// AdoptSweepState copies the non-durable sweep clock state (lastNow and
// timeUncertain) from a swept clone when no lease was removed. A no-op sweep
// must neither rewrite durable state nor lose clock-jump detection.
func (b *LeaseBook) AdoptSweepState(swept *LeaseBook) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.lastNow = swept.lastNow
	b.timeUncertain = swept.timeUncertain
}

// HasLeases reports whether every key already has a stored lease. Callers use
// this to defer refresh-only observations to the background merger.
func (b *LeaseBook) HasLeases(keys []LeaseKey) bool {
	if len(keys) == 0 {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, k := range keys {
		if _, ok := b.leases[k]; !ok {
			return false
		}
	}
	return true
}

// RefreshDue reports whether every key already has a lease whose remaining
// lifetime is at least half of the observed TTL. A false result requires a
// durable refresh (new lease, near-expiry, or an invalid/absent key). Callers
// use this to avoid rewriting the whole ownership transaction on every repeat
// DNS answer while still refreshing before a reference can expire.
func (b *LeaseBook) RefreshDue(keys []LeaseKey, ttls []time.Duration, now time.Time) bool {
	if len(keys) == 0 || len(keys) != len(ttls) {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for i, k := range keys {
		l, ok := b.leases[k]
		if !ok {
			return false
		}
		if l.Expires.Sub(now) < ttls[i]/2 {
			return false
		}
	}
	return true
}

// Sweep returns expired references, never prefixes: the ownership ledger must
// recheck all owners before withdrawing any exact prefix. Renewal and sweep are
// serialized. Time uncertainty freezes deletion until explicit trusted recovery.
func (b *LeaseBook) Sweep(f featurepolicy.Fence, limit int, activity ActivityProvider) []LeaseKey {
	b.mu.Lock()
	defer b.mu.Unlock()
	if f != b.fence || limit <= 0 {
		return nil
	}
	now := b.now()
	if !b.lastNow.IsZero() {
		elapsed := now.Sub(b.lastNow)
		wall := now.Round(0).Sub(b.lastNow.Round(0))
		if elapsed < 0 || elapsed > b.opts.ClockJump || absDuration(wall-elapsed) > b.opts.ClockJump {
			b.timeUncertain = true
		}
	}
	b.lastNow = now
	if b.timeUncertain {
		return nil
	}
	keys := make([]LeaseKey, 0, len(b.leases))
	for k := range b.leases {
		keys = append(keys, k)
	}
	orders := make(map[LeaseKey]string, len(keys))
	for _, k := range keys {
		orders[k] = leaseOrder(k)
	}
	sort.Slice(keys, func(i, j int) bool { return orders[keys[i]] < orders[keys[j]] })
	var removed []LeaseKey
	for _, k := range keys {
		l := b.leases[k]
		if now.Before(l.GraceUntil) || now.Before(l.FirstAdvertised.Add(b.opts.MinAdvertise)) {
			continue
		}
		if b.opts.BoundedActivity && now.Before(l.AbsoluteRetainUntil) {
			state := ActivityUnknown
			if activity != nil {
				state = activity.Activity(k.ProfileID, k.IP)
			}
			if state != ActivityIdle {
				continue
			}
		}
		removed = append(removed, k)
		delete(b.leases, k)
		if len(removed) == limit {
			break
		}
	}
	return removed
}
func absDuration(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}
func leaseOrder(k LeaseKey) string {
	return fmt.Sprintf("%q|%q|%q|%q|%s|%q", k.ProfileID, k.AssignedRoot, k.QName, k.Chain, k.IP, k.Source)
}

// AdvanceFence preserves references only in the same profile. Assigned-domain
// removal is explicit; callers retain only roots still granted by control.
func (b *LeaseBook) AdvanceFence(f featurepolicy.Fence, assigned func(string) bool) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	old := b.fence
	if f.ProfileID != old.ProfileID || f.Generation < old.Generation || f.AssignedDomainsEpoch < old.AssignedDomainsEpoch || f.PeerIdentityEpoch < old.PeerIdentityEpoch {
		return fmt.Errorf("lease: stale fence")
	}
	for k, l := range b.leases {
		if assigned != nil && !assigned(k.AssignedRoot) {
			delete(b.leases, k)
		} else {
			l.Fence = f
			b.leases[k] = l
		}
	}
	b.fence = f
	return nil
}

// TimeUncertain reports that destructive sweeps are frozen.
func (b *LeaseBook) TimeUncertain() bool { b.mu.Lock(); defer b.mu.Unlock(); return b.timeUncertain }

// ConfirmTime is an explicit trusted-time recovery action, never an automatic
// fresh grace window. Persist the resulting book before scheduling a sweep.
func (b *LeaseBook) ConfirmTime() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.timeUncertain = false
	b.lastNow = b.now()
}
