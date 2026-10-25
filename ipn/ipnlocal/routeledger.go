// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"net/netip"
	"slices"
	"sync"
	"tailscale.com/featurepolicy"
	"tailscale.com/types/appctype"
)

// RouteLedgerStore is a profile-bound durable journal and atomic prefs adapter.
// Apply must compare exact current prefs with before and check the active profile
// and policy fence in the same critical section as its write. Save must be atomic
// and durable, leaving old bytes intact on failure. No callback may reenter the
// ledger. In production it belongs to the single LocalBackend coordinator.
type RouteLedgerStore interface {
	Load() ([]byte, error)
	Save([]byte) error
	Current() ([]netip.Prefix, error)
	Apply(before, desired []netip.Prefix) error
}

// PrefixOwners records exact ownership. CreatedByModule is evidence, never
// inferred merely because a prefix appears in old RouteInfo.Domains.
type PrefixOwners struct {
	Manual                bool
	Control               map[string]bool
	Auto                  map[string]bool
	LegacyUnknown         bool
	ExitDefault           bool
	CreatedByModule       bool
	AutoIPv6Blocked       bool
	FirstObservedRevision uint64
	AdvertisedRevision    uint64
}

func (o PrefixOwners) retained() bool {
	return o.Manual || len(o.Control) > 0 || len(o.Auto) > 0 || o.LegacyUnknown || o.ExitDefault
}
func (o PrefixOwners) nonAuto() bool {
	return o.Manual || len(o.Control) > 0 || o.LegacyUnknown || o.ExitDefault
}

type routeLedgerState struct {
	SchemaVersion int
	Fence         featurepolicy.Fence
	Sequence      uint64
	Applied       uint64
	Owners        map[netip.Prefix]PrefixOwners
	Before        []netip.Prefix
	Desired       []netip.Prefix
	Pending       bool
}
type ledgerEnvelope struct {
	Payload json.RawMessage
	SHA256  [32]byte
}

// RouteLedger serializes owner changes through intent -> prefs -> applied.
// It never withdraws a prefix without module-created evidence, even after an
// unexplained external write or a legacy migration. Nil backend installation is
// the default-off fast path; constructing a ledger itself does not modify prefs.
type RouteLedger struct {
	mu              sync.Mutex
	fence           featurepolicy.Fence
	store           RouteLedgerStore
	state           routeLedgerState
	degraded        bool
	blockAutoIPv6   bool
	retainAutomatic func(string) bool
}

// NewRouteLedger loads one profile's sidecar. Corruption blocks activation.
// Recovery must complete before new events may be consumed.
func NewRouteLedger(f featurepolicy.Fence, store RouteLedgerStore) (*RouteLedger, error) {
	return loadRouteLedger(f, store, false, false)
}

func newRouteLedgerPolicy(f featurepolicy.Fence, store RouteLedgerStore, blockIPv6 bool) (*RouteLedger, error) {
	return loadRouteLedger(f, store, blockIPv6, true)
}
func loadRouteLedger(f featurepolicy.Fence, store RouteLedgerStore, blockIPv6, rebase bool) (*RouteLedger, error) {
	if store == nil {
		return nil, fmt.Errorf("ledger requires durable store")
	}
	l := &RouteLedger{fence: f, store: store, blockAutoIPv6: blockIPv6, state: routeLedgerState{SchemaVersion: 1, Fence: f, Owners: map[netip.Prefix]PrefixOwners{}}}
	data, e := store.Load()
	if errors.Is(e, fs.ErrNotExist) {
		return l, nil
	}
	if e != nil {
		return nil, e
	}
	var env ledgerEnvelope
	if e = json.Unmarshal(data, &env); e != nil {
		return nil, e
	}
	if sha256.Sum256(env.Payload) != env.SHA256 {
		return nil, fmt.Errorf("ledger checksum")
	}
	if e = json.Unmarshal(env.Payload, &l.state); e != nil {
		return nil, e
	}
	s := &l.state
	if s.SchemaVersion != 1 || s.Fence.ProfileID != f.ProfileID || s.Fence.Generation > f.Generation || (s.Fence.Generation == f.Generation && (s.Fence.AssignedDomainsEpoch > f.AssignedDomainsEpoch || s.Fence.PeerIdentityEpoch > f.PeerIdentityEpoch)) || s.Owners == nil || s.Applied > s.Sequence || (!s.Pending && s.Applied != s.Sequence) {
		return nil, fmt.Errorf("ledger invalid state/fence")
	}
	for p, o := range s.Owners {
		if !validLedgerPrefix(p) || o.ExitDefault && p.Bits() != 0 || len(o.Auto) > 0 && !p.IsSingleIP() {
			return nil, fmt.Errorf("ledger invalid owner")
		}
	}
	for _, p := range append(slices.Clone(s.Before), s.Desired...) {
		if !validLedgerPrefix(p) {
			return nil, fmt.Errorf("ledger invalid journal prefix")
		}
	}
	// An old-epoch intent may add stale routes or remove newly required ones.
	// Reject activation until the coordinator provides a fresh reconciliation;
	// never replay it under a new epoch merely because the profile is unchanged.
	if s.Pending && s.Fence != f {
		if !rebase {
			return nil, fmt.Errorf("ledger pending intent requires original fence recovery")
		}
		current, err := store.Current()
		if err != nil {
			return nil, err
		}
		// Superseded intent is not replayed. Keep current non-auto evidence,
		// protect ambiguous interrupted removals, and let fresh producers
		// re-establish additions under the current domain/family policy.
		for p, o := range s.Owners {
			present := slices.Contains(current, p)
			if !present {
				o.Auto = nil
				o.Control = nil
			}
			if present && !o.retained() {
				o.LegacyUnknown = true
			}
			s.Owners[p] = o
		}
		s.Before = sortedRoutes(current)
		s.Desired = sortedRoutes(current)
		s.Pending = false
		s.Applied = s.Sequence
	}
	if s.Fence != f {
		s.Fence = f
		s.Sequence = 0
		s.Applied = 0
	}
	return l, nil
}
func validLedgerPrefix(p netip.Prefix) bool {
	return p.IsValid() && p == p.Masked() && !p.Addr().Is4In6()
}
func sortedRoutes(ps []netip.Prefix) []netip.Prefix {
	ps = slices.Clone(ps)
	slices.SortFunc(ps, func(a, b netip.Prefix) int {
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c
		}
		return a.Bits() - b.Bits()
	})
	return slices.Compact(ps)
}
func cloneLedger(s routeLedgerState) routeLedgerState {
	s.Before = slices.Clone(s.Before)
	s.Desired = slices.Clone(s.Desired)
	s.Owners = maps.Clone(s.Owners)
	for p, o := range s.Owners {
		o.Control = maps.Clone(o.Control)
		o.Auto = maps.Clone(o.Auto)
		s.Owners[p] = o
	}
	return s
}

func (l *RouteLedger) save(s routeLedgerState) error {
	payload, e := json.Marshal(s)
	if e != nil {
		return e
	}
	b, e := json.Marshal(ledgerEnvelope{payload, sha256.Sum256(payload)})
	if e != nil {
		return e
	}
	return l.store.Save(b)
}

// Update replaces exactly one owner's contribution. Sequence is contiguous
// within a fence; reordered events require fresh desired-state reconciliation.
func (l *RouteLedger) Update(e appctype.RouteOwnerEvent) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.degraded || l.state.Pending {
		return fmt.Errorf("ledger recovery required")
	}
	if e.Fence != l.fence || e.Sequence != l.state.Sequence+1 {
		return fmt.Errorf("ledger stale fence or out-of-order event")
	}
	if e.Source != appctype.RouteOwnerManual && e.Source != appctype.RouteOwnerControl && e.Source != appctype.RouteOwnerAuto && e.Source != appctype.RouteOwnerReadvertise {
		return fmt.Errorf("ledger invalid update source")
	}
	if (e.Source == appctype.RouteOwnerAuto || e.Source == appctype.RouteOwnerControl) && e.OwnerID == "" {
		return fmt.Errorf("ledger owner id required")
	}
	for _, p := range e.Prefixes {
		if !validLedgerPrefix(p) || e.Source == appctype.RouteOwnerAuto && !p.IsSingleIP() {
			return fmt.Errorf("ledger invalid prefix")
		}
	}
	current, err := l.store.Current()
	if err != nil {
		return err
	}
	current = sortedRoutes(current)
	s := cloneLedger(l.state)
	s.Sequence = e.Sequence
	s.Fence = e.Fence
	protectExternal(&s, current)
	for p, o := range s.Owners {
		switch e.Source {
		case appctype.RouteOwnerManual:
			o.Manual = false
			o.ExitDefault = false
		case appctype.RouteOwnerControl:
			delete(o.Control, e.OwnerID)
		case appctype.RouteOwnerAuto:
			delete(o.Auto, e.OwnerID)
		}
		s.Owners[p] = o
	}
	if e.Source != appctype.RouteOwnerReadvertise {
		for _, p := range e.Prefixes {
			o, exists := s.Owners[p]
			if !exists {
				o.FirstObservedRevision = s.Sequence
			}
			switch e.Source {
			case appctype.RouteOwnerManual:
				if p.Bits() == 0 {
					o.ExitDefault = true
				} else {
					o.Manual = true
				}
			case appctype.RouteOwnerControl:
				if o.Control == nil {
					o.Control = map[string]bool{}
				}
				o.Control[e.OwnerID] = true
			case appctype.RouteOwnerAuto:
				if o.Auto == nil {
					o.Auto = map[string]bool{}
				}
				o.Auto[e.OwnerID] = true
				o.AutoIPv6Blocked = false
			}
			s.Owners[p] = o
		}
	}
	s.Before = current
	l.filterAutomatic(&s)
	s.Desired = desiredRoutes(s, current)
	for _, p := range s.Desired {
		if !slices.Contains(current, p) {
			o := s.Owners[p]
			o.CreatedByModule = true
			o.AdvertisedRevision = s.Sequence
			s.Owners[p] = o
		}
	}
	s.Pending = true
	if err = l.save(s); err != nil {
		return err
	}
	l.state = s
	return l.applyPending()
}

// protectExternal treats unexplained advertisements as unknown, even if a
// tombstone happens to mention that prefix from a previous module lifetime.
func protectExternal(s *routeLedgerState, current []netip.Prefix) {
	known := make(map[netip.Prefix]bool, len(s.Desired))
	for _, p := range s.Desired {
		known[p] = true
	}
	for _, p := range current {
		if !known[p] {
			o := s.Owners[p]
			o.LegacyUnknown = true
			s.Owners[p] = o
		}
	}
}
func desiredRoutes(s routeLedgerState, current []netip.Prefix) []netip.Prefix {
	var out []netip.Prefix
	for p, o := range s.Owners {
		if o.nonAuto() {
			out = append(out, p)
		}
	}
	// Only automatic host contributions can be covered; /0 never swallows them.
	for p, o := range s.Owners {
		if len(o.Auto) > 0 && !o.nonAuto() && !coveredRouteRangeNoDefault(out, p) {
			out = append(out, p)
		}
	}
	included := make(map[netip.Prefix]bool, len(out))
	for _, p := range out {
		included[p] = true
	}
	for _, p := range current {
		o, ok := s.Owners[p]
		if (!ok || !o.CreatedByModule) && !included[p] {
			included[p] = true
			out = append(out, p)
		}
	}
	return sortedRoutes(out)
}
func (l *RouteLedger) applyPending() error {
	s := l.state
	if err := l.store.Apply(s.Before, s.Desired); err != nil {
		l.degraded = true
		return err
	}
	s.Pending = false
	s.Applied = s.Sequence
	if err := l.save(s); err != nil {
		l.degraded = true
		return err
	}
	l.state = s
	l.degraded = false
	return nil
}

// Recover resolves a prepared intent idempotently. Unexplained concurrent prefs
// additions gain unknown ownership before any further side effects. Applied
// journal writes may be retried without repeating a successful prefs change.
func (l *RouteLedger) Recover() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	current, e := l.store.Current()
	if e != nil {
		return e
	}
	current = sortedRoutes(current)
	s := cloneLedger(l.state)
	if s.Pending && slices.Equal(current, s.Desired) && !l.needsIPv6Withdrawal(s) {
		s.Pending = false
		s.Applied = s.Sequence
		if e = l.save(s); e != nil {
			return e
		}
		l.state = s
		l.degraded = false
		return nil
	}
	if !s.Pending && slices.Equal(current, s.Desired) && !l.needsIPv6Withdrawal(s) {
		l.degraded = false
		return nil
	}
	// A current route in Before can be explained by a crash before Apply. Other
	// unexpected prefixes are external and must not be deleted by intent replay.
	for _, p := range current {
		if !slices.Contains(s.Desired, p) && (!s.Pending || !slices.Contains(s.Before, p)) {
			o := s.Owners[p]
			o.LegacyUnknown = true
			s.Owners[p] = o
		}
	}
	s.Before = current
	l.filterAutomatic(&s)
	s.Desired = desiredRoutes(s, current)
	s.Pending = true
	if e = l.save(s); e != nil {
		return e
	}
	l.state = s
	return l.applyPending()
}

// Owners returns a defensive snapshot for previews; it grants no claim authority.
func (l *RouteLedger) Owners() map[netip.Prefix]PrefixOwners {
	l.mu.Lock()
	defer l.mu.Unlock()
	return cloneLedger(l.state).Owners
}

// MigrationPlan binds dry-run observations to a complete legacy prefs/RouteInfo
// snapshot and policy fence. Unknown is never inferred to be exclusive auto.
type MigrationPlan struct {
	// Private authority is generated locally; decoded or edited display plans
	// cannot grant ownership. Always regenerate from current state.
	boundHash       string
	boundCandidates []netip.Prefix
	SnapshotHash    string
	Unknown         []netip.Prefix
	Control         []netip.Prefix
	ExitDefaults    []netip.Prefix
	Candidates      []netip.Prefix
}

// MigrationDryRun generates an audit-only plan. It performs no store/prefs write.
func MigrationDryRun(f featurepolicy.Fence, prefs []netip.Prefix, ri appctype.RouteInfo) MigrationPlan {
	prefs = sortedRoutes(prefs)
	copyRI := appctype.RouteInfo{Control: sortedRoutes(ri.Control), Wildcards: slices.Clone(ri.Wildcards), Domains: map[string][]netip.Addr{}}
	slices.Sort(copyRI.Wildcards)
	for d, ips := range ri.Domains {
		ips = slices.Clone(ips)
		slices.SortFunc(ips, func(a, b netip.Addr) int { return a.Compare(b) })
		copyRI.Domains[d] = slices.Compact(ips)
	}
	raw, _ := json.Marshal(struct {
		Fence     featurepolicy.Fence
		Prefs     []netip.Prefix
		RouteInfo appctype.RouteInfo
	}{f, prefs, copyRI})
	h := sha256.Sum256(raw)
	p := MigrationPlan{SnapshotHash: hex.EncodeToString(h[:]), Control: copyRI.Control}
	for _, r := range prefs {
		if r.Bits() == 0 {
			p.ExitDefaults = append(p.ExitDefaults, r)
		} else {
			p.Unknown = append(p.Unknown, r)
		}
	}
	for _, ips := range copyRI.Domains {
		for _, ip := range ips {
			r := netip.PrefixFrom(ip, ip.BitLen())
			if slices.Contains(prefs, r) {
				p.Candidates = append(p.Candidates, r)
			}
		}
	}
	p.Candidates = sortedRoutes(p.Candidates)
	p.boundHash = p.SnapshotHash
	p.boundCandidates = slices.Clone(p.Candidates)
	return p
}

// ValidateClaims checks a proposed reviewed manifest against this exact dry run.
// It does not execute adoption, remove unknown, or remove manual/control owners.
func (p MigrationPlan) ValidateClaims(expectedHash string, claims []netip.Prefix) error {
	if p.boundHash == "" || expectedHash != p.boundHash || p.SnapshotHash != p.boundHash {
		return fmt.Errorf("migration snapshot changed")
	}
	seen := map[netip.Prefix]bool{}
	for _, r := range claims {
		if !validLedgerPrefix(r) || !r.IsSingleIP() || !slices.Contains(p.boundCandidates, r) || seen[r] {
			return fmt.Errorf("invalid migration claim")
		}
		seen[r] = true
	}
	return nil
}

// filterAutomatic is the final desired-union gate, shared by update and crash
// recovery. It removes only automatic contributions, regardless of activity.
func (l *RouteLedger) filterAutomatic(s *routeLedgerState) {
	for p, o := range s.Owners {
		for id := range o.Auto {
			if l.retainAutomatic != nil && !l.retainAutomatic(id) {
				delete(o.Auto, id)
			}
		}
		s.Owners[p] = o
	}
	if !l.blockAutoIPv6 {
		return
	}
	for p, o := range s.Owners {
		if p.Addr().Is6() && p.IsSingleIP() {
			if len(o.Auto) > 0 {
				o.AutoIPv6Blocked = true
			}
			o.Auto = nil
			s.Owners[p] = o
		}
	}
}
func (l *RouteLedger) needsIPv6Withdrawal(s routeLedgerState) bool {
	if !l.blockAutoIPv6 {
		return false
	}
	for p, o := range s.Owners {
		if p.Addr().Is6() && len(o.Auto) > 0 {
			return true
		}
	}
	return false
}
