// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"tailscale.com/appc"
	"tailscale.com/featurepolicy"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnauth"
	"tailscale.com/types/appctype"
)

// ownershipRequestedLocked includes a temporarily invalidated snapshot: a
// control/profile transition must not fall back to the untyped writer.
func (b *LocalBackend) ownershipRequestedLocked() bool {
	return b.unifiedOwnership || b.unifiedSnapshot != nil && b.unifiedSnapshot.OwnershipEnabled()
}

// ApplyUnifiedOwner is the synchronous typed-owner consumer. Producers capture
// the fence when work is created, not when a delayed queue entry is consumed.
// Sequence zero is assigned here, at the daemon's single-writer barrier.
func (b *LocalBackend) ApplyUnifiedOwner(e appctype.RouteOwnerEvent) error {
	b.mu.Lock()
	b.waitUnifiedPrefsTransactionLocked()
	defer b.mu.Unlock()
	if e.Source == appctype.RouteOwnerManual {
		return fmt.Errorf("manual owner requires EditPrefsAs")
	}
	return b.applyUnifiedOwnerLocked(e, nil, nil, nil)
}

// applyUnifiedOwnerLocked owns the writer barrier across the entire journal,
// prefs, applied transaction. No appc lock may be held by a caller. Other backend
// writers and policy publication wait; readers keep seeing committed prefs.
// The separate ledger namespace cannot be overwritten by upstream SetPrefs.
func (b *LocalBackend) applyUnifiedOwnerLocked(e appctype.RouteOwnerEvent, candidate *ipn.Prefs, mp *ipn.MaskedPrefs, actor ipnauth.Actor) error {
	s := b.unifiedSnapshot
	if b.unifiedTTLBlocked {
		return fmt.Errorf("appc TTL: restart recovery required")
	}
	if s == nil || !s.OwnershipEnabled() || b.unifiedRevision != b.unifiedPublishedRevision || e.Fence != s.Fence() {
		return fmt.Errorf("owner: stale policy fence")
	}
	profile := b.pm.CurrentProfile()
	if string(profile.ID()) != e.Fence.ProfileID || profile.Key() == "" || b.pm.store == nil {
		return fmt.Errorf("owner: missing profile store")
	}
	// A control-map echo often asks to readvertise an already committed union.
	// With a ready consumer the cached ownership view is authoritative. Avoid
	// reopening and rewriting large journals for this no-op; changed unions
	// still go through the durable transaction below.
	if e.Source == appctype.RouteOwnerReadvertise && e.Sequence == 0 && b.unifiedConsumerFence == e.Fence && b.unifiedOwnersProfile == e.Fence.ProfileID && b.unifiedOwners != nil {
		current := sortedRoutes(b.pm.CurrentPrefs().AdvertiseRoutes().AsSlice())
		if slices.Equal(current, desiredRoutes(routeLedgerState{Owners: b.unifiedOwners}, current)) {
			return nil
		}
	}
	old := b.pm.CurrentPrefs()
	if candidate == nil {
		candidate = old.AsStruct()
	}
	store, key := b.pm.store, profile.Key()
	current := sortedRoutes(old.AdvertiseRoutes().AsSlice())
	roots := slices.Clone(b.unifiedDomains)
	blockV6 := s.Config().AutoIPv6.Enabled && !s.Config().AutoIPv6.Publish
	var durable *ipn.Prefs
	applyCandidate := old.AsStruct()
	applyingEdit, editDurable := false, false
	done := make(chan struct{})
	b.unifiedPrefsPendingSince = time.Now()
	b.unifiedPrefsPending = done
	b.mu.Unlock()
	adapter := UnifiedLedgerStore{Store: store, ProfileKey: key,
		ReadPrefs: func() ([]netip.Prefix, error) { return slices.Clone(current), nil },
		ApplyPrefs: func(before, desired []netip.Prefix) error {
			if !slices.Equal(sortedRoutes(before), current) {
				return fmt.Errorf("owner: prefs CAS conflict")
			}
			next := applyCandidate.Clone()
			next.AdvertiseRoutes = slices.Clone(desired)
			// This callback is inside our pending barrier. Reacquiring mu must not
			// wait on our own channel. Validate the final union, not just user input.
			b.mu.Lock()
			err := b.checkPrefsLocked(next)
			b.mu.Unlock()
			if err != nil {
				return err
			}
			if err := ipn.WriteState(store, key, next.ToBytes()); err != nil {
				return err
			}
			durable = next
			editDurable = applyingEdit
			current = slices.Clone(desired)
			return nil
		},
	}
	ttlIntent, ttlErr := readConnectorIntent(store, key)
	intent, err := readClearIntent(store, key)
	if ttlErr != nil {
		err = ttlErr
	} else if ttlIntent.Schema != 0 && !ttlIntent.Complete {
		err = fmt.Errorf("appc TTL: recovery required")
	}
	var ledger *RouteLedger
	if err == nil && intent.Schema != 0 && !intent.Complete {
		err = fmt.Errorf("automatic clear: recovery pending")
	}
	if err == nil {
		ledger, err = newRouteLedgerPolicy(e.Fence, adapter, blockV6)
	}
	if err == nil {
		ledger.retainAutomatic = func(id string) bool {
			if !strings.HasPrefix(id, "dns/") {
				return true
			}
			fields := strings.Split(id, "/")
			return len(fields) == 4 && slices.Contains(roots, fields[1])
		}
		// Only resolve a pending transaction here. A fresh manual event must not
		// persist its unrelated edits as a side effect of migration recovery.
		if ledger.state.Pending {
			err = ledger.Recover()
		}
		if err == nil {
			applyCandidate = candidate
			applyingEdit = true
			if e.Sequence == 0 {
				e.Sequence = ledger.state.Sequence + 1
			}
			err = ledger.Update(e)
		}
	}
	b.mu.Lock()
	b.unifiedPrefsPending = nil
	b.unifiedPrefsPendingSince = time.Time{}
	close(done)
	if err == nil {
		b.unifiedOwners = ledger.Owners()
		b.unifiedOwnersProfile = e.Fence.ProfileID
	}
	if durable != nil {
		// A failed final journal save is not an applied acknowledgement. Prefs did
		// become durable, so install that exact record and retain pending recovery.
		if mp != nil && editDurable {
			b.onEditPrefsLocked(actor, mp, old, durable.View())
		}
		b.installCommittedRoutePrefsLocked(durable)
	}
	if err != nil {
		b.noteUnifiedIssueLocked(unifiedCauseOwner, err)
		b.unifiedStatus.Applied = featurepolicy.Fence{}
		b.unifiedStatus.Reconciling = true
		b.unifiedStatus.Degraded = b.unifiedDegradedFromHealthLocked()
	}
	return err
}

// UnifiedMigrationDryRun reads legacy state under the writer barrier. It never
// adopts a route and never writes state. The hash includes the active fence.
func (b *LocalBackend) UnifiedMigrationDryRun() (MigrationPlan, error) {
	b.mu.Lock()
	b.waitUnifiedPrefsTransactionLocked()
	defer b.mu.Unlock()
	if b.unifiedSnapshot == nil || b.unifiedPublishedRevision != b.unifiedRevision {
		return MigrationPlan{}, fmt.Errorf("migration: policy not ready")
	}
	ri, err := b.readRouteInfoLocked()
	if err == ipn.ErrStateNotExist {
		ri = &appctype.RouteInfo{}
		err = nil
	}
	if err != nil {
		return MigrationPlan{}, err
	}
	return MigrationDryRun(b.unifiedSnapshot.Fence(), b.pm.CurrentPrefs().AdvertiseRoutes().AsSlice(), *ri), nil
}

// reconcileUnifiedOwnerConsumer runs on the existing lifecycle worker, outside
// b.mu. DNS callbacks are synchronous so durable failure reaches PeerAPI's
// LeaseObservationError -> SERVFAIL path. Old callbacks carry an old fence.
func (b *LocalBackend) reconcileUnifiedOwnerConsumer(r *unifiedPolicyRuntime, s *featurepolicy.PolicySnapshot) (err error) {
	defer func() {
		if err != nil {
			return
		}
		b.mu.Lock()
		b.waitUnifiedPrefsTransactionLocked()
		defer b.mu.Unlock()
		if b.unifiedSnapshot != s || b.unifiedPublishedRevision != b.unifiedRevision {
			err = fmt.Errorf("owner consumer changed during installation")
			return
		}
		b.unifiedConsumerFence = s.Fence()
	}()
	b.mu.Lock()
	b.waitUnifiedPrefsTransactionLocked()
	if b.unifiedSnapshot != s || b.unifiedPublishedRevision != b.unifiedRevision {
		b.mu.Unlock()
		return fmt.Errorf("owner consumer: stale snapshot")
	}
	ac := b.appConnector
	roots := slices.Clone(b.unifiedDomains)
	control := slices.Clone(b.unifiedControlRoutes)
	b.mu.Unlock()
	if r.connector != nil && r.leaseProfile != s.Fence().ProfileID {
		r.connectorAdapter.detached = true
		if err := r.connector.HandoffTTL("profile-handoff"); err != nil {
			return err
		}
		r.connector = nil
		r.connectorAdapter = nil
		b.clearUnifiedActivity()
	}
	if err := b.recoverUnifiedClear(r, s); err != nil {
		return err
	}
	if !s.OwnershipEnabled() {
		if r.connector != nil {
			if err := r.connector.HandoffTTL("all-off"); err != nil {
				return err
			}
			r.connector = nil
			r.connectorAdapter = nil
		}
		b.clearUnifiedActivity()
		if err := b.finishConnectorHandoff(s.Fence()); err != nil {
			return err
		}
		if err := b.handoffUnifiedOwnership(s); err != nil {
			return err
		}
		if ac != nil {
			ac.SetLeaseObserver(nil, nil)
		}
		return nil
	}
	if s.Config().Lease.Enabled {
		return b.configureUnifiedLeases(r, s, roots)
	}
	if r.connector != nil {
		if err := r.connector.HandoffTTL("policy-disable"); err != nil {
			return err
		}
		r.connector = nil
		r.connectorAdapter = nil
	}
	if err := b.ApplyUnifiedOwner(appctype.RouteOwnerEvent{Fence: s.Fence(), Source: appctype.RouteOwnerControl, OwnerID: "appc-control", Prefixes: control}); err != nil {
		return err
	}
	b.clearUnifiedActivity()
	if ac != nil {
		ac.SetLeaseObserver(roots, func(obs []appc.DNSLeaseObservation) error {
			for _, o := range obs {
				p := netip.PrefixFrom(o.IP, o.IP.BitLen())
				if !allowedAutoRoute(p) {
					continue
				}
				// A separate owner for each root/question/address preserves shared IPs.
				id := "dns/" + o.AssignedRoot + "/" + o.QName + "/" + o.IP.String()
				if err := b.ApplyUnifiedOwner(appctype.RouteOwnerEvent{Fence: s.Fence(), Source: appctype.RouteOwnerAuto, OwnerID: id, Prefixes: []netip.Prefix{p}}); err != nil {
					return err
				}
			}
			return nil
		})
	}
	return nil
}

// UnifiedIPv6Diagnostics distinguishes shared-owner retention from migration
// ambiguity. Neither diagnostic grants ownership or claims production readiness.
func (b *LocalBackend) UnifiedIPv6Diagnostics() (shared, unknown []netip.Prefix) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.pm == nil || b.unifiedOwnersProfile != string(b.pm.CurrentProfile().ID()) {
		return nil, nil
	}
	for p, o := range b.unifiedOwners {
		if !p.Addr().Is6() || !p.IsSingleIP() {
			continue
		}
		if o.LegacyUnknown {
			unknown = append(unknown, p)
		}
		if o.AutoIPv6Blocked && o.nonAuto() {
			shared = append(shared, p)
		}
	}
	return sortedRoutes(shared), sortedRoutes(unknown)
}

// UnifiedAutomaticClearPlan is the independent debug-operation boundary for
// Patch08. An ordinary set never consumes this plan or clears automatic state.
// Execution binds lease evidence too and uses a recoverable intent spanning
// both authorities; a route-only clear would be resurrected.
type UnifiedAutomaticClearPlan struct {
	Fence        featurepolicy.Fence
	SnapshotHash string
	Withdraw     []netip.Prefix
	EvidenceOnly []netip.Prefix
	Retain       []netip.Prefix
}

func (b *LocalBackend) PreviewUnifiedAutomaticClear() (UnifiedAutomaticClearPlan, error) {
	b.mu.Lock()
	b.waitUnifiedPrefsTransactionLocked()
	defer b.mu.Unlock()
	return b.previewUnifiedAutomaticClearLocked()
}
func (b *LocalBackend) previewUnifiedAutomaticClearLocked() (UnifiedAutomaticClearPlan, error) {
	if !b.ownershipRequestedLocked() || b.unifiedSnapshot == nil || b.unifiedPublishedRevision != b.unifiedRevision || b.unifiedOwnersProfile != string(b.pm.CurrentProfile().ID()) {
		return UnifiedAutomaticClearPlan{}, fmt.Errorf("automatic clear: owners not ready")
	}
	plan := UnifiedAutomaticClearPlan{Fence: b.unifiedSnapshot.Fence()}
	for p, o := range b.unifiedOwners {
		if len(o.Auto) == 0 && !o.AutoIPv6Blocked {
			continue
		}
		if o.CreatedByModule && !o.nonAuto() {
			plan.Withdraw = append(plan.Withdraw, p)
		} else {
			plan.Retain = append(plan.Retain, p)
		}
	}
	plan.Withdraw, plan.Retain = sortedRoutes(plan.Withdraw), sortedRoutes(plan.Retain)
	data, err := json.Marshal(struct {
		Fence  featurepolicy.Fence
		Owners map[netip.Prefix]PrefixOwners
		Prefs  []netip.Prefix
	}{plan.Fence, b.unifiedOwners, sortedRoutes(b.pm.CurrentPrefs().AdvertiseRoutes().AsSlice())})
	if err != nil {
		return UnifiedAutomaticClearPlan{}, err
	}
	digest := sha256.Sum256(data)
	plan.SnapshotHash = hex.EncodeToString(digest[:])
	return plan, nil
}
