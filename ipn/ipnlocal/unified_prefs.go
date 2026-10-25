// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"fmt"
	"net/netip"
	"slices"
	"time"

	"tailscale.com/featurepolicy"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnauth"
)

// prepareRouteCAS validates a route-only change against the current full prefs.
// It does no I/O or publication. Call under b.mu after entering the prefs barrier.
func (pm *profileManager) prepareRouteCAS(profile string, before, desired []netip.Prefix) (ipn.PrefsView, error) {
	p := pm.CurrentProfile()
	if string(p.ID()) != profile || p.Key() == "" || pm.store == nil {
		return ipn.PrefsView{}, fmt.Errorf("durable routes: unavailable profile store")
	}
	old := pm.CurrentPrefs()
	if !slices.Equal(sortedRoutes(old.AdvertiseRoutes().AsSlice()), sortedRoutes(before)) {
		return ipn.PrefsView{}, fmt.Errorf("durable routes: prefs CAS conflict")
	}
	for _, p := range desired {
		if !validLedgerPrefix(p) {
			return ipn.PrefsView{}, fmt.Errorf("durable routes: invalid prefix")
		}
	}
	next := old.AsStruct()
	next.AdvertiseRoutes = sortedRoutes(desired)
	return next.View(), nil
}

// persistRouteCAS is the synchronous adapter for standalone profile managers.
// LocalBackend uses prepareRouteCAS and the transaction barrier below instead.
func (pm *profileManager) persistRouteCAS(profile string, before, desired []netip.Prefix) (ipn.PrefsView, error) {
	next, err := pm.prepareRouteCAS(profile, before, desired)
	if err != nil {
		return ipn.PrefsView{}, err
	}
	if err := pm.writePrefsToStore(pm.CurrentProfile().Key(), next); err != nil {
		return ipn.PrefsView{}, err
	}
	return next, nil
}

// waitUnifiedPrefsTransactionLocked must run immediately after acquiring b.mu
// at every prefs/profile writer entry, BEFORE reading candidates or validating
// actors. Normal writers remain serialized by b.mu. A route commit temporarily
// releases b.mu for I/O; this barrier excludes other writers for that interval.
// Read-only backend operations can still acquire b.mu and see committed state.
// Reacquiring callers loop because another transaction may have begun meanwhile.
func (b *LocalBackend) waitUnifiedPrefsTransactionLocked() {
	for b.unifiedPrefsPending != nil {
		done := b.unifiedPrefsPending
		b.mu.Unlock()
		<-done
		b.mu.Lock()
	}
}

// applyUnifiedRoutes is the backend half of UnifiedLedgerStore.Apply. Call
// without an appc or backend lock held. The writer barrier spans validation,
// durable I/O (outside b.mu), and installation. Policy publication and input
// changes use the same barrier, so the fence cannot change during persistence.
// Legacy writers still do their own I/O under b.mu; this does not yet move all
// profileManager persistence out of b.mu or activate the daemon coordinator.
func (b *LocalBackend) applyUnifiedRoutes(f featurepolicy.Fence, before, desired []netip.Prefix) error {
	b.mu.Lock()
	b.waitUnifiedPrefsTransactionLocked()
	defer b.mu.Unlock()
	if b.unifiedSnapshot == nil || !b.unifiedSnapshot.OwnershipEnabled() || b.unifiedPublishedRevision != b.unifiedRevision || b.unifiedSnapshot.Fence() != f {
		return fmt.Errorf("durable routes: stale policy fence")
	}
	mp := &ipn.MaskedPrefs{AdvertiseRoutesSet: true, Prefs: ipn.Prefs{AdvertiseRoutes: slices.Clone(desired)}}
	if err := b.checkEditPrefsAccessLocked(ipnauth.Self, b.pm.CurrentPrefs(), mp); err != nil {
		return err
	}
	candidate := b.pm.CurrentPrefs().AsStruct()
	candidate.ApplyEdits(mp)
	if err := b.checkPrefsLocked(candidate); err != nil {
		return err
	}
	next, err := b.pm.prepareRouteCAS(f.ProfileID, before, desired)
	if err != nil {
		return err
	}
	// Capture the complete immutable record and namespace before releasing mu.
	// No profile or prefs mutation can pass the barrier until installation.
	store, key := b.pm.store, b.pm.CurrentProfile().Key()
	data := next.ToBytes()
	done := make(chan struct{})
	b.unifiedPrefsPendingSince = time.Now()
	b.unifiedPrefsPending = done
	b.mu.Unlock()
	err = ipn.WriteState(store, key, data)
	b.mu.Lock()
	// We still hold mu until the committed state is installed (or the error
	// returned). Awakened writers cannot capture candidates before that point.
	b.unifiedPrefsPending = nil
	b.unifiedPrefsPendingSince = time.Time{}
	close(done)
	if err != nil {
		return err
	}
	b.installCommittedRoutePrefsLocked(next.AsStruct())
	return nil
}
