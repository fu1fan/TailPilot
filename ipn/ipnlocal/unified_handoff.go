// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"slices"
	"strings"
	"time"

	"tailscale.com/appc"
	"tailscale.com/featurepolicy"
	"tailscale.com/ipn"
	"tailscale.com/types/appctype"
)

// compatibilityRouteInfo is a conservative handoff, not an ownership claim.
// Only proved exclusive module-created advertisements are handed back as
// automatic routes. Shared/manual/unknown prefixes stay in prefs unchanged.
func compatibilityRouteInfo(owners map[netip.Prefix]PrefixOwners, current []netip.Prefix, roots []string, control []netip.Prefix, leases []appc.Lease) appctype.RouteInfo {
	ri := appctype.RouteInfo{Control: slices.Clone(control), Domains: map[string][]netip.Addr{}}
	allowed := func(name string) bool {
		for _, r := range roots {
			if name == r || strings.HasPrefix(r, "*.") && strings.HasSuffix(name, r[1:]) && len(name) > len(r)-1 {
				return true
			}
		}
		return false
	}
	add := func(name string, ip netip.Addr) {
		p := netip.PrefixFrom(ip, ip.BitLen())
		o := owners[p]
		if !allowed(name) || !o.CreatedByModule || o.nonAuto() || len(o.Auto) == 0 || !slices.Contains(current, p) {
			return
		}
		ri.Domains[name] = append(ri.Domains[name], ip)
	}
	for _, root := range roots {
		if strings.HasPrefix(root, "*.") {
			ri.Wildcards = append(ri.Wildcards, root[2:])
		} else {
			ri.Domains[root] = nil
		}
	}
	for p, o := range owners {
		for id := range o.Auto {
			parts := strings.Split(id, "/")
			if len(parts) == 4 && parts[0] == "dns" {
				add(parts[2], p.Addr())
			}
		}
	}
	for _, l := range leases {
		add(l.Key.QName, l.Key.IP)
	}
	for d, ips := range ri.Domains {
		slices.SortFunc(ips, func(a, b netip.Addr) int { return a.Compare(b) })
		ri.Domains[d] = slices.Compact(ips)
	}
	return ri
}

// handoffUnifiedOwnership freezes writers while building and persisting the
// legacy view. It never applies a route diff and keeps both sidecars for restart.
func (b *LocalBackend) handoffUnifiedOwnership(s *featurepolicy.PolicySnapshot) error {
	b.mu.Lock()
	b.waitUnifiedPrefsTransactionLocked()
	if !b.unifiedOwnership {
		b.mu.Unlock()
		return nil
	}
	if b.unifiedSnapshot != s || b.unifiedPublishedRevision != b.unifiedRevision {
		b.mu.Unlock()
		return fmt.Errorf("handoff: stale policy")
	}
	p := b.pm.CurrentProfile()
	store, key := b.pm.store, p.Key()
	current := slices.Clone(b.pm.CurrentPrefs().AdvertiseRoutes().AsSlice())
	roots, control := slices.Clone(b.unifiedDomains), slices.Clone(b.unifiedControlRoutes)
	ac := b.appConnector
	done := make(chan struct{})
	b.unifiedPrefsPendingSince = time.Now()
	b.unifiedPrefsPending = done
	b.mu.Unlock()
	adapter := UnifiedLedgerStore{Store: store, ProfileKey: key, ReadPrefs: func() ([]netip.Prefix, error) { return current, nil }}
	_, err := (UnifiedPolicyStore{Store: store, ProfileKey: key}).HandoffPending()
	var ledger *RouteLedger
	if err == nil {
		ledger, err = newRouteLedgerPolicy(s.Fence(), adapter, false)
	}
	var leases []appc.Lease
	if err == nil {
		data, readErr := (UnifiedLeaseStore{Store: store, ProfileKey: key}).Load()
		if readErr == nil {
			book, restoreErr := appc.RestoreLeaseBook(data, s.Fence(), appc.LeaseOptions{MaxEntries: 100000, ClockJump: 5 * time.Minute}, time.Now)
			if restoreErr != nil {
				err = restoreErr
			} else {
				leases = book.Snapshot()
			}
		} else if !errors.Is(readErr, fs.ErrNotExist) {
			err = readErr
		}
	}
	if err == nil {
		ri := compatibilityRouteInfo(ledger.Owners(), current, roots, control, leases)
		ttl, e := readConnectorIntent(store, key)
		if e != nil {
			err = e
		} else if ttl.Schema != 0 {
			if !ttl.Complete || !ttl.Handoff {
				err = fmt.Errorf("appc TTL: durable handoff required")
			} else {
				ri = connectorCompatibility(ttl)
			}
		}
		if err != nil {
			b.mu.Lock()
			b.unifiedPrefsPending = nil
			b.unifiedPrefsPendingSince = time.Time{}
			close(done)
			b.mu.Unlock()
			return err
		}
		data, marshalErr := json.Marshal(ri)
		if marshalErr != nil {
			err = marshalErr
		} else {
			err = ipn.WriteState(store, key+"||_routeInfo", data)
		}
		if err == nil {
			err = ipn.WriteState(store, key+"||_unifiedHandoffV1", []byte("complete"))
		}
		if err == nil && ac != nil {
			ac.InstallLegacyRouteInfo(ri)
		}
	}
	b.logf("unified handoff: generation=%d complete=%t", s.Fence().Generation, err == nil)
	b.mu.Lock()
	b.unifiedPrefsPending = nil
	b.unifiedPrefsPendingSince = time.Time{}
	close(done)
	if err == nil {
		b.unifiedOwnership = false
	}
	b.mu.Unlock()
	return err
}
