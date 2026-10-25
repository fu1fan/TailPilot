// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"tailscale.com/featurepolicy"
	"tailscale.com/ipn"
)

// The intent is durable before either authority changes. While pending, the
// lifecycle worker recovers it before installing consumers or accepting DNS.
// Recovery reuses the owner journal's CAS and unknown-owner protection.
type unifiedClearIntent struct {
	Schema      int
	Fence       featurepolicy.Fence
	PreviewHash string
	Source      string
	StartedAt   time.Time
	Complete    bool
	Leases      []byte
	Ledger      []byte
}

func clearKey(key ipn.StateKey) ipn.StateKey { return key + "||_unifiedClearV1" }
func writeClearIntent(store ipn.StateStore, key ipn.StateKey, v unifiedClearIntent) error {
	payload, err := json.Marshal(v)
	if err != nil {
		return err
	}
	data, err := json.Marshal(ledgerEnvelope{Payload: payload, SHA256: sha256.Sum256(payload)})
	if err != nil {
		return err
	}
	return ipn.WriteState(store, clearKey(key), data)
}
func readClearIntent(store ipn.StateStore, key ipn.StateKey) (unifiedClearIntent, error) {
	var v unifiedClearIntent
	data, err := store.ReadState(clearKey(key))
	if errors.Is(err, ipn.ErrStateNotExist) {
		return v, nil
	}
	if err != nil {
		return v, err
	}
	var env ledgerEnvelope
	if json.Unmarshal(data, &env) != nil || sha256.Sum256(env.Payload) != env.SHA256 || json.Unmarshal(env.Payload, &v) != nil || v.Schema != 1 {
		return v, fmt.Errorf("automatic clear: corrupt intent")
	}
	return v, nil
}

// applyClearIntent is idempotent. No completion is recorded until both
// authorities and prefs are durable. Store errors retain the pending intent.
func applyClearIntent(store ipn.StateStore, key ipn.StateKey, v unifiedClearIntent, adapter UnifiedLedgerStore) error {
	if v.Schema == 0 || v.Complete {
		return nil
	}
	if err := (UnifiedLeaseStore{store, key}).Save(v.Leases); err != nil {
		return err
	}
	if err := adapter.Save(v.Ledger); err != nil {
		return err
	}
	ledger, err := NewRouteLedger(v.Fence, adapter)
	if err != nil {
		return err
	}
	if err = ledger.Recover(); err != nil {
		return err
	}
	v.Complete = true
	return writeClearIntent(store, key, v)
}

// Legacy two-authority clear execution is retired. Pending historical intents
// remain recoverable before installing the Connector authority.
func (b *LocalBackend) clearUnifiedAutomatic(r *unifiedPolicyRuntime, req UnifiedDebugRequest, dry bool) (UnifiedAutomaticClearPlan, error) {
	return UnifiedAutomaticClearPlan{}, fmt.Errorf("legacy automatic clear retired; use appc-route-reset-preview")
}

// recoverUnifiedClear is called before any owner/lease consumer (also disable).
func (b *LocalBackend) recoverUnifiedClear(r *unifiedPolicyRuntime, s *featurepolicy.PolicySnapshot) error {
	b.mu.Lock()
	b.waitUnifiedPrefsTransactionLocked()
	if b.unifiedSnapshot != s || b.unifiedPublishedRevision != b.unifiedRevision {
		b.mu.Unlock()
		return fmt.Errorf("automatic clear recovery: stale policy")
	}
	key, store := b.pm.CurrentProfile().Key(), b.pm.store
	if key == "" || store == nil {
		b.mu.Unlock()
		return nil
	}
	next := b.pm.CurrentPrefs().AsStruct()
	current := sortedRoutes(next.AdvertiseRoutes)
	done := make(chan struct{})
	b.unifiedPrefsPending = done
	b.unifiedPrefsPendingSince = time.Now()
	b.mu.Unlock()
	intent, err := readClearIntent(store, key)
	var durable *ipn.Prefs
	if err == nil && intent.Schema != 0 && !intent.Complete {
		if intent.Fence.ProfileID != s.Fence().ProfileID {
			err = fmt.Errorf("automatic clear recovery: foreign profile")
		} else {
			adapter := UnifiedLedgerStore{Store: store, ProfileKey: key, ReadPrefs: func() ([]netip.Prefix, error) { return slices.Clone(current), nil }, ApplyPrefs: func(before, desired []netip.Prefix) error {
				if !slices.Equal(sortedRoutes(before), current) {
					return fmt.Errorf("automatic clear recovery: prefs CAS conflict")
				}
				next.AdvertiseRoutes = slices.Clone(desired)
				if err := ipn.WriteState(store, key, next.ToBytes()); err != nil {
					return err
				}
				current = slices.Clone(desired)
				durable = next.Clone()
				return nil
			}}
			err = applyClearIntent(store, key, intent, adapter)
		}
		b.logf("unified automatic clear recovery: complete=%t", err == nil)
	}
	b.mu.Lock()
	if durable != nil {
		b.installCommittedRoutePrefsLocked(durable)
	}
	b.unifiedPrefsPending = nil
	b.unifiedPrefsPendingSince = time.Time{}
	close(done)
	b.mu.Unlock()
	return err
}
