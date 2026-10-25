// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"tailscale.com/featurepolicy"
	"tailscale.com/ipn"
)

// UnifiedPolicyStore implements featurepolicy.Store in a captured profile
// namespace. It does not consult a mutable current-profile pointer during I/O.
// Construct it from a verified LoginProfile ID and Key at the lifecycle barrier.
// It never reads the identity-bearing profile state; only the separate sidecar.
type UnifiedPolicyStore struct {
	Store      ipn.StateStore
	ProfileID  string
	ProfileKey ipn.StateKey
}

// Load reads the captured profile's LKG independently of AppCStoreRoutes.
func (s UnifiedPolicyStore) Load(profile string) ([]byte, error) {
	if e := s.check(profile); e != nil {
		return nil, e
	}
	b, e := s.Store.ReadState(s.ProfileKey + "||_unifiedPolicyV1")
	if errors.Is(e, ipn.ErrStateNotExist) {
		e = fs.ErrNotExist
	}
	return b, e
}

// Save atomically writes a prepared LKG using the StateStore's durable contract.
func (s UnifiedPolicyStore) Save(profile string, b []byte) error {
	if e := s.check(profile); e != nil {
		return e
	}
	// Prepare the handoff BEFORE accepting a disabled LKG. A crash on either
	// side of the LKG write leaves a recoverable intent, never a completed handoff.
	var next struct{ Config json.RawMessage }
	if err := json.Unmarshal(b, &next); err != nil {
		return err
	}
	c, err := featurepolicy.Parse(next.Config)
	if err != nil {
		return err
	}
	if !c.Enabled || !c.Lease.Enabled && !c.AutoIPv6.Enabled {
		old, readErr := s.Load(profile)
		if readErr != nil && !errors.Is(readErr, fs.ErrNotExist) {
			return readErr
		}
		var previous struct{ Config json.RawMessage }
		if readErr == nil {
			if err := json.Unmarshal(old, &previous); err != nil {
				return err
			}
			pc, err := featurepolicy.Parse(previous.Config)
			if err != nil {
				return err
			}
			if pc.Enabled && (pc.Lease.Enabled || pc.AutoIPv6.Enabled) {
				if err := ipn.WriteState(s.Store, s.ProfileKey+"||_unifiedHandoffV1", []byte("pending")); err != nil {
					return err
				}
			}
		}
	}
	return ipn.WriteState(s.Store, s.ProfileKey+"||_unifiedPolicyV1", b)
}
func (s UnifiedPolicyStore) check(profile string) error {
	if s.Store == nil || s.ProfileID == "" || s.ProfileKey == "" || profile != s.ProfileID {
		return fmt.Errorf("policy store: profile mismatch or missing namespace")
	}
	return nil
}

// UnifiedLedgerStore implements RouteLedgerStore using an independent sidecar.
// ReadPrefs and ApplyPrefs are supplied by the serialized backend coordinator;
// ApplyPrefs must durably apply its CAS and fence before acknowledging success.
// Upstream editPrefsLocked alone is insufficient: setPrefsLocked at baseline
// local.go:5540 logs persistence errors but does not return them to its caller.
type UnifiedLedgerStore struct {
	Store      ipn.StateStore
	ProfileKey ipn.StateKey
	ReadPrefs  func() ([]netip.Prefix, error)
	ApplyPrefs func(before, desired []netip.Prefix) error
}

// Load reads only the ownership sidecar, never old identity or prefs bytes.
func (s UnifiedLedgerStore) Load() ([]byte, error) {
	if s.Store == nil || s.ProfileKey == "" {
		return nil, fmt.Errorf("ledger store: missing namespace")
	}
	b, e := s.Store.ReadState(s.ProfileKey + "||_unifiedRouteLedgerV1")
	if errors.Is(e, ipn.ErrStateNotExist) {
		e = fs.ErrNotExist
	}
	return b, e
}

// Save persists the journal independently of the AppCStoreRoutes control knob.
func (s UnifiedLedgerStore) Save(b []byte) error {
	if s.Store == nil || s.ProfileKey == "" {
		return fmt.Errorf("ledger store: missing namespace")
	}
	return ipn.WriteState(s.Store, s.ProfileKey+"||_unifiedRouteLedgerV1", b)
}

// Current returns the coordinator's actual current advertisement set.
func (s UnifiedLedgerStore) Current() ([]netip.Prefix, error) {
	if s.ReadPrefs == nil {
		return nil, fmt.Errorf("ledger store: missing prefs reader")
	}
	return s.ReadPrefs()
}

// Apply delegates to the durable, fenced CAS operation; it is never an ordinary
// user EditPrefs call and must not be marked as a manual owner update.
func (s UnifiedLedgerStore) Apply(before, desired []netip.Prefix) error {
	if s.ApplyPrefs == nil {
		return fmt.Errorf("ledger store: missing durable prefs writer")
	}
	return s.ApplyPrefs(before, desired)
}

// UnifiedLeaseStore captures a profile namespace independently of the legacy
// AppCStoreRoutes knob. It contains only lease evidence, not identity state.
type UnifiedLeaseStore struct {
	Store      ipn.StateStore
	ProfileKey ipn.StateKey
}

func (s UnifiedLeaseStore) Load() ([]byte, error) {
	if s.Store == nil || s.ProfileKey == "" {
		return nil, fmt.Errorf("lease store: missing namespace")
	}
	data, err := s.Store.ReadState(s.ProfileKey + "||_unifiedLeasesV1")
	if errors.Is(err, ipn.ErrStateNotExist) {
		err = fs.ErrNotExist
	}
	return data, err
}
func (s UnifiedLeaseStore) Save(data []byte) error {
	if s.Store == nil || s.ProfileKey == "" {
		return fmt.Errorf("lease store: missing namespace")
	}
	return ipn.WriteState(s.Store, s.ProfileKey+"||_unifiedLeasesV1", data)
}

// HandoffPending is independent of the LKG: acceptance is not application.
func (s UnifiedPolicyStore) HandoffPending() (bool, error) {
	if s.Store == nil || s.ProfileKey == "" {
		return false, nil
	}
	data, err := s.Store.ReadState(s.ProfileKey + "||_unifiedHandoffV1")
	if errors.Is(err, ipn.ErrStateNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	switch string(data) {
	case "pending":
		return true, nil
	case "complete":
		return false, nil
	default:
		return false, fmt.Errorf("handoff: corrupt transition marker")
	}
}
