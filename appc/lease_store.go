// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package appc

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"tailscale.com/featurepolicy"
	"tailscale.com/util/jsonchecksum"
	"time"
)

type savedLease struct {
	Lease           Lease
	TTLRemaining    time.Duration
	GraceRemaining  time.Duration
	ActiveRemaining time.Duration
	DwellRemaining  time.Duration
}
type savedLeases struct {
	BootID           string
	Schema           int
	Fence            featurepolicy.Fence
	SavedAt          time.Time
	TimeUncertain    bool
	TimeConfirmation TimeConfirmation
	Leases           []savedLease
}
type leaseEnvelope struct {
	Payload json.RawMessage
	SHA256  [32]byte
}

// MarshalState stores wall deadlines and remaining monotonic lifetimes. The
// caller persists these bytes in the profile's StateStore, not a public file.
func (b *LeaseBook) MarshalState() ([]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	s := savedLeases{BootID: b.opts.BootID, Schema: 1, Fence: b.fence, SavedAt: now, TimeUncertain: b.timeUncertain, TimeConfirmation: b.timeConfirmation}
	for _, l := range b.leases {
		s.Leases = append(s.Leases, savedLease{l, max(0, l.Expires.Sub(now)), max(0, l.GraceUntil.Sub(now)), max(0, l.AbsoluteRetainUntil.Sub(now)), max(0, l.FirstAdvertised.Add(b.opts.MinAdvertise).Sub(now))})
	}
	return jsonchecksum.Marshal(s)
}

// RestoreLeaseBook checks corruption and profile identity. Deadlines never gain
// time across restart: min(saved remaining, wall remaining). A backward wall
// jump freezes deletion, and the flag survives repeated restarts. No hard bound
// on retention is claimed when wall time cannot be trusted across boots.
func RestoreLeaseBook(data []byte, f featurepolicy.Fence, o LeaseOptions, now func() time.Time) (*LeaseBook, error) {
	var env leaseEnvelope
	if e := json.Unmarshal(data, &env); e != nil {
		return nil, e
	}
	if sha256.Sum256(env.Payload) != env.SHA256 {
		return nil, fmt.Errorf("lease checksum")
	}
	var s savedLeases
	if e := json.Unmarshal(env.Payload, &s); e != nil {
		return nil, e
	}
	if s.Schema != 1 || s.Fence.ProfileID != f.ProfileID || s.Fence.Generation > f.Generation || (s.Fence.Generation == f.Generation && (s.Fence.AssignedDomainsEpoch > f.AssignedDomainsEpoch || s.Fence.PeerIdentityEpoch > f.PeerIdentityEpoch)) {
		return nil, fmt.Errorf("lease state fence")
	}
	b := NewLeaseBook(f, o, now)
	n := b.now()
	// Boot identity alone does not prove elapsed time across a process restart.
	// Until trusted time is supplied, protect routes even within the same boot.
	b.timeUncertain = s.TimeUncertain || n.Before(s.SavedAt.Add(-o.ClockJump)) || !o.TimeTrusted
	b.lastNow = n
	b.timeConfirmation = s.TimeConfirmation
	if len(s.Leases) > o.MaxEntries {
		return nil, fmt.Errorf("lease state capacity")
	}
	restore := func(deadline time.Time, remaining time.Duration) time.Time {
		// An expired deadline is historical evidence. Moving it to this boot
		// would reset reported expiry age on every restart, even while frozen.
		if !deadline.After(n) {
			return deadline
		}
		return n.Add(min(max(0, remaining), max(0, deadline.Sub(n))))
	}
	for _, v := range s.Leases {
		l := v.Lease
		if l.Key.ProfileID != f.ProfileID || !l.Key.IP.IsValid() || l.Key.IP.Is4In6() {
			return nil, fmt.Errorf("lease state key")
		}
		if _, ok := b.leases[l.Key]; ok {
			return nil, fmt.Errorf("duplicate lease")
		}
		l.Expires = restore(l.Expires, v.TTLRemaining)
		l.GraceUntil = restore(l.GraceUntil, v.GraceRemaining)
		l.AbsoluteRetainUntil = restore(l.AbsoluteRetainUntil, v.ActiveRemaining)
		l.FirstAdvertised = restore(l.FirstAdvertised.Add(o.MinAdvertise), v.DwellRemaining).Add(-o.MinAdvertise)
		l.Fence = f
		b.leases[l.Key] = l
	}
	return b, nil
}
