// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"fmt"
	"math/rand/v2"
	"net/netip"
	"slices"
	"time"

	"errors"
	"io/fs"
	"tailscale.com/appc"
	"tailscale.com/featurepolicy"
)

func (b *LocalBackend) configureUnifiedLeases(r *unifiedPolicyRuntime, s *featurepolicy.PolicySnapshot, roots []string) error {
	b.mu.Lock()
	b.waitUnifiedPrefsTransactionLocked()
	ac := b.appConnector
	control := slices.Clone(b.unifiedControlRoutes)
	b.mu.Unlock()
	if ac == nil {
		return fmt.Errorf("appc TTL: connector unavailable")
	}
	c := s.Config().Lease
	boot, _ := appc.SystemBootID()
	opts := appc.LeaseOptions{BootID: boot, TimeTrusted: false, Grace: time.Duration(c.GraceSeconds) * time.Second, MinAdvertise: time.Duration(c.MinAdvertiseSeconds) * time.Second, MaxActiveRetention: time.Duration(c.MaxActiveRetentionSeconds) * time.Second, BoundedActivity: c.ActivityMode == "bounded", MaxEntries: c.MaxEntries, ClockJump: time.Duration(c.ClockJumpSeconds) * time.Second}
	if r.connector != ac || r.leaseProfile != s.Fence().ProfileID {
		ac.SetLeaseObserver(roots, func([]appc.DNSLeaseObservation) error { return fmt.Errorf("appc TTL: installation pending") })
		ac.Wait(b.ctx)
		saved, err := b.connectorTransaction(s.Fence(), nil)
		if err != nil {
			return err
		}
		cfg := appc.ConnectorTTLConfig{Fence: s.Fence(), Roots: roots, Control: control, Options: opts}
		b.mu.Lock()
		b.waitUnifiedPrefsTransactionLocked()
		// Replay can publish changed prefs and trigger a new control snapshot.
		// Do not publish a takeover with that old fence: a failed install is
		// deliberately quarantined and cannot be retried in place.
		if b.unifiedSnapshot != s || b.unifiedPublishedRevision != b.unifiedRevision || b.appConnector != ac {
			b.mu.Unlock()
			return fmt.Errorf("appc TTL: inputs changed during recovery")
		}
		capturedStore, capturedKey := b.pm.store, b.pm.CurrentProfile().Key()
		b.mu.Unlock()
		adapter := &connectorBackend{b: b, ac: ac, store: capturedStore, key: capturedKey}
		cfg.Commit = adapter.commit
		if saved.Schema != 0 && !saved.Handoff {
			cfg.Restore = saved.Transition.AfterLeaseState
			cfg.Legacy = saved.Transition.After.Legacy
			cfg.Revision = saved.Transition.After.Revision
			// Restore the prior assignment first; configure prunes changed roots only
			// after the old book and its ownership have been durably recovered.
			cfg.Roots = saved.Transition.After.Roots
			cfg.Control = saved.Transition.After.Control
		} else {
			b.mu.Lock()
			b.waitUnifiedPrefsTransactionLocked()
			st, k := b.pm.store, b.pm.CurrentProfile().Key()
			b.mu.Unlock()
			data, e := (UnifiedLeaseStore{st, k}).Load()
			if e == nil && !saved.Handoff {
				cfg.Restore = data
			} else if e != nil && !errors.Is(e, fs.ErrNotExist) {
				return e
			}
		}
		if err = ac.InstallTTLTakeover(cfg); err != nil {
			return err
		}
		r.connector, r.connectorAdapter, r.leaseProfile = ac, adapter, s.Fence().ProfileID
		r.packets = appc.NewPacketActivity(s.Fence().ProfileID, c.MaxFlowEntries, time.Duration(c.UDPIdleSeconds)*time.Second, time.Now)
	}
	state, err := ac.TTLState()
	if err != nil {
		return err
	}
	if state.Fence != s.Fence() || !slices.Equal(state.Roots, roots) || !slices.Equal(state.Control, control) {
		if err = ac.ConfigureTTL(s.Fence(), roots, control, opts); err != nil {
			return err
		}
	}
	r.packets.Configure(c.MaxFlowEntries, time.Duration(c.UDPIdleSeconds)*time.Second)
	if b.sys != nil {
		if tun, ok := b.sys.Tun.GetOK(); ok {
			tun.SetActivityObserver(r.packets.Observe)
		}
	}
	r.nextSweep = time.Now().Add(time.Duration(c.SweepSeconds) * time.Second)
	return nil
}

func (b *LocalBackend) sweepUnifiedLeases(r *unifiedPolicyRuntime, s *featurepolicy.PolicySnapshot) error {
	if r.connector == nil || !s.Enabled() || !s.Config().Lease.Enabled || time.Now().Before(r.nextSweep) {
		return nil
	}
	c := s.Config().Lease
	jitter := time.Duration(rand.Int64N(int64(c.JitterSeconds)*int64(time.Second) + 1))
	r.nextSweep = time.Now().Add(time.Duration(c.SweepSeconds)*time.Second + jitter)
	state, err := r.connector.TTLState()
	if err != nil {
		return err
	}
	var ips []netip.Addr
	for _, l := range state.Leases {
		ips = append(ips, l.Key.IP)
	}
	r.packets.SetManaged(ips)
	activity := appc.NewSystemActivity(s.Fence().ProfileID, ips, c.MaxFlowEntries, time.Duration(c.SweepSeconds+c.JitterSeconds+1)*time.Second)
	_ = activity.Refresh()
	return r.connector.SweepTTL(s.Fence(), c.BatchSize, appc.CombinedActivity{Kernel: activity, Packets: r.packets})
}

func (b *LocalBackend) clearUnifiedActivity() {
	if b.sys != nil {
		if tun, ok := b.sys.Tun.GetOK(); ok {
			tun.SetActivityObserver(nil)
		}
	}
}
