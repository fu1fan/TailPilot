// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_appconnectors

package appc

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/featurepolicy"
)

// This fake is an atomic in-memory backend, not a production StateStore adapter.
// Non-Connector owners are independent of the entire Connector contribution.
type ttlBackend struct {
	last       ConnectorTTLTransition
	protected  []netip.Prefix
	advertised []netip.Prefix
	fail       bool
	prewrite   bool
	uncertain  bool
	commits    int
	attempts   int
}

func (b *ttlBackend) commit(tr ConnectorTTLTransition) error {
	b.attempts++
	if b.fail {
		return errors.New("injected disk failure")
	}
	if b.prewrite {
		return fmt.Errorf("injected fence reject: %w", ErrTTLCommitNotStarted)
	}
	if b.uncertain {
		return errors.New("injected uncertain persistence failure")
	}
	if b.commits > 0 && tr.Before.Hash() != b.last.After.Hash() {
		return errors.New("backend CAS")
	}
	b.last = tr
	b.commits++
	b.advertised = slices.Clone(b.protected)
	ri := tr.After.RouteInfo()
	b.advertised = append(b.advertised, ri.Control...)
	for _, ips := range ri.Domains {
		for _, ip := range ips {
			b.advertised = append(b.advertised, netip.PrefixFrom(ip, ip.BitLen()))
		}
	}
	slices.SortFunc(b.advertised, func(a, b netip.Prefix) int { return a.Compare(b) })
	b.advertised = slices.Compact(b.advertised)
	return nil
}
func ttlFixture(t *testing.T, legacy []LegacyDNSReference) (*AppConnector, *ttlBackend, *time.Time, featurepolicy.Fence) {
	t.Helper()
	now := time.Unix(10000, 0)
	f := featurepolicy.Fence{ProfileID: "test", Generation: 3}
	backend := &ttlBackend{protected: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0"), netip.MustParsePrefix("192.0.2.9/32"), netip.MustParsePrefix("198.51.100.1/32")}}
	ac := &AppConnector{sourceID: 123, logf: t.Logf}
	err := ac.InstallTTLTakeover(ConnectorTTLConfig{Fence: f, Roots: []string{"*.example.com"}, Control: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}, Legacy: legacy, Options: LeaseOptions{TimeTrusted: true, MaxEntries: 100, Grace: 2 * time.Second, ClockJump: time.Hour}, Now: func() time.Time { return now }, Commit: backend.commit})
	if err != nil {
		t.Fatal(err)
	}
	return ac, backend, &now, f
}
func ttlWire(t *testing.T, name string, ttl uint32) []byte {
	t.Helper()
	m := dnsmessage.Message{Header: dnsmessage.Header{Response: true}, Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName(name + "."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}, Answers: []dnsmessage.Resource{leaseA(name+".", ttl)}}
	b, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func mustTTL(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
func hasTTLRoute(b *ttlBackend) bool {
	return slices.Contains(b.advertised, netip.MustParsePrefix("192.0.2.1/32"))
}

func TestConnectorTTLImportResetRelearn(t *testing.T) {
	old := LegacyDNSReference{"*.example.com", "www.example.com", netip.MustParseAddr("192.0.2.1")}
	ac, b, now, f := ttlFixture(t, []LegacyDNSReference{old})
	*now = now.Add(10 * time.Minute)
	mustTTL(t, ac.SweepTTL(f, 100, nil))
	if !hasTTLRoute(b) {
		t.Fatal("invented TTL for old learning")
	}
	plan, err := ac.PreviewTTLReset()
	mustTTL(t, err)
	if len(plan.Domains[old.Domain]) != 1 || len(plan.PreserveControl) != 1 || len(plan.PreserveRoots) != 1 {
		t.Fatal(plan)
	}
	if ac.ResetTTL(plan.SnapshotHash, f.Generation, "") == nil {
		t.Fatal("missing source accepted")
	}
	if ac.ResetTTL(plan.SnapshotHash, f.Generation+1, "test") == nil {
		t.Fatal("wrong generation accepted")
	}
	mustTTL(t, ac.ResetTTL(plan.SnapshotHash, f.Generation, "operator-reviewed"))
	if hasTTLRoute(b) || len(ac.DomainRoutes()) != 0 {
		t.Fatal("learning not cleared")
	}
	for _, p := range b.protected {
		if !slices.Contains(b.advertised, p) {
			t.Fatal("lost protected owner", p)
		}
	}
	if !slices.Contains(b.advertised, plan.PreserveControl[0]) {
		t.Fatal("lost static route")
	}
	if ac.ResetTTL(plan.SnapshotHash, f.Generation, "repeat") == nil {
		t.Fatal("replayed preview")
	}
	mustTTL(t, ac.ObserveDNSResponse(ttlWire(t, old.Domain, 5)))
	if !hasTTLRoute(b) || len(ac.DomainRoutes()[old.Domain]) != 1 {
		t.Fatal("failed relearn")
	}
	*now = now.Add(6 * time.Second)
	mustTTL(t, ac.SweepTTL(f, 100, nil))
	if !hasTTLRoute(b) {
		t.Fatal("lost grace")
	}
	*now = now.Add(time.Second)
	mustTTL(t, ac.SweepTTL(f, 100, nil))
	if hasTTLRoute(b) || len(ac.DomainRoutes()[old.Domain]) != 0 {
		t.Fatal("expiry did not remove learning and advertisement")
	}
	if ac.ClearRoutes() == nil {
		t.Fatal("unguarded legacy clear accepted")
	}
}

func TestConnectorTTLSharedRenewalAndLegacy(t *testing.T) {
	legacy := []LegacyDNSReference{{"*.example.com", "www.example.com", netip.MustParseAddr("192.0.2.1")}, {"*.example.com", "other.example.com", netip.MustParseAddr("192.0.2.1")}}
	ac, b, now, f := ttlFixture(t, legacy)
	mustTTL(t, ac.ObserveDNSResponse(ttlWire(t, "www.example.com", 1)))
	if len(b.last.After.Legacy) != 1 {
		t.Fatal("wrong legacy references replaced")
	}
	*now = now.Add(4 * time.Second)
	mustTTL(t, ac.SweepTTL(f, 100, nil))
	if !hasTTLRoute(b) {
		t.Fatal("expired another domain's legacy reference")
	}
	mustTTL(t, ac.ObserveDNSResponse(ttlWire(t, "other.example.com", 5)))
	*now = now.Add(time.Second)
	mustTTL(t, ac.ObserveDNSResponse(ttlWire(t, "other.example.com", 10)))
	if len(b.last.After.Legacy) != 0 {
		t.Fatal("real observation did not take over legacy")
	}
	// The refresher merges deferred renewal before the next sweep in production.
	ac.ttl.Load().flushRefresh()
	*now = now.Add(7 * time.Second)
	mustTTL(t, ac.SweepTTL(f, 100, nil))
	if !hasTTLRoute(b) {
		t.Fatal("renewal shortened")
	}
	*now = now.Add(5 * time.Second)
	mustTTL(t, ac.SweepTTL(f, 100, nil))
	if hasTTLRoute(b) {
		t.Fatal("last reference did not expire")
	}
}

func TestConnectorTTLResetRollbackAndLateResponse(t *testing.T) {
	ac, b, now, f := ttlFixture(t, nil)
	wire := ttlWire(t, "www.example.com", 5)
	mustTTL(t, ac.ObserveDNSResponse(wire))
	expiry := b.last.After.Leases[0].Expires
	// This sink represents parsing that finished before reset but waited for the
	// writer. Its second epoch check is essential; the outer DNS check is too early.
	oldSink := ac.leaseSink.Load()
	p, err := ac.PreviewTTLReset()
	mustTTL(t, err)
	mustTTL(t, ac.ResetTTL(p.SnapshotHash, f.Generation, "reset"))
	obs, err := ParseLeaseDNS(wire, []string{"*.example.com"})
	mustTTL(t, err)
	if oldSink.observe(obs) == nil {
		t.Fatal("pre-reset response resurrected learning")
	}
	after, err := ac.PreviewTTLReset()
	mustTTL(t, err)
	*now = now.Add(2 * time.Second)
	mustTTL(t, ac.RollbackTTLReset(after.SnapshotHash, f.Generation, "rollback"))
	if !hasTTLRoute(b) || !b.last.After.Leases[0].Expires.Equal(expiry) {
		t.Fatal("rollback lost route or extended TTL")
	}
	p, err = ac.PreviewTTLReset()
	mustTTL(t, err)
	mustTTL(t, ac.ResetTTL(p.SnapshotHash, f.Generation, "reset2"))
	after, err = ac.PreviewTTLReset()
	mustTTL(t, err)
	*now = now.Add(time.Second)
	mustTTL(t, ac.ObserveDNSResponse(wire))
	if ac.RollbackTTLReset(after.SnapshotHash, f.Generation, "stale") == nil {
		t.Fatal("rollback overwrote relearning")
	}
}

func TestConnectorTTLFailedCommitQuarantines(t *testing.T) {
	ac, b, _, f := ttlFixture(t, nil)
	b.fail = true
	if ac.ObserveDNSResponse(ttlWire(t, "www.example.com", 1)) == nil {
		t.Fatal("failed commit acknowledged")
	}
	if hasTTLRoute(b) || len(ac.DomainRoutes()) != 0 {
		t.Fatal("failed commit projected")
	}
	b.fail = false
	if ac.SweepTTL(f, 100, nil) == nil {
		t.Fatal("quarantine bypassed")
	}
	if _, err := ac.PreviewTTLReset(); err == nil {
		t.Fatal("preview concealed recovery requirement")
	}
}

func TestConnectorTTLConfigureAndRestart(t *testing.T) {
	ac, b, now, f := ttlFixture(t, nil)
	mustTTL(t, ac.ObserveDNSResponse(ttlWire(t, "www.example.com", 5)))
	saved := b.last.AfterLeaseState
	expiry := b.last.After.Leases[0].Expires
	*now = now.Add(4 * time.Second)
	other := &AppConnector{sourceID: 124, logf: t.Logf}
	rb := &ttlBackend{}
	mustTTL(t, other.InstallTTLTakeover(ConnectorTTLConfig{Fence: f, Roots: []string{"*.example.com"}, Restore: saved, Options: LeaseOptions{MaxEntries: 100, Grace: 2 * time.Second, ClockJump: time.Hour}, Now: func() time.Time { return *now }, Commit: rb.commit}))
	if !rb.last.After.Leases[0].Expires.Equal(expiry) {
		t.Fatal("restart extended TTL")
	}
	*now = now.Add(10 * time.Second)
	mustTTL(t, other.SweepTTL(f, 100, nil))
	if !hasTTLRoute(rb) {
		t.Fatal("untrusted restart expired route")
	}
	f.Generation++
	mustTTL(t, other.ConfigureTTL(f, []string{"new.example.com"}, []netip.Prefix{netip.MustParsePrefix("2001:db8::/48")}))
	if hasTTLRoute(rb) || len(other.DomainRoutes()) != 1 {
		t.Fatal("assignment removal not reconciled")
	}
	if other.SweepTTL(featurepolicy.Fence{ProfileID: "foreign", Generation: 100}, 100, nil) == nil {
		t.Fatal("foreign fence accepted")
	}
}

type ttlActivity ActivityState

func (a ttlActivity) Activity(string, netip.Addr) ActivityState { return ActivityState(a) }
func TestConnectorTTLActivityBound(t *testing.T) {
	for _, activity := range []ActivityState{ActivityActive, ActivityUnknown, ActivityIdle} {
		t.Run(string(rune('0'+activity)), func(t *testing.T) {
			ac, b, now, f := ttlFixture(t, nil)
			tt := ac.ttl.Load()
			tt.book.opts.BoundedActivity = true
			tt.book.opts.MaxActiveRetention = 10 * time.Second
			mustTTL(t, ac.ObserveDNSResponse(ttlWire(t, "www.example.com", 1)))
			*now = now.Add(4 * time.Second)
			mustTTL(t, ac.SweepTTL(f, 100, ttlActivity(activity)))
			if hasTTLRoute(b) != (activity != ActivityIdle) {
				t.Fatal("activity protection mismatch")
			}
			*now = now.Add(7 * time.Second)
			mustTTL(t, ac.SweepTTL(f, 100, ttlActivity(activity)))
			if hasTTLRoute(b) {
				t.Fatal("activity extended absolute deadline")
			}
		})
	}
}

func TestConnectorTTLConcurrentPreviewSweep(t *testing.T) {
	ac, _, _, f := ttlFixture(t, nil)
	mustTTL(t, ac.ObserveDNSResponse(ttlWire(t, "www.example.com", 20)))
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 20 {
				if _, err := ac.PreviewTTLReset(); err != nil {
					t.Error(err)
				}
				if err := ac.SweepTTL(f, 10, nil); err != nil {
					t.Error(err)
				}
				_ = ac.DomainRoutes()
			}
		})
	}
	wg.Wait()
}

func TestConnectorTTLSharedProtectedAndTimeRecovery(t *testing.T) {
	ac, b, now, f := ttlFixture(t, nil)
	p := netip.MustParsePrefix("192.0.2.1/32")
	b.protected = append(b.protected, p) // same host also belongs to manual/unknown
	mustTTL(t, ac.ObserveDNSResponse(ttlWire(t, "www.example.com", 1)))
	before, err := ac.PreviewTTLReset()
	mustTTL(t, err)
	mustTTL(t, ac.ResetTTL(before.SnapshotHash, f.Generation, "reset"))
	if !hasTTLRoute(b) || len(b.last.After.Leases) != 0 {
		t.Fatal("shared host deleted or learning retained")
	}
	ac.SetLeaseObserver(nil, nil)
	if ac.leaseSink.Load() == nil {
		t.Fatal("legacy setter detached takeover")
	}
	// Clock uncertainty freezes expiry until explicit confirmation.
	mustTTL(t, ac.ObserveDNSResponse(ttlWire(t, "www.example.com", 1)))
	mustTTL(t, ac.SweepTTL(f, 100, nil))
	*now = now.Add(-time.Second)
	mustTTL(t, ac.SweepTTL(f, 100, nil))
	*now = now.Add(10 * time.Second)
	mustTTL(t, ac.SweepTTL(f, 100, nil))
	if len(b.last.After.Leases) != 1 {
		t.Fatal("uncertain clock deleted learning")
	}
	mustTTL(t, ac.ConfirmTTLTime(f, "test-clock-reviewed"))
	mustTTL(t, ac.SweepTTL(f, 100, nil))
	if len(b.last.After.Leases) != 0 || !hasTTLRoute(b) {
		t.Fatal("time recovery or protected union wrong")
	}
}
