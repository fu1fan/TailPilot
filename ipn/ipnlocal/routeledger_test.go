package ipnlocal

import (
	"errors"
	"io/fs"
	"net/netip"
	"slices"
	"tailscale.com/featurepolicy"
	"tailscale.com/types/appctype"
	"testing"
)

type ledgerFixture struct {
	data      []byte
	routes    []netip.Prefix
	saveCalls int
	failSave  int
	failApply bool
}

func (f *ledgerFixture) Load() ([]byte, error) {
	if f.data == nil {
		return nil, fs.ErrNotExist
	}
	return slices.Clone(f.data), nil
}
func (f *ledgerFixture) Save(b []byte) error {
	f.saveCalls++
	if f.saveCalls == f.failSave {
		return errors.New("disk full")
	}
	f.data = slices.Clone(b)
	return nil
}
func (f *ledgerFixture) Current() ([]netip.Prefix, error) { return slices.Clone(f.routes), nil }
func (f *ledgerFixture) Apply(before, desired []netip.Prefix) error {
	if f.failApply {
		return errors.New("prefs failure")
	}
	if !slices.Equal(sortedRoutes(f.routes), sortedRoutes(before)) {
		return errors.New("prefs CAS")
	}
	f.routes = slices.Clone(desired)
	return nil
}

var ledgerFence = featurepolicy.Fence{ProfileID: "p", Generation: 1, AssignedDomainsEpoch: 1, PeerIdentityEpoch: 1}

func prefix(s string) netip.Prefix { return netip.MustParsePrefix(s) }
func newLedgerTest(t *testing.T, f *ledgerFixture) *RouteLedger {
	t.Helper()
	l, e := NewRouteLedger(ledgerFence, f)
	if e != nil {
		t.Fatal(e)
	}
	return l
}
func event(seq uint64, source appctype.RouteOwnerSource, id string, ps ...netip.Prefix) appctype.RouteOwnerEvent {
	return appctype.RouteOwnerEvent{Fence: ledgerFence, Sequence: seq, Source: source, OwnerID: id, Prefixes: ps}
}

// U-L06: each durable boundary, corrupt state and retry after a failed write.
func TestRouteLedgerCrashRecovery(t *testing.T) {
	p := prefix("192.0.2.1/32")
	for _, point := range []string{"intent", "prefs", "applied"} {
		t.Run(point, func(t *testing.T) {
			f := &ledgerFixture{}
			l := newLedgerTest(t, f)
			switch point {
			case "intent":
				f.failSave = 1
			case "prefs":
				f.failApply = true
			case "applied":
				f.failSave = 2
			}
			if e := l.Update(event(1, appctype.RouteOwnerAuto, "lease1", p)); e == nil {
				t.Fatal("expected failure")
			}
			if point == "intent" && len(f.routes) > 0 {
				t.Fatal("prefs before intent")
			}
			f.failSave = 0
			f.failApply = false
			l = newLedgerTest(t, f)
			if e := l.Recover(); e != nil {
				t.Fatal(e)
			}
			if point == "intent" {
				if len(f.routes) > 0 {
					t.Fatal("failed intent changed routes")
				}
				return
			}
			if !slices.Equal(f.routes, []netip.Prefix{p}) {
				t.Fatal("pending intent lost")
			}
			if e := l.Recover(); e != nil {
				t.Fatal(e)
			}
			if e := l.Update(event(2, appctype.RouteOwnerAuto, "lease1")); e != nil {
				t.Fatal(e)
			}
			if len(f.routes) != 0 {
				t.Fatal("proved auto retained")
			}
			f.data[len(f.data)/2] ^= 1
			if _, e := NewRouteLedger(ledgerFence, f); e == nil {
				t.Fatal("corruption accepted")
			}
		})
	}
}

// U-L07/U-L08/U-L09: independent owners, protected unknown and exact routes.
func TestRouteLedgerOwners(t *testing.T) {
	p := prefix("192.0.2.1/32")
	cover := prefix("192.0.2.0/24")
	def := prefix("0.0.0.0/0")
	f := &ledgerFixture{}
	l := newLedgerTest(t, f)
	for _, e := range []appctype.RouteOwnerEvent{event(1, appctype.RouteOwnerAuto, "a", p), event(2, appctype.RouteOwnerAuto, "b", p), event(3, appctype.RouteOwnerManual, "", p), event(4, appctype.RouteOwnerAuto, "a"), event(5, appctype.RouteOwnerManual, "", cover, def)} {
		if err := l.Update(e); err != nil {
			t.Fatal(err)
		}
	}
	if slices.Contains(f.routes, p) || !slices.Contains(f.routes, cover) {
		t.Fatal("covered host advertised")
	}
	if e := l.Update(event(6, appctype.RouteOwnerManual, "", def)); e != nil {
		t.Fatal(e)
	}
	if !slices.Contains(f.routes, p) || !slices.Contains(f.routes, def) {
		t.Fatal("host not restored or swallowed by /0")
	}
	if e := l.Update(event(7, appctype.RouteOwnerAuto, "b")); e != nil {
		t.Fatal(e)
	}
	if !slices.Equal(f.routes, []netip.Prefix{def}) {
		t.Fatal("last auto owner not withdrawn")
	}
	// Every pre-existing prefix is protected, even if legacy RouteInfo claims it.
	f = &ledgerFixture{routes: []netip.Prefix{p}}
	l = newLedgerTest(t, f)
	if e := l.Update(event(1, appctype.RouteOwnerAuto, "a", p)); e != nil {
		t.Fatal(e)
	}
	if e := l.Update(event(2, appctype.RouteOwnerAuto, "a")); e != nil {
		t.Fatal(e)
	}
	if !slices.Contains(f.routes, p) {
		t.Fatal("unknown route removed")
	}
	plan := MigrationDryRun(ledgerFence, []netip.Prefix{p, def}, appctype.RouteInfo{Control: []netip.Prefix{p}, Domains: map[string][]netip.Addr{"a": {p.Addr()}}})
	if e := plan.ValidateClaims(plan.SnapshotHash, []netip.Prefix{p}); e != nil {
		t.Fatal(e)
	}
	if e := plan.ValidateClaims("old", []netip.Prefix{p}); e == nil {
		t.Fatal("unbound claim")
	}
	if e := plan.ValidateClaims(plan.SnapshotHash, []netip.Prefix{def}); e == nil {
		t.Fatal("default claim")
	}
	if !slices.Contains(plan.Unknown, p) {
		t.Fatal("migration guessed auto")
	}
}

// U-L10: stale profile/epochs/sequence cannot mutate current owner state.
func TestRouteLedgerFences(t *testing.T) {
	f := &ledgerFixture{}
	l := newLedgerTest(t, f)
	p := prefix("192.0.2.1/32")
	e := event(1, appctype.RouteOwnerAuto, "a", p)
	if err := l.Update(e); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*appctype.RouteOwnerEvent){func(e *appctype.RouteOwnerEvent) { e.Fence.ProfileID = "other" }, func(e *appctype.RouteOwnerEvent) { e.Fence.AssignedDomainsEpoch++ }, func(e *appctype.RouteOwnerEvent) { e.Sequence = 1 }, func(e *appctype.RouteOwnerEvent) { e.Sequence = 3 }} {
		e := event(2, appctype.RouteOwnerAuto, "a")
		change(&e)
		if err := l.Update(e); err == nil {
			t.Fatal("stale/reordered event")
		}
	}
	if !slices.Contains(f.routes, p) {
		t.Fatal("stale event removed route")
	}
}

func TestRouteLedgerDeleteCrashAndExternalChange(t *testing.T) {
	p := prefix("192.0.2.1/32")
	external := prefix("198.51.100.1/32")
	for _, point := range []string{"intent", "prefs", "applied"} {
		t.Run(point, func(t *testing.T) {
			f := &ledgerFixture{}
			l := newLedgerTest(t, f)
			if e := l.Update(event(1, appctype.RouteOwnerAuto, "a", p)); e != nil {
				t.Fatal(e)
			}
			switch point {
			case "intent":
				f.failSave = f.saveCalls + 1
			case "prefs":
				f.failApply = true
			case "applied":
				f.failSave = f.saveCalls + 2
			}
			if e := l.Update(event(2, appctype.RouteOwnerAuto, "a")); e == nil {
				t.Fatal("expected failure")
			}
			f.failApply = false
			f.failSave = 0
			// An unrelated writer adds a route while the transaction is interrupted.
			f.routes = append(f.routes, external)
			l = newLedgerTest(t, f)
			if e := l.Recover(); e != nil {
				t.Fatal(e)
			}
			if !slices.Contains(f.routes, external) {
				t.Fatal("external route lost")
			}
			if point == "intent" && !slices.Contains(f.routes, p) {
				t.Fatal("uncommitted delete replayed")
			}
			if point != "intent" && slices.Contains(f.routes, p) {
				t.Fatal("prepared delete lost")
			}
			if !l.Owners()[external].LegacyUnknown {
				t.Fatal("external owner not protected")
			}
		})
	}
}

func TestRouteLedgerControlManualAndReadvertise(t *testing.T) {
	p := prefix("192.0.2.1/32")
	f := &ledgerFixture{}
	l := newLedgerTest(t, f)
	events := []appctype.RouteOwnerEvent{event(1, appctype.RouteOwnerControl, "c", p), event(2, appctype.RouteOwnerAuto, "a", p), event(3, appctype.RouteOwnerManual, "", p), event(4, appctype.RouteOwnerControl, "c"), event(5, appctype.RouteOwnerAuto, "a"), event(6, appctype.RouteOwnerReadvertise, "", prefix("198.51.100.1/32"))}
	for _, e := range events {
		if err := l.Update(e); err != nil {
			t.Fatal(err)
		}
	}
	if !slices.Equal(f.routes, []netip.Prefix{p}) {
		t.Fatal("manual owner lost or readvertise invented owner")
	}
	o := l.Owners()
	delete(o, p)
	if !l.Owners()[p].Manual {
		t.Fatal("mutable owner snapshot")
	}
	if e := l.Update(event(7, appctype.RouteOwnerManual, "")); e != nil {
		t.Fatal(e)
	}
	if len(f.routes) != 0 {
		t.Fatal("last owner retained")
	}
}

func TestRouteLedgerConcurrentStaleEvents(t *testing.T) {
	f := &ledgerFixture{}
	l := newLedgerTest(t, f)
	p := prefix("192.0.2.1/32")
	if e := l.Update(event(1, appctype.RouteOwnerAuto, "a", p)); e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 32)
	for range 32 {
		go func() { done <- l.Update(event(1, appctype.RouteOwnerAuto, "a")) }()
	}
	for range 32 {
		if e := <-done; e == nil {
			t.Fatal("duplicate consumed")
		}
	}
	if !slices.Contains(f.routes, p) {
		t.Fatal("duplicate removed owner")
	}
}

func TestMigrationClaimAuthority(t *testing.T) {
	p := prefix("192.0.2.1/32")
	foreign := prefix("198.51.100.1/32")
	plan := MigrationDryRun(ledgerFence, []netip.Prefix{p}, appctype.RouteInfo{Domains: map[string][]netip.Addr{"a": {p.Addr()}}})
	plan.Candidates = append(plan.Candidates, foreign)
	if e := plan.ValidateClaims(plan.SnapshotHash, []netip.Prefix{foreign}); e == nil {
		t.Fatal("display mutation granted claim")
	}
	forged := MigrationPlan{SnapshotHash: plan.SnapshotHash, Candidates: []netip.Prefix{p}}
	if e := forged.ValidateClaims(plan.SnapshotHash, []netip.Prefix{p}); e == nil {
		t.Fatal("unverified plan granted claim")
	}
}
