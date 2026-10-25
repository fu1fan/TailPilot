package ipnlocal

import (
	"net/netip"
	"slices"
	"testing"

	"tailscale.com/types/appctype"
)

// U-V01: final union gate rejects new automatic v6 while leaving IPv4 and
// explicit manual/control/default advertisements independent of the switch.
func TestRouteLedgerIPv6Owners(t *testing.T) {
	auto, shared, manual, control, unknown := prefix("2001:db8::1/128"), prefix("2001:db8::2/128"), prefix("2001:db8::3/128"), prefix("2001:db8::4/128"), prefix("2001:db8::5/128")
	v4, def := prefix("192.0.2.1/32"), prefix("::/0")
	f := &ledgerFixture{routes: []netip.Prefix{unknown}}
	l := newLedgerTest(t, f)
	for _, e := range []appctype.RouteOwnerEvent{event(1, appctype.RouteOwnerAuto, "a", auto, shared, v4), event(2, appctype.RouteOwnerManual, "", shared, manual, def), event(3, appctype.RouteOwnerControl, "c", control)} {
		if err := l.Update(e); err != nil {
			t.Fatal(err)
		}
	}
	l, err := newRouteLedgerPolicy(ledgerFence, f, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Update(event(4, appctype.RouteOwnerReadvertise, "")); err != nil {
		t.Fatal(err)
	}
	if slices.Contains(f.routes, auto) {
		t.Fatal("exclusive automatic IPv6 retained")
	}
	for _, p := range []netip.Prefix{shared, manual, control, unknown, v4, def} {
		if !slices.Contains(f.routes, p) {
			t.Fatal("protected prefix withdrawn", p)
		}
	}
	for p, o := range l.Owners() {
		if p.Addr().Is6() && len(o.Auto) > 0 {
			t.Fatal("automatic IPv6 owner survived", p)
		}
	}
	if err := l.Update(event(5, appctype.RouteOwnerAuto, "new", auto)); err != nil {
		t.Fatal(err)
	}
	if slices.Contains(f.routes, auto) {
		t.Fatal("new automatic IPv6 bypassed gate")
	}
}

// U-V02: recovery never replays a queued IPv6 addition across the family gate,
// including after prefs succeeded and the applied marker failed.
func TestRouteLedgerIPv6Pending(t *testing.T) {
	for _, point := range []string{"prefs", "applied"} {
		t.Run(point, func(t *testing.T) {
			f := &ledgerFixture{}
			l := newLedgerTest(t, f)
			if point == "prefs" {
				f.failApply = true
			} else {
				f.failSave = 2
			}
			if err := l.Update(event(1, appctype.RouteOwnerAuto, "a", prefix("2001:db8::1/128"))); err == nil {
				t.Fatal("missing injected failure")
			}
			f.failApply = false
			f.failSave = 0
			next := ledgerFence
			next.Generation++
			l, err := newRouteLedgerPolicy(next, f, true)
			if err != nil {
				t.Fatal(err)
			}
			if err := l.Recover(); err != nil {
				t.Fatal(err)
			}
			if len(f.routes) != 0 {
				t.Fatal("pending IPv6 replayed", f.routes)
			}
		})
	}
}

// U-V03: off preserves original owner behavior; enabling publication does not
// resurrect removed owners. A fresh observation is required without live leases.
func TestRouteLedgerIPv6DefaultOff(t *testing.T) {
	f := &ledgerFixture{}
	l := newLedgerTest(t, f)
	p := prefix("2001:db8::1/128")
	if err := l.Update(event(1, appctype.RouteOwnerAuto, "a", p)); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(f.routes, p) {
		t.Fatal("default off gated IPv6")
	}
	l, err := newRouteLedgerPolicy(ledgerFence, f, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Update(event(2, appctype.RouteOwnerReadvertise, "")); err != nil {
		t.Fatal(err)
	}
	l, err = newRouteLedgerPolicy(ledgerFence, f, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Update(event(3, appctype.RouteOwnerReadvertise, "")); err != nil {
		t.Fatal(err)
	}
	if len(f.routes) != 0 {
		t.Fatal("removed owner resurrected")
	}
	if err := l.Update(event(4, appctype.RouteOwnerAuto, "a", p)); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(f.routes, p) {
		t.Fatal("fresh observation rejected")
	}
}
