package appc

import (
	"net/netip"
	"slices"
	"tailscale.com/types/appctype"
	"tailscale.com/util/eventbus/eventbustest"
	"testing"
)

func TestLeaseLegacyHandoffFences(t *testing.T) {
	ac := NewAppConnector(Config{Logf: t.Logf, EventBus: eventbustest.NewBus(t), SourceID: 7})
	defer ac.Close()
	if !ac.AcceptLegacyEvent(7, 0) || ac.AcceptLegacyEvent(8, 0) {
		t.Fatal("initial source identity")
	}
	ac.SetLeaseObserver([]string{"example.test"}, func([]DNSLeaseObservation) error { return nil })
	if ac.AcceptLegacyEvent(7, 0) {
		t.Fatal("old untyped event accepted while managed")
	}
	ip := netip.MustParseAddr("192.0.2.1")
	ri := appctype.RouteInfo{Domains: map[string][]netip.Addr{"example.test": {ip}}}
	ac.InstallLegacyRouteInfo(ri)
	if ac.AcceptLegacyEvent(7, 0) {
		t.Fatal("pre-enable event accepted after disable")
	}
	if !ac.AcceptLegacyEvent(7, ac.legacyEventEpoch()) {
		t.Fatal("new legacy source unavailable")
	}
	if !slices.Equal(ac.DomainRoutes()["example.test"], []netip.Addr{ip}) {
		t.Fatal("handoff missing routes")
	}
	ri.Domains["example.test"][0] = netip.MustParseAddr("192.0.2.2")
	if ac.DomainRoutes()["example.test"][0] != ip {
		t.Fatal("handoff aliased caller")
	}
}
