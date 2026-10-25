package appc

import (
	"encoding/json"
	"net/netip"
	"tailscale.com/featurepolicy"
	"testing"
	"time"
)

func TestConnectorStateEqualDurableRoundTrip(t *testing.T) {
	now := time.Now()
	original := ConnectorTTLState{Fence: featurepolicy.Fence{ProfileID: "p", Generation: 3}, SourceID: 9, Revision: 4, Roots: []string{"*.example.test"}, Control: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}, Legacy: []LegacyDNSReference{{Domain: "legacy.example.test"}}, Leases: []Lease{{Key: LeaseKey{ProfileID: "p", QName: "www.example.test", IP: netip.MustParseAddr("192.0.2.1")}, LastObserved: now, Expires: now.Add(time.Minute), GraceUntil: now.Add(2 * time.Minute), AbsoluteRetainUntil: now.Add(time.Hour), FirstAdvertised: now, EffectiveTTL: time.Minute, Fence: featurepolicy.Fence{ProfileID: "p"}}}}
	raw, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	var persisted ConnectorTTLState
	if err = json.Unmarshal(raw, &persisted); err != nil {
		t.Fatal(err)
	}
	if !original.Equal(persisted) {
		t.Fatal("durable round trip changed equality")
	}
	mutations := []func(*ConnectorTTLState){
		func(s *ConnectorTTLState) { s.Fence.Generation++ }, func(s *ConnectorTTLState) { s.SourceID++ }, func(s *ConnectorTTLState) { s.Revision++ },
		func(s *ConnectorTTLState) { s.Roots[0] = "other.test" }, func(s *ConnectorTTLState) { s.Control[0] = netip.MustParsePrefix("198.51.100.0/24") }, func(s *ConnectorTTLState) { s.Legacy[0].Domain = "other.test" },
		func(s *ConnectorTTLState) { s.Leases[0].Key.Source = "other" }, func(s *ConnectorTTLState) { s.Leases[0].EffectiveTTL++ }, func(s *ConnectorTTLState) { s.Leases[0].Fence.Generation++ },
		func(s *ConnectorTTLState) { s.Leases[0].LastObserved = s.Leases[0].LastObserved.Add(time.Nanosecond) },
		func(s *ConnectorTTLState) { s.Leases[0].Expires = s.Leases[0].Expires.Add(time.Nanosecond) },
		func(s *ConnectorTTLState) { s.Leases[0].GraceUntil = s.Leases[0].GraceUntil.Add(time.Nanosecond) },
		func(s *ConnectorTTLState) {
			s.Leases[0].AbsoluteRetainUntil = s.Leases[0].AbsoluteRetainUntil.Add(time.Nanosecond)
		},
		func(s *ConnectorTTLState) {
			s.Leases[0].FirstAdvertised = s.Leases[0].FirstAdvertised.Add(time.Nanosecond)
		},
		func(s *ConnectorTTLState) { s.Leases = nil },
	}
	for i, mutate := range mutations {
		changed := cloneTTLState(persisted)
		mutate(&changed)
		if original.Equal(changed) {
			t.Fatalf("CAS accepted changed field %d", i)
		}
	}
}
