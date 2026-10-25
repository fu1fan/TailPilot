//go:build !ts_omit_appconnectors

package appc

import (
	"errors"
	"fmt"
	"golang.org/x/net/dns/dnsmessage"
	"net/netip"
	"testing"
	"time"
)

func leaseDNSWire(t *testing.T, answers []dnsmessage.Resource) []byte {
	t.Helper()
	m := dnsmessage.Message{Header: dnsmessage.Header{Response: true}, Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName("www.example.com."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}, Answers: answers}
	b, e := m.Pack()
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func leaseA(name string, ttl uint32) dnsmessage.Resource {
	return dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(name), Class: dnsmessage.ClassINET, TTL: ttl}, Body: &dnsmessage.AResource{A: [4]byte{192, 0, 2, 1}}}
}
func leaseCNAME(from, to string, ttl uint32) dnsmessage.Resource {
	return dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(from), Class: dnsmessage.ClassINET, TTL: ttl}, Body: &dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName(to)}}
}
func TestLeaseDNSChainTTL(t *testing.T) {
	for _, ttl := range []uint32{0, 10, 200000} {
		wire := leaseDNSWire(t, []dnsmessage.Resource{leaseA("cdn.example.net.", ttl), leaseCNAME("www.example.com.", "cdn.example.net.", 300000)})
		obs, e := ParseLeaseDNS(wire, []string{"*.example.com"})
		if e != nil || len(obs) != 1 {
			t.Fatalf("parse %v: %v", obs, e)
		}
		if obs[0].TTL != time.Duration(ttl)*time.Second || obs[0].IP != netip.MustParseAddr("192.0.2.1") {
			t.Fatal(obs)
		}
	}
	wire := leaseDNSWire(t, []dnsmessage.Resource{leaseA("cdn.example.net.", 600), leaseCNAME("www.example.com.", "cdn.example.net.", 20)})
	obs, e := ParseLeaseDNS(wire, []string{"*.example.com"})
	if e != nil || obs[0].TTL != 20*time.Second {
		t.Fatal(obs, e)
	}
	if obs, e := ParseLeaseDNS(wire, []string{"other.example.com"}); e != nil || len(obs) != 0 {
		t.Fatal("unassigned observation", obs, e)
	}
}
func TestLeaseDNSRejectsAmbiguousChain(t *testing.T) {
	cases := [][]dnsmessage.Resource{
		{leaseCNAME("www.example.com.", "a.example.", 1), leaseCNAME("www.example.com.", "b.example.", 2)},
		{leaseCNAME("www.example.com.", "a.example.", 1), leaseCNAME("a.example.", "www.example.com.", 2)},
		{leaseCNAME("www.example.com.", "a.example.", 1), leaseA("www.example.com.", 10)},
	}
	for _, a := range cases {
		if _, e := ParseLeaseDNS(leaseDNSWire(t, a), []string{"*.example.com"}); e == nil {
			t.Fatal("unsafe chain accepted")
		}
	}
}
func TestLeaseDNSRRSetMinimum(t *testing.T) {
	obs, e := ParseLeaseDNS(leaseDNSWire(t, []dnsmessage.Resource{leaseA("www.example.com.", 100), leaseA("www.example.com.", 2)}), []string{"www.example.com"})
	if e != nil || len(obs) != 1 || obs[0].TTL != 2*time.Second {
		t.Fatal(obs, e)
	}
}

func TestLeaseDNSObserverAndFailure(t *testing.T) {
	var e AppConnector
	calls := 0
	e.SetLeaseObserver([]string{"www.example.com"}, func(o []DNSLeaseObservation) error { calls++; return fmt.Errorf("disk full") })
	wire := leaseDNSWire(t, []dnsmessage.Resource{leaseA("www.example.com.", 40)})
	var leaseErr *LeaseObservationError
	if err := e.ObserveDNSResponse(wire); !errors.As(err, &leaseErr) {
		t.Fatal("missing durable error", err)
	}
	if calls != 1 {
		t.Fatal("sink not called")
	}
	q := dnsmessage.Message{Header: dnsmessage.Header{ID: 123, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName("www.example.com."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}
	query, err := q.Pack()
	if err != nil {
		t.Fatal(err)
	}
	failure, err := LeaseFailureResponse(query)
	if err != nil {
		t.Fatal(err)
	}
	var m dnsmessage.Message
	if err := m.Unpack(failure); err != nil {
		t.Fatal(err)
	}
	if m.Header.ID != 123 || m.Header.RCode != dnsmessage.RCodeServerFailure || len(m.Answers) != 0 || m.Header.AuthenticData {
		t.Fatal("bad SERVFAIL", m)
	}
}

func TestLeaseDNSNegativeAndIPv6(t *testing.T) {
	for _, rcode := range []dnsmessage.RCode{dnsmessage.RCodeNameError, dnsmessage.RCodeServerFailure} {
		m := dnsmessage.Message{Header: dnsmessage.Header{Response: true, RCode: rcode}, Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName("www.example.com."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}, Answers: []dnsmessage.Resource{leaseA("www.example.com.", 10)}}
		wire, err := m.Pack()
		if err != nil {
			t.Fatal(err)
		}
		if observations, err := ParseLeaseDNS(wire, []string{"*.example.com"}); err != nil || len(observations) != 0 {
			t.Fatal(observations, err)
		}
	}
	ip := netip.MustParseAddr("2001:db8::1")
	m := dnsmessage.Message{Header: dnsmessage.Header{Response: true}, Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName("www.example.com."), Type: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET}}, Answers: []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("www.example.com."), Class: dnsmessage.ClassINET, TTL: 100}, Body: &dnsmessage.AAAAResource{AAAA: ip.As16()}}}}
	wire, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	observations, err := ParseLeaseDNS(wire, []string{"*.example.com"})
	if err != nil || len(observations) != 1 || observations[0].IP != ip {
		t.Fatal(observations, err)
	}
}

func FuzzLeaseDNS(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte("not a DNS response"))
	f.Fuzz(func(t *testing.T, wire []byte) { _, _ = ParseLeaseDNS(wire, []string{"*.example.com"}) })
}

func TestLeaseCapturedDNSObserverRejectsReplacement(t *testing.T) {
	e := &AppConnector{}
	oldCalled, newCalled := false, false
	e.SetLeaseObserver([]string{"*.example.com"}, func([]DNSLeaseObservation) error { oldCalled = true; return nil })
	captured := e.CaptureDNSObserver()
	e.SetLeaseObserver([]string{"*.example.com"}, func([]DNSLeaseObservation) error { newCalled = true; return nil })
	err := captured(leaseDNSWire(t, []dnsmessage.Resource{leaseA("www.example.com.", 60)}))
	if err == nil || oldCalled || newCalled {
		t.Fatalf("err=%v old=%v new=%v", err, oldCalled, newCalled)
	}
}
