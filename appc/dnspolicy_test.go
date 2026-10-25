package appc

import (
	"bytes"
	"github.com/miekg/dns"
	"testing"
)

func policyWire(t testing.TB, name string, typ uint16, records ...string) ([]byte, []byte) {
	t.Helper()
	q := new(dns.Msg)
	q.SetQuestion(name, typ)
	m := new(dns.Msg)
	m.SetReply(q)
	m.AuthenticatedData = true
	m.CheckingDisabled = true
	for _, s := range records {
		rr, e := dns.NewRR(s)
		if e != nil {
			t.Fatal(e)
		}
		m.Answer = append(m.Answer, rr)
	}
	qb, e := q.Pack()
	if e != nil {
		t.Fatal(e)
	}
	rb, e := m.Pack()
	if e != nil {
		t.Fatal(e)
	}
	return qb, rb
}
func TestDNSPolicy(t *testing.T) {
	p := DNSPolicy{Targets: []string{"*.example.test"}, Assigned: []string{"*.example.test"}, IPv4Only: true, TTLCap: 60, NegativeTTL: 30, MaxDepth: 16}
	t.Run("scope", func(t *testing.T) {
		for _, n := range []string{"example.test.", "badexample.test.", "cdn.test."} {
			q, r := policyWire(t, n, dns.TypeAAAA, n+" 300 IN AAAA 2001:db8::1")
			out, e := p.Transform(q, r)
			if e != nil || !bytes.Equal(out.Wire, r) || out.Managed {
				t.Fatalf("%s: %+v %v", n, out, e)
			}
		}
	})
	t.Run("chain", func(t *testing.T) {
		q, r := policyWire(t, "WWW.Example.test.", dns.TypeAAAA, "www.example.test. 100 IN CNAME cdn.test.", "cdn.test. 200 IN AAAA 2001:db8::1")
		out, e := p.Transform(q, r)
		if e != nil {
			t.Fatal(e)
		}
		var m dns.Msg
		m.Unpack(out.Wire)
		if m.Rcode != 0 || m.AuthenticatedData || !m.CheckingDisabled || len(m.Answer) != 1 || m.Answer[0].Header().Ttl != 60 || out.CacheControl != "no-store" {
			t.Fatalf("%+v %s", m, out.CacheControl)
		}
	})
	t.Run("hint", func(t *testing.T) {
		q, r := policyWire(t, "a.example.test.", dns.TypeHTTPS, `a.example.test. 100 IN HTTPS 1 . mandatory=alpn,ipv6hint alpn=h2 port=443 ipv4hint=192.0.2.1 ipv6hint=2001:db8::1`)
		out, e := p.Transform(q, r)
		if e != nil {
			t.Fatal(e)
		}
		var m dns.Msg
		m.Unpack(out.Wire)
		s := m.Answer[0].(*dns.HTTPS)
		for _, v := range s.Value {
			if v.Key() == dns.SVCB_IPV6HINT {
				t.Fatal("IPv6 hint")
			}
		}
		obs, e := ParseLeaseDNS(out.Wire, p.Assigned)
		if e != nil || len(obs) != 1 || obs[0].TTL.Seconds() != 60 {
			t.Fatalf("%+v %v", obs, e)
		}
	})
	t.Run("default off", func(t *testing.T) {
		out, e := (DNSPolicy{}).Transform([]byte{1}, []byte{2})
		if e != nil || !bytes.Equal(out.Wire, []byte{2}) {
			t.Fatal(out, e)
		}
	})
	t.Run("invalid", func(t *testing.T) {
		q, r := policyWire(t, "a.example.test.", dns.TypeAAAA)
		var m dns.Msg
		m.Unpack(r)
		m.Truncated = true
		r, _ = m.Pack()
		if _, e := p.Transform(q, r); e == nil {
			t.Fatal("TC accepted")
		}
		if _, e := p.Transform(q, []byte{0xc0, 0}); e == nil {
			t.Fatal("malformed accepted")
		}
	})
}
func FuzzDNSPolicy(f *testing.F) {
	q, r := policyWire(f, "a.example.test.", dns.TypeAAAA, "a.example.test. 300 IN AAAA 2001:db8::1")
	f.Add(q, r)
	f.Fuzz(func(t *testing.T, q, r []byte) {
		p := DNSPolicy{IPv4Only: true, Targets: []string{"*.example.test"}, Assigned: []string{"*.example.test"}, MaxDepth: 16, NegativeTTL: 30}
		out, e := p.Transform(q, r)
		if e == nil && out.Managed {
			var m dns.Msg
			if e := m.Unpack(out.Wire); e != nil {
				t.Fatal(e)
			}
		}
	})
}

func TestDNSPolicyRecords(t *testing.T) {
	p := DNSPolicy{Assigned: []string{"*.example.test"}, Targets: []string{"*.example.test"}, IPv4Only: true, TTLCap: 60, NegativeTTL: 30, MaxDepth: 16}
	t.Run("DNAME", func(t *testing.T) {
		q, r := policyWire(t, "a.example.test.", dns.TypeA, "example.test. 10 IN DNAME other.test.", "a.other.test. 100 IN A 192.0.2.1")
		out, e := p.Transform(q, r)
		if e != nil {
			t.Fatal(e)
		}
		obs, e := ParseLeaseDNS(out.Wire, p.Assigned)
		if e != nil || len(obs) != 1 || obs[0].TTL.Seconds() != 10 {
			t.Fatal(obs, e)
		}
	})
	t.Run("AliasMode additional", func(t *testing.T) {
		q, r := policyWire(t, "a.example.test.", dns.TypeHTTPS, "a.example.test. 12 IN HTTPS 0 cdn.test.", "cdn.test. 100 IN HTTPS 1 . ipv4hint=192.0.2.1 ipv6hint=2001:db8::1")
		var m dns.Msg
		m.Unpack(r)
		rr, _ := dns.NewRR("cdn.test. 100 IN AAAA 2001:db8::1")
		m.Extra = []dns.RR{rr}
		r, _ = m.Pack()
		out, e := p.Transform(q, r)
		if e != nil {
			t.Fatal(e)
		}
		m.Unpack(out.Wire)
		if len(m.Extra) != 0 {
			t.Fatal(m)
		}
		obs, e := ParseLeaseDNS(out.Wire, p.Assigned)
		if e != nil || len(obs) != 1 || obs[0].TTL.Seconds() != 12 || obs[0].Source != "svcb-hint" {
			t.Fatal(obs, e)
		}
	})
	for _, record := range []string{`a.example.test. 100 IN SVCB 1 . mandatory=key65400 key65400=abc`, `a.example.test. 100 IN HTTPS 1 2001:db8::1. ipv6hint=2001:db8::1`} {
		t.Run(record, func(t *testing.T) {
			q, r := policyWire(t, "a.example.test.", dns.TypeHTTPS, record)
			out, e := p.Transform(q, r)
			if e != nil {
				t.Fatal(e)
			}
			var m dns.Msg
			m.Unpack(out.Wire)
			if len(m.Answer) != 0 {
				t.Fatal(m)
			}
		})
	}
	t.Run("negative DNSSEC", func(t *testing.T) {
		q, r := policyWire(t, "a.example.test.", dns.TypeAAAA, "a.example.test. 100 IN AAAA 2001:db8::1")
		var m dns.Msg
		m.Unpack(r)
		soa, _ := dns.NewRR("example.test. 90 IN SOA ns.example.test. hostmaster.example.test. 1 60 60 60 80")
		nsec, _ := dns.NewRR("a.example.test. 90 IN NSEC b.example.test. AAAA RRSIG NSEC")
		m.Ns = []dns.RR{soa, nsec}
		m.Answer = append(m.Answer, &dns.RRSIG{Hdr: dns.RR_Header{Name: "a.example.test.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 90}, TypeCovered: dns.TypeAAAA, SignerName: "example.test."})
		r, _ = m.Pack()
		out, e := p.Transform(q, r)
		if e != nil {
			t.Fatal(e)
		}
		m.Unpack(out.Wire)
		if m.AuthenticatedData || !m.CheckingDisabled || len(m.Answer) != 0 || len(m.Ns) != 1 || m.Ns[0].(*dns.SOA).Minttl != 30 || out.CacheControl != "max-age=30" {
			t.Fatal(m, out)
		}
	})
	t.Run("foreign SOA", func(t *testing.T) {
		q, r := policyWire(t, "a.example.test.", dns.TypeAAAA, "a.example.test. 100 IN CNAME cdn.test.", "cdn.test. 100 IN AAAA 2001:db8::1")
		var m dns.Msg
		m.Unpack(r)
		rr, _ := dns.NewRR("example.test. 90 IN SOA ns.example.test. hostmaster.example.test. 1 60 60 60 80")
		m.Ns = []dns.RR{rr}
		r, _ = m.Pack()
		out, e := p.Transform(q, r)
		if e != nil || out.CacheControl != "no-store" {
			t.Fatal(out, e)
		}
	})
	t.Run("zero TTL", func(t *testing.T) {
		q, r := policyWire(t, "a.example.test.", dns.TypeA, "a.example.test. 0 IN A 192.0.2.1")
		out, e := p.Transform(q, r)
		if e != nil || out.CacheControl != "no-store" {
			t.Fatal(out, e)
		}
		obs, e := ParseLeaseDNS(out.Wire, p.Assigned)
		if e != nil || len(obs) != 1 || obs[0].TTL != 0 {
			t.Fatal(obs, e)
		}
	})
	t.Run("error codes unchanged", func(t *testing.T) {
		for _, code := range []int{dns.RcodeNameError, dns.RcodeServerFailure, dns.RcodeRefused} {
			q, r := policyWire(t, "a.example.test.", dns.TypeAAAA)
			var m dns.Msg
			m.Unpack(r)
			m.Rcode = code
			r, _ = m.Pack()
			out, e := p.Transform(q, r)
			if e != nil || !bytes.Equal(r, out.Wire) {
				t.Fatal(out, e)
			}
		}
	})
	t.Run("malformed and mismatch", func(t *testing.T) {
		q, r := policyWire(t, "a.example.test.", dns.TypeAAAA)
		for _, wire := range [][]byte{{0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 12, 0, 1, 0, 1}, make([]byte, 65536)} {
			if _, e := p.Transform(q, wire); e == nil {
				t.Fatal("accepted bad response")
			}
		}
		var m dns.Msg
		m.Unpack(q)
		m.Question = append(m.Question, dns.Question{Name: "other.test.", Qtype: dns.TypeA, Qclass: dns.ClassINET})
		q, _ = m.Pack()
		if _, e := p.Transform(q, r); e == nil {
			t.Fatal("mixed questions accepted")
		}
	})
	t.Run("loop", func(t *testing.T) {
		q, r := policyWire(t, "a.example.test.", dns.TypeA, "a.example.test. 30 IN CNAME b.example.test.", "b.example.test. 30 IN CNAME a.example.test.")
		if _, e := p.Transform(q, r); e == nil {
			t.Fatal("loop accepted")
		}
	})
	t.Run("A label", func(t *testing.T) {
		policy := p
		policy.Targets = []string{"XN--BCHER-KVA.example.test"}
		q, r := policyWire(t, "xn--bcher-kva.example.test.", dns.TypeAAAA, "xn--bcher-kva.example.test. 100 IN AAAA 2001:db8::1")
		out, e := policy.Transform(q, r)
		if e != nil || !out.Managed {
			t.Fatal(out, e)
		}
	})
	t.Run("unknown RDATA", func(t *testing.T) {
		q, r := policyWire(t, "a.example.test.", dns.TypeANY, `a.example.test. 20 IN TYPE65400 \# 4 deadbeef`)
		out, e := p.Transform(q, r)
		if e != nil || !bytes.Equal(out.Wire, r) {
			t.Fatal(out, e)
		}
	})
	t.Run("assignment removal", func(t *testing.T) {
		policy := p
		policy.Assigned = nil
		q, r := policyWire(t, "a.example.test.", dns.TypeAAAA, "a.example.test. 100 IN AAAA 2001:db8::1")
		out, e := policy.Transform(q, r)
		if e != nil || out.Managed || !bytes.Equal(r, out.Wire) {
			t.Fatal(out, e)
		}
	})
}

// Wire-level DNSSEC semantics only; synthetic local-policy answers cannot be
// validated end-to-end. No signature verification is claimed by this matrix.
func TestDNSPolicyDNSSECCacheMatrix(t *testing.T) {
	for _, do := range []bool{false, true} {
		for _, cd := range []bool{false, true} {
			for _, typ := range []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeHTTPS} {
				q := new(dns.Msg)
				q.SetQuestion("example.test.", typ)
				q.CheckingDisabled = cd
				q.SetEdns0(1232, do)
				m := new(dns.Msg)
				m.SetReply(q)
				m.AuthenticatedData = true
				m.CheckingDisabled = cd
				m.SetEdns0(1232, do)
				text := "example.test. 600 IN A 192.0.2.1"
				if typ == dns.TypeAAAA {
					text = "example.test. 600 IN AAAA 2001:db8::1"
				}
				if typ == dns.TypeHTTPS {
					text = `example.test. 600 IN HTTPS 1 . alpn="h2" ipv4hint=192.0.2.1 ipv6hint=2001:db8::1`
				}
				rr, err := dns.NewRR(text)
				if err != nil {
					t.Fatal(err)
				}
				sig := &dns.RRSIG{Hdr: dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 600}, TypeCovered: typ, SignerName: "example.test."}
				m.Answer = []dns.RR{rr, sig}
				nsec, _ := dns.NewRR("example.test. 600 IN NSEC next.test. A AAAA RRSIG NSEC")
				nsec3, _ := dns.NewRR("example.test. 600 IN NSEC3 1 0 0 - 00000000000000000000000000000000 A RRSIG")
				m.Ns = []dns.RR{nsec, nsec3}
				qb, _ := q.Pack()
				rb, err := m.Pack()
				if err != nil {
					t.Fatal(err)
				}
				p := DNSPolicy{Assigned: []string{"example.test"}, Targets: []string{"example.test"}, IPv4Only: true, TTLCap: 60, MaxDepth: 16}
				var parsed dns.Msg
				if err := parsed.Unpack(rb); err != nil {
					t.Fatalf("fixture type=%d: %v", typ, err)
				}
				out, err := p.Transform(qb, rb)
				if err != nil {
					t.Fatal(err)
				}
				var got dns.Msg
				if err := got.Unpack(out.Wire); err != nil {
					t.Fatal(err)
				}
				if got.AuthenticatedData || got.CheckingDisabled != cd || got.IsEdns0() == nil || got.IsEdns0().Do() != do {
					t.Fatalf("bad flags DO=%v CD=%v type=%d", do, cd, typ)
				}
				for _, rr := range dnsRecords(&got) {
					switch rr.Header().Rrtype {
					case dns.TypeRRSIG, dns.TypeNSEC, dns.TypeNSEC3:
						t.Fatal("stale proof", rr)
					}
				}
				want := "max-age=60"
				if typ == dns.TypeAAAA {
					want = "no-store"
				}
				if out.CacheControl != want {
					t.Fatalf("cache %s want %s", out.CacheControl, want)
				}
			}
		}
	}
}
