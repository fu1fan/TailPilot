package ipnlocal

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
	"tailscale.com/appc"
)

func TestUnifiedDNSIPv4AnswerDualStackLearning(t *testing.T) {
	for _, tc := range []struct {
		name    string
		typ     uint16
		records []string
	}{
		{"AAAA", dns.TypeAAAA, []string{"example.test. 25 IN CNAME cdn.test.", "cdn.test. 600 IN AAAA 2001:db8::1"}},
		{"HTTPS", dns.TypeHTTPS, []string{"example.test. 25 IN HTTPS 1 . ipv4hint=192.0.2.1 ipv6hint=2001:db8::1"}},
	} {
		for _, fail := range []bool{false, true} {
			t.Run(tc.name+map[bool]string{false: "/success", true: "/commit-failure"}[fail], func(t *testing.T) {
				q := new(dns.Msg)
				q.SetQuestion("example.test.", tc.typ)
				qb, err := q.Pack()
				if err != nil {
					t.Fatal(err)
				}
				r := new(dns.Msg)
				r.SetReply(q)
				for _, text := range tc.records {
					rr, err := dns.NewRR(text)
					if err != nil {
						t.Fatal(err)
					}
					r.Answer = append(r.Answer, rr)
				}
				rb, err := r.Pack()
				if err != nil {
					t.Fatal(err)
				}
				observed := false
				p := appc.DNSPolicy{Assigned: []string{"example.test"}, Targets: []string{"example.test"}, IPv4Only: true, TTLCap: 20, MaxDepth: 16}
				out, err := processUnifiedDNS(context.Background(), qb, p, func() bool { return true }, func(w []byte) error {
					observations, err := appc.ParseLeaseDNS(w, p.Assigned)
					if err != nil {
						return err
					}
					found := false
					for _, o := range observations {
						if o.IP == netip.MustParseAddr("2001:db8::1") {
							found = true
							if o.TTL != 20*time.Second {
								t.Fatalf("IPv6 TTL %v", o.TTL)
							}
						}
					}
					if !found {
						t.Fatal("missing IPv6 lease evidence")
					}
					observed = true
					if fail {
						return errors.New("simulated durable commit failure")
					}
					return nil
				}, func(context.Context, []byte) ([]byte, error) { return rb, nil })
				if err != nil {
					t.Fatal(err)
				}
				if !observed {
					t.Fatal("observer not called")
				}
				var answer dns.Msg
				if err := answer.Unpack(out.Wire); err != nil {
					t.Fatal(err)
				}
				if fail {
					if answer.Rcode != dns.RcodeServerFailure {
						t.Fatal("commit failure released answer")
					}
					return
				}
				if answer.Rcode != dns.RcodeSuccess {
					t.Fatal(answer.Rcode)
				}
				obs, err := appc.ParseLeaseDNS(out.Wire, p.Assigned)
				if err != nil {
					t.Fatal(err)
				}
				for _, o := range obs {
					if o.IP.Is6() {
						t.Fatal("IPv6 leaked to client")
					}
				}
			})
		}
	}
}

func TestUnifiedDNSIPv6RoutePersistedBeforeFilteredReply(t *testing.T) {
	b, r, st := newConnectorDaemon(t, 0)
	q := new(dns.Msg)
	q.SetQuestion("www.example.test.", dns.TypeAAAA)
	qb, err := q.Pack()
	mustTakeover(t, err)
	m := new(dns.Msg)
	m.SetReply(q)
	rr, err := dns.NewRR("www.example.test. 60 IN AAAA 2001:db8::42")
	mustTakeover(t, err)
	m.Answer = []dns.RR{rr}
	rb, err := m.Pack()
	mustTakeover(t, err)
	p := appc.DNSPolicy{Assigned: []string{"*.example.test"}, Targets: []string{"*.example.test"}, IPv4Only: true, TTLCap: 60, MaxDepth: 16}
	out, err := processUnifiedDNS(context.Background(), qb, p, func() bool { return true }, r.connector.CaptureDNSObserver(), func(context.Context, []byte) ([]byte, error) { return rb, nil })
	mustTakeover(t, err)
	var reply dns.Msg
	mustTakeover(t, reply.Unpack(out.Wire))
	if reply.Rcode != dns.RcodeSuccess || len(reply.Answer) != 0 {
		t.Fatal("IPv6 client response was not filtered")
	}
	want := netip.MustParsePrefix("2001:db8::42/128")
	found := false
	for _, route := range b.Prefs().AdvertiseRoutes().All() {
		found = found || route == want
	}
	if !found {
		t.Fatal("IPv6 route was not advertised")
	}
	v, err := readConnectorIntent(st, "profile-p")
	mustTakeover(t, err)
	owner, ok := v.Ledger.Owners[want]
	if !ok || !owner.Auto["appc-ttl"] || owner.LegacyUnknown {
		t.Fatal("IPv6 route lacks durable TTL ownership")
	}
}
