package ipnlocal

import (
	"bytes"
	"context"
	"errors"
	"github.com/miekg/dns"
	"net/http/httptest"
	"net/netip"
	"tailscale.com/appc"
	"tailscale.com/featurepolicy"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/util/eventbus/eventbustest"
	"testing"
)

type unifiedHandlerResolver func([]byte) ([]byte, error)

func (f unifiedHandlerResolver) HandlePeerDNSQuery(_ context.Context, q []byte, _ netip.AddrPort, _ func(string) bool) ([]byte, error) {
	return f(q)
}

// This drives the real HTTP handler with resolver outcomes. UDP/TCP are fake
// upstream outcomes, not a claim to have exercised network transport or I-D.
func TestUnifiedDNSHandlerErrorCacheMatrix(t *testing.T) {
	for _, name := range []string{"udp-a", "tcp-complete", "udp-tc", "resolver-error", "formerr", "empty-question", "notimp", "malformed", "nxdomain", "aaaa", "unrelated", "default-off"} {
		t.Run(name, func(t *testing.T) {
			manager := featurepolicy.NewManager(UnifiedPolicyStore{Store: new(mem.Store), ProfileID: "p", ProfileKey: "p"})
			cfg := []byte(`{"schema_version":1,"enabled":true,"dns_ipv4_only":{"enabled":true,"targets":["example.test"]}}`)
			if name == "default-off" {
				cfg = []byte(`{"schema_version":1}`)
			}
			if _, err := manager.Start(featurepolicy.Inputs{ProfileID: "p", AssignedDomains: []string{"example.test"}}, func() ([]byte, error) { return cfg, nil }); err != nil {
				t.Fatal(err)
			}
			ac := appc.NewAppConnector(appc.Config{Logf: t.Logf, EventBus: eventbustest.NewBus(t)})
			defer ac.Close()
			ac.SetLeaseObserver([]string{"example.test"}, func([]appc.DNSLeaseObservation) error { return nil })
			b := &LocalBackend{logf: t.Logf, appConnector: ac, unifiedSnapshot: manager.Current(), unifiedDomains: []string{"example.test"}}
			q := new(dns.Msg)
			q.SetQuestion("example.test.", dns.TypeA)
			wantCode, wantCache := dns.RcodeSuccess, "max-age=60"
			switch name {
			case "formerr":
				q.Question = append(q.Question, q.Question[0])
				wantCode = dns.RcodeFormatError
				wantCache = "no-store"
			case "empty-question":
				q.Question = nil
				wantCode = dns.RcodeFormatError
				wantCache = "no-store"
			case "notimp":
				q.Opcode = dns.OpcodeStatus
				wantCode = dns.RcodeNotImplemented
				wantCache = "no-store"
			case "malformed":
				wantCode = dns.RcodeFormatError
				wantCache = "no-store"
			case "udp-tc", "resolver-error":
				wantCode = dns.RcodeServerFailure
				wantCache = "no-store"
			case "nxdomain":
				wantCode = dns.RcodeNameError
				wantCache = "no-store"
			case "aaaa":
				q.Question[0].Qtype = dns.TypeAAAA
				wantCache = "no-store"
			case "unrelated":
				q.Question[0].Name = "elsewhere.test."
				wantCache = ""
			case "default-off":
				wantCache = ""
			}
			wire, _ := q.Pack()
			if name == "malformed" {
				wire = []byte{0x12, 0x34, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 0x0c}
			}
			called := false
			resolver := unifiedHandlerResolver(func(query []byte) ([]byte, error) {
				called = true
				if name == "resolver-error" {
					return nil, errors.New("upstream timeout")
				}
				m := new(dns.Msg)
				m.SetReply(q)
				m.AuthenticatedData = true
				rr, _ := dns.NewRR(q.Question[0].Name + " 60 IN A 192.0.2.1")
				if name == "aaaa" {
					rr, _ = dns.NewRR("example.test. 60 IN AAAA 2001:db8::1")
				}
				m.Answer = []dns.RR{rr}
				if name == "udp-tc" {
					m.Truncated = true
				}
				if name == "nxdomain" {
					m.Rcode = dns.RcodeNameError
					m.Answer = nil
				}
				return m.Pack()
			})
			h := &peerAPIHandler{ps: &peerAPIServer{b: b, resolver: resolver}, isSelf: true, remoteAddr: netip.MustParseAddrPort("100.64.0.1:1234")}
			req := httptest.NewRequest("POST", "/dns-query", bytes.NewReader(wire))
			req.Header.Set("Content-Type", "application/dns-message")
			w := httptest.NewRecorder()
			h.handleDNSQuery(w, req)
			if w.Code != 200 {
				t.Fatalf("HTTP %d: %s", w.Code, w.Body.String())
			}
			var answer dns.Msg
			if err := answer.Unpack(w.Body.Bytes()); err != nil {
				t.Fatal(err)
			}
			if answer.Rcode != wantCode || w.Header().Get("Cache-Control") != wantCache {
				t.Fatalf("rcode=%d cache=%q want=%d/%q", answer.Rcode, w.Header().Get("Cache-Control"), wantCode, wantCache)
			}
			if (name == "formerr" || name == "empty-question" || name == "notimp" || name == "malformed") && called {
				t.Fatal("invalid query forwarded")
			}
			if name == "aaaa" && (len(answer.Answer) != 0 || answer.AuthenticatedData) {
				t.Fatal("unsafe filtered answer")
			}
			if (name == "unrelated" || name == "default-off") && !answer.AuthenticatedData {
				t.Fatal("upstream AD changed")
			}
		})
	}
}
