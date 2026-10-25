package ipnlocal

import (
	"context"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"tailscale.com/appc"
	"tailscale.com/control/controlknobs"
	"tailscale.com/health"
	"tailscale.com/net/dns/resolver"
	"tailscale.com/net/netmon"
	"tailscale.com/net/tsdial"
	"tailscale.com/types/dnstype"
	"tailscale.com/util/dnsname"
	"tailscale.com/util/eventbus/eventbustest"
)

// Real loopback UDP/TCP and Resolver.Query, using the same TCP-family forwarder
// path as HandlePeerDNSQuery. Explicit local routes avoid touching host resolver
// configuration. This does not test OS stub discovery or remote client routing.
// Socket failures are fatal, never converted into fake transport success.
func TestUnifiedDNSResolverTransport(t *testing.T) {
	for _, mode := range []string{"udp-complete", "udp-tc-tcp", "retry-disabled"} {
		t.Run(mode, func(t *testing.T) {
			tcp, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { tcp.Close() })
			udp, err := net.ListenPacket("udp4", tcp.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { udp.Close() })
			var udpCalls, tcpCalls atomic.Int32
			handler := dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
				m := new(dns.Msg)
				m.SetReply(q)
				m.AuthenticatedData = true
				if w.LocalAddr().Network() == "udp" {
					udpCalls.Add(1)
					m.Truncated = mode != "udp-complete"
				} else {
					tcpCalls.Add(1)
				}
				if !m.Truncated {
					rr, err := dns.NewRR("example.test. 600 IN AAAA 2001:db8::1")
					if err != nil {
						t.Error(err)
						return
					}
					m.Answer = []dns.RR{rr}
				}
				if err := w.WriteMsg(m); err != nil {
					t.Error(err)
				}
			})
			for _, s := range []*dns.Server{{Listener: tcp, Handler: handler}, {PacketConn: udp, Handler: handler}} {
				ready, done := make(chan struct{}), make(chan error, 1)
				s.NotifyStartedFunc = func() { close(ready) }
				go func() { done <- s.ActivateAndServe() }()
				select {
				case <-ready:
				case err := <-done:
					t.Fatal(err)
				case <-time.After(5 * time.Second):
					t.Fatal("server start timeout")
				}
				t.Cleanup(func() {
					s.Shutdown()
					if err := <-done; err != nil {
						t.Error(err)
					}
				})
			}
			bus := eventbustest.NewBus(t)
			// Loopback needs no OS route-monitor socket. DNS transport stays real.
			nm := netmon.NewStatic()
			t.Cleanup(func() { nm.Close() })
			dialer := new(tsdial.Dialer)
			dialer.SetNetMon(nm)
			dialer.SetBus(bus)
			t.Cleanup(func() { dialer.Close() })
			knobs := new(controlknobs.Knobs)
			knobs.DisableDNSForwarderTCPRetries.Store(mode == "retry-disabled")
			r := resolver.New(t.Logf, nil, dialer, health.NewTracker(bus), knobs)
			t.Cleanup(func() { r.Close() })
			if err := r.SetConfig(resolver.Config{Routes: map[dnsname.FQDN][]*dnstype.Resolver{".": {{Addr: tcp.Addr().String()}}}}); err != nil {
				t.Fatal(err)
			}
			q := new(dns.Msg)
			q.SetQuestion("example.test.", dns.TypeAAAA)
			wire, err := q.Pack()
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			observed := false
			result, err := processUnifiedDNS(ctx, wire, appc.DNSPolicy{Assigned: []string{"example.test"}, Targets: []string{"example.test"}, IPv4Only: true, MaxDepth: 16}, func() bool { return true }, func(b []byte) error {
				observed = true
				var m dns.Msg
				if err := m.Unpack(b); err != nil {
					return err
				}
				if len(m.Answer) != 1 || m.Answer[0].Header().Rrtype != dns.TypeAAAA {
					t.Error("IPv6 route evidence missing")
				}
				return nil
			}, func(ctx context.Context, q []byte) ([]byte, error) {
				return r.Query(ctx, q, "tcp", netip.MustParseAddrPort("100.64.0.1:1234"))
			})
			if err != nil {
				t.Fatal(err)
			}
			var answer dns.Msg
			if err := answer.Unpack(result.Wire); err != nil {
				t.Fatal(err)
			}
			wantCode := dns.RcodeSuccess
			if mode == "retry-disabled" {
				wantCode = dns.RcodeServerFailure
			}
			if answer.Rcode != wantCode || len(answer.Answer) != 0 || answer.AuthenticatedData {
				t.Fatalf("unsafe answer: %v", &answer)
			}
			if udpCalls.Load() == 0 {
				t.Fatal("no real UDP request")
			}
			if mode == "udp-tc-tcp" && tcpCalls.Load() == 0 {
				t.Fatal("no real TCP retry")
			}
			if mode == "retry-disabled" && (tcpCalls.Load() != 0 || observed || result.CacheControl != "no-store") {
				t.Fatal("truncation escaped fail-closed path")
			}
			if mode != "retry-disabled" && !observed {
				t.Fatal("complete response not observed")
			}
		})
	}
}
