package ipnlocal

import (
	"context"
	"errors"
	"fmt"
	"github.com/miekg/dns"
	"tailscale.com/appc"
	"testing"
	"testing/synctest"
	"time"
)

func TestUnifiedDNSPipeline(t *testing.T) {
	q := new(dns.Msg)
	q.SetQuestion("a.example.test.", dns.TypeA)
	qb, _ := q.Pack()
	m := new(dns.Msg)
	m.SetReply(q)
	rr, _ := dns.NewRR("a.example.test. 600 IN A 192.0.2.1")
	m.Answer = []dns.RR{rr}
	rb, _ := m.Pack()
	p := appc.DNSPolicy{Assigned: []string{"a.example.test"}, TTLCap: 60, MaxDepth: 16}
	for _, tc := range []struct {
		name        string
		stale, fail bool
	}{{"success", false, false}, {"epoch", true, false}, {"intent failure", false, true}} {
		t.Run(tc.name, func(t *testing.T) {
			observed := false
			out, e := processUnifiedDNS(context.Background(), qb, p, func() bool { return !tc.stale }, func([]byte) error {
				observed = true
				if tc.fail {
					return errors.New("intent failure")
				}
				return nil
			}, func(context.Context, []byte) ([]byte, error) { return rb, nil })
			if tc.stale {
				if !errors.Is(e, errUnifiedDNSStaleCapture) {
					t.Fatalf("stale capture not classified: %v", e)
				}
				e = nil
			}
			if e != nil {
				t.Fatal(e)
			}
			var got dns.Msg
			got.Unpack(out.Wire)
			if tc.stale || tc.fail {
				if got.Rcode != dns.RcodeServerFailure || out.CacheControl != "no-store" {
					t.Fatal(got, out)
				}
			} else if !observed || got.Answer[0].Header().Ttl != 60 || out.CacheControl != "max-age=60" {
				t.Fatal(got, out)
			}
			if tc.stale && observed {
				t.Fatal("observed stale result")
			}
		})
	}
}

func TestUnifiedDNSExpiredDuringCommit(t *testing.T) {
	q := new(dns.Msg)
	q.SetQuestion("a.example.test.", dns.TypeA)
	qb, _ := q.Pack()
	m := new(dns.Msg)
	m.SetReply(q)
	rr, _ := dns.NewRR("a.example.test. 600 IN A 192.0.2.1")
	m.Answer = []dns.RR{rr}
	rb, _ := m.Pack()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	committed := false
	out, e := processUnifiedDNS(ctx, qb, appc.DNSPolicy{Assigned: []string{"a.example.test"}, TTLCap: 60}, func() bool { return true }, func(w []byte) error {
		var answer dns.Msg
		answer.Unpack(w)
		if answer.Answer[0].Header().Ttl != 60 {
			t.Fatal("uncapped observation")
		}
		committed = true
		cancel()
		return nil
	}, func(context.Context, []byte) ([]byte, error) { return rb, nil })
	if e != nil {
		t.Fatal(e)
	}
	var got dns.Msg
	got.Unpack(out.Wire)
	if !committed || got.Rcode != dns.RcodeServerFailure {
		t.Fatal(got)
	}
	// A completed local commit still does not prove the client installed a route.
}

func TestUnifiedDNSCancellationBoundaries(t *testing.T) {
	for _, managed := range []bool{false, true} {
		for _, phase := range []string{"before-resolve", "after-resolve", "after-valid", "after-observe"} {
			t.Run(fmt.Sprintf("managed=%v/%s", managed, phase), func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				q := new(dns.Msg)
				q.SetQuestion("example.test.", dns.TypeA)
				qb, _ := q.Pack()
				m := new(dns.Msg)
				m.SetReply(q)
				rb, _ := m.Pack()
				p := appc.DNSPolicy{}
				if managed {
					p = appc.DNSPolicy{Assigned: []string{"example.test"}, TTLCap: 60}
				}
				if phase == "before-resolve" {
					cancel()
				}
				resolved, observed := false, false
				out, err := processUnifiedDNS(ctx, qb, p, func() bool {
					if phase == "after-valid" {
						cancel()
					}
					return true
				}, func([]byte) error {
					observed = true
					if phase == "after-observe" {
						cancel()
					}
					return nil
				}, func(context.Context, []byte) ([]byte, error) {
					resolved = true
					// Model an uncooperative resolver returning success after expiry.
					if phase == "after-resolve" {
						cancel()
					}
					return rb, nil
				})
				if phase == "before-resolve" && resolved {
					t.Fatal("canceled request resolved")
				}
				if (phase == "before-resolve" || phase == "after-resolve" || managed && phase == "after-valid") && observed {
					t.Fatal("canceled request observed")
				}
				if !managed && phase == "after-valid" {
					return
				} // unmanaged has no fence check
				if managed {
					var got dns.Msg
					if err != nil || got.Unpack(out.Wire) != nil || got.Rcode != dns.RcodeServerFailure || out.CacheControl != "no-store" {
						t.Fatalf("out=%+v err=%v", out, err)
					}
				} else if !errors.Is(err, context.Canceled) {
					t.Fatalf("got %v", err)
				}
			})
		}
	}
}

// A deterministic clock makes the limit explicit: cooperative I/O returns at
// five seconds; noncancelable I/O returns later, but never as a cached success.
func TestUnifiedDNSCooperativeDeadline(t *testing.T) {
	for _, cooperative := range []bool{true, false} {
		t.Run(fmt.Sprint(cooperative), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				start := time.Now()
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				q := new(dns.Msg)
				q.SetQuestion("example.test.", dns.TypeA)
				wire, _ := q.Pack()
				out, err := processUnifiedDNS(ctx, wire, appc.DNSPolicy{Assigned: []string{"example.test"}, TTLCap: 60}, func() bool { return true }, func([]byte) error { t.Fatal("late answer observed"); return nil }, func(ctx context.Context, _ []byte) ([]byte, error) {
					if cooperative {
						<-ctx.Done()
						return nil, ctx.Err()
					}
					time.Sleep(6 * time.Second)
					m := new(dns.Msg)
					m.SetReply(q)
					return m.Pack()
				})
				var m dns.Msg
				if err != nil || m.Unpack(out.Wire) != nil || m.Rcode != dns.RcodeServerFailure || out.CacheControl != "no-store" {
					t.Fatalf("out=%+v err=%v", out, err)
				}
				want := 5 * time.Second
				if !cooperative {
					want = 6 * time.Second
				}
				if got := time.Since(start); got != want {
					t.Fatalf("elapsed=%v want=%v", got, want)
				}
			})
		})
	}
}
