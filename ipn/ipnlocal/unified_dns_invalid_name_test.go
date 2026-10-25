// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"bytes"
	"context"
	"errors"
	"github.com/miekg/dns"
	"tailscale.com/appc"
	"testing"
)

// A legacy observation-parser error for a query that the DNS policy does not
// manage must not be converted into a managed SERVFAIL. This was the R2b
// `durable DNS lease: DNS policy: invalid name` -> client SERVFAIL path: a
// _dmarc-style QNAME is forwarded unmanaged, then ParseLeaseDNS rejected the
// question name after resolution.
func TestUnifiedDNSUnmanagedObserveErrorKeepsUpstream(t *testing.T) {
	q := new(dns.Msg)
	q.SetQuestion("_dmarc.example.test.", dns.TypeTXT)
	qb, err := q.Pack()
	if err != nil {
		t.Fatal(err)
	}
	m := new(dns.Msg)
	m.SetReply(q)
	rr, err := dns.NewRR(`_dmarc.example.test. 60 IN TXT "v=DMARC1"`)
	if err != nil {
		t.Fatal(err)
	}
	m.Answer = []dns.RR{rr}
	rb, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	out, err := processUnifiedDNS(context.Background(), qb, appc.DNSPolicy{}, func() bool { return true }, func([]byte) error {
		return &appc.LeaseObservationError{Err: errors.New("DNS policy: invalid name")}
	}, func(context.Context, []byte) ([]byte, error) { return rb, nil })
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.Wire, rb) || out.Managed || out.CacheControl == "no-store" {
		t.Fatalf("unmanaged upstream answer was replaced: %+v", out)
	}
	var answer dns.Msg
	if err := answer.Unpack(out.Wire); err != nil {
		t.Fatal(err)
	}
	if answer.Rcode != dns.RcodeSuccess || len(answer.Answer) != 1 {
		t.Fatalf("upstream answer lost: %v", &answer)
	}
}

// The durable-observation guarantee still applies to managed queries: a lease
// observation failure must withhold the positive answer as SERVFAIL.
func TestUnifiedDNSManagedObserveErrorStillFails(t *testing.T) {
	q := new(dns.Msg)
	q.SetQuestion("www.example.test.", dns.TypeA)
	qb, err := q.Pack()
	if err != nil {
		t.Fatal(err)
	}
	m := new(dns.Msg)
	m.SetReply(q)
	rr, err := dns.NewRR("www.example.test. 60 IN A 192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	m.Answer = []dns.RR{rr}
	rb, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	p := appc.DNSPolicy{Assigned: []string{"*.example.test"}, TTLCap: 60}
	out, err := processUnifiedDNS(context.Background(), qb, p, func() bool { return true }, func([]byte) error {
		return &appc.LeaseObservationError{Err: errors.New("injected durable failure")}
	}, func(context.Context, []byte) ([]byte, error) { return rb, nil })
	if err != nil {
		t.Fatal(err)
	}
	var answer dns.Msg
	if err := answer.Unpack(out.Wire); err != nil {
		t.Fatal(err)
	}
	if answer.Rcode != dns.RcodeServerFailure || out.CacheControl != "no-store" || !out.Managed {
		t.Fatalf("managed observation failure did not fail closed: %+v %v", out, &answer)
	}
}
