// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package appc

import (
	"github.com/miekg/dns"
	"testing"
)

// DNS policy roots are LDH A-labels by construction. A client may still ask a
// legitimate DNS question under an assigned root whose QNAME is outside that
// grammar, such as a service label (_dmarc, _sip._tcp) or an un-encoded IDN.
// Those queries are not managed by the policy, so the lease parser must skip
// them instead of returning "DNS policy: invalid name" (which would be turned
// into a client SERVFAIL).
func TestParseLeaseDNSIgnoresNonPolicyQuestionName(t *testing.T) {
	for _, name := range []string{
		"_dmarc.example.test.",
		"_domainkey.example.test.",
		"_sip._tcp.example.test.",
		"münchen.example.test.",
		"*.example.test.",
	} {
		t.Run(name, func(t *testing.T) {
			_, response := policyWire(t, name, dns.TypeTXT, name+" 60 IN TXT \"v=DMARC1\"")
			obs, err := ParseLeaseDNS(response, []string{"*.example.test"})
			if err != nil {
				t.Fatalf("observation parser failed an unmanaged query: %v", err)
			}
			if len(obs) != 0 {
				t.Fatalf("unexpected observations for non-policy name: %+v", obs)
			}
		})
	}
}

// The valid-name path must keep parsing real lease evidence unchanged.
func TestParseLeaseDNSStillParsesValidQuestionName(t *testing.T) {
	_, response := policyWire(t, "www.example.test.", dns.TypeA, "www.example.test. 60 IN A 192.0.2.1")
	obs, err := ParseLeaseDNS(response, []string{"*.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	if len(obs) != 1 || obs[0].QName != "www.example.test" || obs[0].IP.String() != "192.0.2.1" {
		t.Fatalf("valid lease lost: %+v", obs)
	}
}
