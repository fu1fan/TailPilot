// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package appc

import (
	"errors"
	"fmt"
	"math"
	"net/netip"
	"strings"
	"time"

	"github.com/miekg/dns"
	"tailscale.com/featurepolicy"
	"tailscale.com/util/clientmetric"
)

// metricLeaseInvalidQuestionName counts legitimate DNS questions whose QNAME is
// outside the policy's LDH A-label grammar (service labels such as _dmarc or
// un-encoded IDN). They cannot match an assigned root, so they are not lease
// evidence; the client's upstream answer must stand instead of a SERVFAIL.
var metricLeaseInvalidQuestionName = clientmetric.NewCounter("appc_lease_invalid_question_name")
var metricLeaseInvalidRecordName = clientmetric.NewCounter("appc_lease_invalid_record_name")

// errPolicyInvalidName marks a DNS name outside the policy's LDH A-label
// grammar. Callers distinguish a client question (skip observation) from a
// managed response record (fail closed / diagnostic).
var errPolicyInvalidName = errors.New("DNS policy: invalid name")

// DNSPolicy is a per-query immutable capture. It has no shared DNS or alias
// cache. Assigned must come from the current authenticated connector assignment.
type DNSPolicy struct {
	Targets, Assigned   []string
	IPv4Only            bool
	TTLCap, NegativeTTL uint32
	MaxDepth            int
}

type DNSPolicyResult struct {
	Wire             []byte
	Managed, Changed bool
	CacheControl     string
}

func dnsName(s string) (string, error) {
	n, e := featurepolicy.NormalizeDomain(s)
	if e != nil || strings.Contains(n, "*") {
		return "", errPolicyInvalidName
	}
	if _, e := netip.ParseAddr(n); e == nil {
		return "", fmt.Errorf("%w: literal target", errPolicyInvalidName)
	}
	return n, nil
}
func dnsMatch(pattern, name string) bool {
	p, e := featurepolicy.NormalizeDomain(pattern)
	if e != nil {
		return false
	}
	return p == name || strings.HasPrefix(p, "*.") && strings.HasSuffix(name, p[1:]) && len(name) > len(p)-1
}
func dnsRoot(roots []string, name string) string {
	root := ""
	for _, r := range roots {
		if dnsMatch(r, name) && (len(r) > len(root) || len(r) == len(root) && r < root) {
			root = r
		}
	}
	return root
}
func svcb(rr dns.RR) *dns.SVCB {
	switch r := rr.(type) {
	case *dns.SVCB:
		return r
	case *dns.HTTPS:
		return &r.SVCB
	}
	return nil
}
func dnsRecords(m *dns.Msg) []dns.RR {
	out := append([]dns.RR{}, m.Answer...)
	out = append(out, m.Ns...)
	return append(out, m.Extra...)
}

// dnsChain proves reachability in this response only. DNAME substitution is
// label based. TTLs include every alias edge; cycles and excess depth fail shut.
func dnsChain(m *dns.Msg, root string, depth int) (map[string]uint32, error) {
	if depth < 1 {
		depth = 16
	}
	if depth > 32 {
		depth = 32
	}
	chainRecords := append(append([]dns.RR{}, m.Answer...), m.Extra...)
	reached := map[string]uint32{}
	active := map[string]bool{}
	var visit func(string, uint32, int) error
	visit = func(name string, ttl uint32, level int) error {
		if level > depth || active[name] {
			return fmt.Errorf("DNS policy: alias loop or depth")
		}
		if old, ok := reached[name]; ok && old <= ttl {
			return nil
		}
		reached[name] = ttl
		active[name] = true
		defer delete(active, name)
		var cname string
		for _, rr := range chainRecords {
			if rr.Header().Class != dns.ClassINET {
				continue
			}
			owner, e := dnsName(rr.Header().Name)
			if e != nil {
				return e
			}
			target := ""
			switch r := rr.(type) {
			case *dns.CNAME:
				if owner == name {
					target = r.Target
					if cname != "" && !strings.EqualFold(cname, target) {
						return fmt.Errorf("DNS policy: conflicting alias")
					}
					cname = target
				}
			case *dns.DNAME:
				if strings.HasSuffix(name, "."+owner) {
					target = strings.TrimSuffix(name, owner) + r.Target
					reached[owner] = min(ttl, rr.Header().Ttl)
				}
			default:
				if s := svcb(rr); s != nil && owner == name && s.Target != "." {
					target = s.Target
				}
			}
			if target != "" {
				n, e := dnsName(target)
				if e != nil {
					return e
				}
				if n == name {
					if s := svcb(rr); s != nil && s.Priority > 0 {
						continue
					}
				}
				if e := visit(n, min(ttl, rr.Header().Ttl), level+1); e != nil {
					return e
				}
			}
		}
		if cname != "" {
			for _, rr := range chainRecords {
				if strings.EqualFold(rr.Header().Name, dns.Fqdn(name)) && (rr.Header().Rrtype == dns.TypeA || rr.Header().Rrtype == dns.TypeAAAA) {
					return fmt.Errorf("DNS policy: alias with address")
				}
			}
		}
		return nil
	}
	if e := visit(root, math.MaxUint32, 0); e != nil {
		return nil, e
	}
	return reached, nil
}

// sanitizeSVCB returns false when the record cannot safely express its target
// or mandatory parameters. Unknown non-mandatory values are left untouched.
func sanitizeSVCB(s *dns.SVCB, ipv4 bool) bool {
	if s.Target != "." {
		if _, e := dnsName(s.Target); e != nil {
			return false
		}
	}
	if s.Priority == 0 {
		return s.Target != "." && len(s.Value) == 0
	}
	present := map[dns.SVCBKey]bool{}
	for _, v := range s.Value {
		if present[v.Key()] {
			return false
		}
		present[v.Key()] = true
	}
	values := s.Value[:0]
	for _, v := range s.Value {
		if ipv4 && v.Key() == dns.SVCB_IPV6HINT {
			continue
		}
		if mandatory, ok := v.(*dns.SVCBMandatory); ok {
			keys := mandatory.Code[:0]
			seen := map[dns.SVCBKey]bool{}
			for _, key := range mandatory.Code {
				if ipv4 && key == dns.SVCB_IPV6HINT {
					continue
				}
				if key == dns.SVCB_MANDATORY || key > dns.SVCB_IPV6HINT || !present[key] || seen[key] {
					return false
				}
				seen[key] = true
				keys = append(keys, key)
			}
			mandatory.Code = keys
			if len(keys) == 0 {
				continue
			}
		}
		values = append(values, v)
	}
	s.Value = values
	return true
}

// Transform runs after upstream permission checking/resolution and before any
// lease observation. Errors must be converted to failure, never upstream bytes.
func (p DNSPolicy) Transform(query, response []byte) (DNSPolicyResult, error) {
	return p.transform(query, response, false)
}

// TransformForRoutes applies the same validation, chain and TTL constraints as
// Transform, but retains IPv6 evidence for route learning. Its bytes must never
// be returned to a client when IPv4Only is enabled.
func (p DNSPolicy) TransformForRoutes(query, response []byte) (DNSPolicyResult, error) {
	return p.transform(query, response, true)
}

func (p DNSPolicy) transform(query, response []byte, retainIPv6 bool) (DNSPolicyResult, error) {
	out := DNSPolicyResult{Wire: response}
	if !p.IPv4Only && p.TTLCap == 0 {
		return out, nil
	}
	var q dns.Msg
	if len(query) > 65535 || q.Unpack(query) != nil {
		return out, fmt.Errorf("DNS policy: malformed query")
	}
	for _, question := range q.Question {
		n, e := dnsName(question.Name)
		if e == nil && dnsRoot(p.Assigned, n) != "" && (p.TTLCap != 0 || p.IPv4Only && dnsRoot(p.Targets, n) != "") {
			out.Managed = true
		}
	}
	if !out.Managed {
		return out, nil
	}
	if len(q.Question) != 1 || q.Response || q.Opcode != dns.OpcodeQuery || q.Question[0].Qclass != dns.ClassINET {
		return out, fmt.Errorf("DNS policy: unsupported query")
	}
	name, _ := dnsName(q.Question[0].Name)
	ipv4 := p.IPv4Only && !retainIPv6 && dnsRoot(p.Targets, name) != ""
	var m dns.Msg
	if len(response) > 65535 || m.Unpack(response) != nil || !m.Response || m.Truncated || m.Id != q.Id || m.Opcode != q.Opcode || len(m.Question) != 1 || !strings.EqualFold(m.Question[0].Name, q.Question[0].Name) || m.Question[0].Qtype != q.Question[0].Qtype || m.Question[0].Qclass != q.Question[0].Qclass {
		return out, fmt.Errorf("DNS policy: incomplete or mismatched response")
	}
	if m.Rcode != dns.RcodeSuccess {
		out.CacheControl = "no-store"
		return out, nil
	}
	// Drop unsafe service records before following their targets. Only records
	// reachable from the root are subsequently exposed as usable policy answers.
	// Invalid unrelated records are retained, as they carry no root context.
	reached, e := dnsChain(&m, name, p.MaxDepth)
	if e != nil {
		// Unsafe SVCB targets can be discarded rather than failing the entire query.
		for _, section := range []*[]dns.RR{&m.Answer, &m.Extra} {
			kept := (*section)[:0]
			for _, rr := range *section {
				if s := svcb(rr); s != nil {
					if s.Target != "." {
						if _, err := dnsName(s.Target); err != nil {
							out.Changed = true
							continue
						}
					}
				}
				kept = append(kept, rr)
			}
			*section = kept
		}
		reached, e = dnsChain(&m, name, p.MaxDepth)
		if e != nil {
			return out, e
		}
	}
	removedAAAA := false
	for _, section := range []*[]dns.RR{&m.Answer, &m.Ns, &m.Extra} {
		kept := (*section)[:0]
		for _, rr := range *section {
			owner, _ := dnsName(rr.Header().Name)
			chainTTL, ok := reached[owner]
			if !ok || rr.Header().Class != dns.ClassINET {
				kept = append(kept, rr)
				continue
			}
			if ipv4 && rr.Header().Rrtype == dns.TypeAAAA {
				removedAAAA = true
				out.Changed = true
				continue
			}
			if s := svcb(rr); s != nil {
				before := s.String()
				if !sanitizeSVCB(s, ipv4) {
					out.Changed = true
					continue
				}
				out.Changed = out.Changed || before != s.String()
			}
			ttl := rr.Header().Ttl
			if p.TTLCap != 0 {
				ttl = min(ttl, p.TTLCap)
			}
			// Chain minima are reflected on the wire as well as in the lease sink.
			ttl = min(ttl, chainTTL)
			if ttl != rr.Header().Ttl {
				rr.Header().Ttl = ttl
				out.Changed = true
			}
			kept = append(kept, rr)
		}
		*section = kept
	}
	negative := q.Question[0].Qtype == dns.TypeAAAA && removedAAAA
	if negative {
		soa := false
		kept := m.Ns[:0]
		for _, rr := range m.Ns {
			s, ok := rr.(*dns.SOA)
			if !ok {
				continue
			}
			zone, e := dnsName(s.Hdr.Name)
			if e != nil {
				continue
			}
			covers := true
			for n := range reached {
				covers = covers && (n == zone || strings.HasSuffix(n, "."+zone))
			}
			if !covers {
				continue
			}
			s.Hdr.Ttl = min(s.Hdr.Ttl, s.Minttl, p.NegativeTTL)
			s.Minttl = min(s.Minttl, p.NegativeTTL)
			kept = append(kept, s)
			soa = true
		}
		m.Ns = kept
		out.Changed = true
		if !soa {
			out.CacheControl = "no-store"
		}
	}
	if out.Changed {
		m.AuthenticatedData = false
		// Conservative removal includes signatures for unchanged sets: no stale
		// denial proofs or misleading signature survive a local-policy synthesis.
		for _, section := range []*[]dns.RR{&m.Answer, &m.Ns, &m.Extra} {
			kept := (*section)[:0]
			for _, rr := range *section {
				switch rr.Header().Rrtype {
				case dns.TypeRRSIG, dns.TypeNSEC, dns.TypeNSEC3:
					continue
				}
				kept = append(kept, rr)
			}
			*section = kept
		}
		wire, e := m.Pack()
		if e != nil || len(wire) > 65535 {
			return out, fmt.Errorf("DNS policy: encode failure")
		}
		out.Wire = wire
	}
	if out.CacheControl == "" {
		ttl := uint32(math.MaxUint32)
		for _, rr := range dnsRecords(&m) {
			if rr.Header().Rrtype != dns.TypeOPT {
				ttl = min(ttl, rr.Header().Ttl)
				if soa, ok := rr.(*dns.SOA); ok {
					ttl = min(ttl, soa.Minttl)
				}
			}
		}
		if ttl == math.MaxUint32 || ttl == 0 {
			out.CacheControl = "no-store"
		} else {
			out.CacheControl = fmt.Sprintf("max-age=%d", ttl)
		}
	}
	return out, nil
}

func parseStructuredLeaseDNS(wire []byte, roots []string) ([]DNSLeaseObservation, error) {
	var m dns.Msg
	if len(wire) > 65535 || m.Unpack(wire) != nil || len(m.Question) != 1 {
		return nil, fmt.Errorf("lease DNS: malformed response")
	}
	name, e := dnsName(m.Question[0].Name)
	if e != nil {
		// Assigned roots are normalized LDH A-labels, so this QNAME can never
		// match one. It is still a valid DNS question: skip observation rather
		// than turning a client query into "DNS policy: invalid name".
		metricLeaseInvalidQuestionName.Add(1)
		return nil, nil
	}
	root := dnsRoot(roots, name)
	if root == "" {
		return nil, nil
	}
	if !m.Response || m.Truncated || m.Opcode != 0 {
		return nil, fmt.Errorf("lease DNS: incomplete response")
	}
	if m.Rcode != 0 || m.Question[0].Qclass != dns.ClassINET {
		return nil, nil
	}
	reached, e := dnsChain(&m, name, 32)
	if e != nil {
		if errors.Is(e, errPolicyInvalidName) {
			metricLeaseInvalidRecordName.Add(1)
		}
		return nil, e
	}
	type entry struct {
		owner  string
		source string
		rrtype uint16
		ip     netip.Addr
		ttl    uint32
	}
	var entries []entry
	for _, rr := range append(append([]dns.RR{}, m.Answer...), m.Extra...) {
		owner, _ := dnsName(rr.Header().Name)
		ttl, ok := reached[owner]
		if !ok || rr.Header().Class != dns.ClassINET {
			continue
		}
		ttl = min(ttl, rr.Header().Ttl)
		add := func(ip netip.Addr) error {
			if !ip.IsValid() || ip.Is4In6() {
				return fmt.Errorf("lease DNS: invalid address")
			}
			source := "peerapi-dns"
			if svcb(rr) != nil {
				source = "svcb-hint"
			}
			entries = append(entries, entry{owner: owner, source: source, rrtype: rr.Header().Rrtype, ip: ip, ttl: ttl})
			return nil
		}
		switch r := rr.(type) {
		case *dns.A:
			if ip, ok := netip.AddrFromSlice(r.A.To4()); ok {
				if e := add(ip); e != nil {
					return nil, e
				}
			}
		case *dns.AAAA:
			if ip, ok := netip.AddrFromSlice(r.AAAA); ok {
				if e := add(ip); e != nil {
					return nil, e
				}
			}
		default:
			if s := svcb(rr); s != nil && s.Priority > 0 {
				if !sanitizeSVCB(s, false) {
					return nil, fmt.Errorf("lease DNS: unsafe service record")
				}
				for _, v := range s.Value {
					if h, ok := v.(*dns.SVCBIPv6Hint); ok {
						for _, a := range h.Hint {
							ip, ok := netip.AddrFromSlice(a)
							if !ok || !ip.Is6() || ip.Is4In6() {
								return nil, fmt.Errorf("lease DNS: invalid IPv6 hint")
							}
							if e := add(ip); e != nil {
								return nil, e
							}
						}
					}
					if h, ok := v.(*dns.SVCBIPv4Hint); ok {
						for _, a := range h.Hint {
							if ip, ok := netip.AddrFromSlice(a.To4()); ok {
								if e := add(ip); e != nil {
									return nil, e
								}
							}
						}
					}
				}
			}
		}
	}
	// Use the RRset minimum even when one address appears with multiple TTLs.
	out := []DNSLeaseObservation{}
	seen := map[string]bool{}
	for _, v := range entries {
		ttl := v.ttl
		for _, other := range entries {
			if other.owner == v.owner && other.rrtype == v.rrtype {
				ttl = min(ttl, other.ttl)
			}
		}
		key := fmt.Sprintf("%s/%d/%s", v.owner, v.rrtype, v.ip)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, DNSLeaseObservation{AssignedRoot: root, QName: name, Chain: name + " > " + v.owner, IP: v.ip, Source: v.source, TTL: time.Duration(ttl) * time.Second})
	}
	return out, nil
}

// CheckQuery classifies protocol errors before upstream resolution. Default-off
// is byte-for-byte upstream behavior. With a policy active, undecodable queries
// fail closed with FORMERR; valid unrelated questions retain the upstream path.
func (p DNSPolicy) CheckQuery(wire []byte) (managed bool, failure *DNSPolicyResult) {
	if p.TTLCap == 0 && !p.IPv4Only {
		return false, nil
	}
	var q dns.Msg
	malformed := len(wire) > 65535 || q.Unpack(wire) != nil
	if !malformed && len(q.Question) == 0 {
		malformed = true
	}
	if !malformed {
		for _, question := range q.Question {
			name, err := dnsName(question.Name)
			if err == nil && dnsRoot(p.Assigned, name) != "" && (p.TTLCap != 0 || p.IPv4Only && dnsRoot(p.Targets, name) != "") {
				managed = true
			}
		}
		if !managed {
			return false, nil
		}
	}
	code := dns.RcodeSuccess
	if malformed || q.Response || len(q.Question) != 1 {
		code = dns.RcodeFormatError
	} else if q.Opcode != dns.OpcodeQuery || q.Question[0].Qclass != dns.ClassINET {
		code = dns.RcodeNotImplemented
	}
	if code == dns.RcodeSuccess {
		return managed, nil
	}
	out := new(dns.Msg)
	if malformed {
		if len(wire) >= 2 {
			out.Id = uint16(wire[0])<<8 | uint16(wire[1])
		}
		out.Response = true
	} else {
		out.SetReply(&q)
	}
	out.Rcode = code
	out.AuthenticatedData = false
	data, _ := out.Pack()
	return true, &DNSPolicyResult{Wire: data, Managed: true, CacheControl: "no-store"}
}
