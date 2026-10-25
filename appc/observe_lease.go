// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package appc

import (
	"net/netip"
	"slices"
	"sync/atomic"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/types/appctype"
)

// DNSLeaseObservation carries the TTL actually present in a returned answer.
// No independent cap is applied: the pre-send policy transforms the wire first.
type DNSLeaseObservation struct {
	AssignedRoot string
	QName        string
	Chain        string
	IP           netip.Addr
	Source       string
	TTL          time.Duration
}

type dnsLeaseSink struct {
	roots   []string
	observe func([]DNSLeaseObservation) error
}

// SetLeaseObserver installs the synchronous lease path. A nil observer restores
// the exact upstream parser/advertiser. The callback must durably record leases
// and route intent before returning success; it is invoked with no appc lock.
// Callers must capture and recheck the policy/profile fence at side-effect time.
func (e *AppConnector) SetLeaseObserver(roots []string, observe func([]DNSLeaseObservation) error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	// Takeover cannot be detached without a durable backend handoff.
	if e.ttl.Load() != nil {
		return
	}
	if observe == nil {
		if e.leaseSink.Load() != nil {
			e.leaseEpoch.Add(1)
		}
		e.leaseSink.Store(nil)
		return
	}
	e.leaseEpoch.Add(1)
	e.leaseSink.Store(&dnsLeaseSink{roots: slices.Clone(roots), observe: observe})
}

// ParseLeaseDNS observes only reachable records in the actual returned response.
// It supports CNAME, DNAME and SVCB/HTTPS, without cross-response alias state.
func ParseLeaseDNS(wire []byte, roots []string) ([]DNSLeaseObservation, error) {
	return parseStructuredLeaseDNS(wire, roots)
}

// Keep the pointer type local to this implementation while allowing AppConnector
// to remain buildable with ts_omit_appconnectors.
type leaseSinkPointer = atomic.Pointer[dnsLeaseSink]

// LeaseObservationError requires withholding a managed positive answer. Legacy
// parser errors deliberately retain their upstream best-effort behavior.
type LeaseObservationError struct{ Err error }

func (e *LeaseObservationError) Error() string { return "durable DNS lease: " + e.Err.Error() }
func (e *LeaseObservationError) Unwrap() error { return e.Err }

// LeaseFailureResponse constructs a SERVFAIL from the original query, without
// retaining a positive answer, signatures, or the AD bit from upstream.
func LeaseFailureResponse(query []byte) ([]byte, error) {
	var q dnsmessage.Message
	if err := q.Unpack(query); err != nil {
		return nil, err
	}
	out := dnsmessage.Message{Header: dnsmessage.Header{ID: q.Header.ID, Response: true, RecursionDesired: q.Header.RecursionDesired, CheckingDisabled: q.Header.CheckingDisabled, RecursionAvailable: true, RCode: dnsmessage.RCodeServerFailure}, Questions: q.Questions}
	return out.Pack()
}

// InstallLegacyRouteInfo installs a durable handoff without advertising a diff.
// The caller excludes backend writers and fences old DNS callbacks first.
func (e *AppConnector) InstallLegacyRouteInfo(ri appctype.RouteInfo) {
	if e.ttl.Load() != nil {
		return
	} // A legacy writer cannot replace the TTL authority.
	e.leaseEpoch.Add(1)
	done := make(chan struct{})
	e.queue.Add(func() {
		e.mu.Lock()
		defer e.mu.Unlock()
		e.controlRoutes = slices.Clone(ri.Control)
		e.wildcards = slices.Clone(ri.Wildcards)
		e.domains = map[string][]netip.Addr{}
		for d, ips := range ri.Domains {
			e.domains[d] = slices.Clone(ips)
		}
		e.leaseSink.Store(nil)
		close(done)
	})
	<-done
}
