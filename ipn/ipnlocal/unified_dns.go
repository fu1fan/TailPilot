// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"tailscale.com/featurepolicy"
	"time"

	"tailscale.com/appc"
	"tailscale.com/util/clientmetric"
)

var (
	metricUnifiedDNSManaged = clientmetric.NewCounter("unified_dns_managed")
	metricUnifiedDNSChanged = clientmetric.NewCounter("unified_dns_changed")
	metricUnifiedDNSFailure = clientmetric.NewCounter("unified_dns_failure")

	// Failure classes are split so an upstream timeout, a queue deadline and a
	// persistent consumer/commit rejection are not conflated in one counter.
	metricUnifiedDNSUpstreamError     = clientmetric.NewCounter("unified_dns_upstream_error")
	metricUnifiedDNSUpstreamTimeout   = clientmetric.NewCounter("unified_dns_upstream_timeout")
	metricUnifiedDNSObserveError      = clientmetric.NewCounter("unified_dns_observe_error")
	metricUnifiedDNSQueueStale        = clientmetric.NewCounter("unified_dns_queue_stale")
	metricUnifiedDNSQueueFull         = clientmetric.NewCounter("unified_dns_queue_full")
	metricUnifiedDNSQueueDeadline     = clientmetric.NewCounter("unified_dns_queue_deadline")
	metricUnifiedDNSCommitPrewrite    = clientmetric.NewCounter("unified_dns_commit_prewrite_stale")
	metricUnifiedDNSCommitObserver    = clientmetric.NewCounter("unified_dns_commit_observer_stale")
	metricUnifiedDNSCommitBlocked     = clientmetric.NewCounter("unified_dns_commit_ttl_blocked")
	metricUnifiedDNSCommitStorage     = clientmetric.NewCounter("unified_dns_commit_storage")
	metricUnifiedDNSCommitOther       = clientmetric.NewCounter("unified_dns_commit_other")
	metricUnifiedDNSQueueStoppedCount = clientmetric.NewCounter("unified_dns_queue_stopped")
)

// unifiedDNSFailureClass is a fixed vocabulary for DNS path failures.
type unifiedDNSFailureClass string

const (
	dnsFailUpstream      unifiedDNSFailureClass = "upstream"
	dnsFailUpstreamDelay unifiedDNSFailureClass = "upstream-timeout"
	dnsFailPolicyInvalid unifiedDNSFailureClass = "policy-invalid"
	dnsFailPrewriteStale unifiedDNSFailureClass = "prewrite-stale"
	dnsFailObserverStale unifiedDNSFailureClass = "observer-stale"
	dnsFailTTLBlocked    unifiedDNSFailureClass = "ttl-blocked"
	dnsFailQueueDeadline unifiedDNSFailureClass = "queue-deadline"
	dnsFailStorage       unifiedDNSFailureClass = "storage"
	dnsFailCommit        unifiedDNSFailureClass = "commit"
)

// classifyUnifiedDNSFailure maps an observe/commit error to a bounded cause and
// reports whether the failure is persistent enough to keep degraded set.
func classifyUnifiedDNSFailure(err error) (class unifiedDNSFailureClass, phase string, action string, persistent bool) {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return dnsFailQueueDeadline, "queue", "", false
	}
	var commitErr *connectorCommitError
	if errors.As(err, &commitErr) {
		phase = commitErr.Stage
		switch commitErr.Stage {
		case "prewrite-fence":
			return dnsFailPrewriteStale, phase, "", true
		case "prewrite-blocked":
			return dnsFailTTLBlocked, phase, "", true
		}
		var te *appc.TTLTransitionError
		if errors.As(err, &te) {
			action = te.Action
		}
		if commitErr.Started {
			return dnsFailStorage, phase, action, true
		}
		return dnsFailCommit, phase, action, true
	}
	if errors.Is(err, appc.ErrTTLStaleObservation) {
		return dnsFailObserverStale, "observer", "", false
	}
	var te *appc.TTLTransitionError
	if errors.As(err, &te) {
		phase, action = string(te.Phase), te.Action
		if te.Phase == appc.TTLCommitPrewrite {
			return dnsFailPrewriteStale, phase, action, true
		}
		return dnsFailStorage, phase, action, true
	}
	return dnsFailCommit, "", "", true
}

func countUnifiedDNSFailure(class unifiedDNSFailureClass) {
	switch class {
	case dnsFailPrewriteStale:
		metricUnifiedDNSCommitPrewrite.Add(1)
	case dnsFailObserverStale:
		metricUnifiedDNSCommitObserver.Add(1)
	case dnsFailTTLBlocked:
		metricUnifiedDNSCommitBlocked.Add(1)
	case dnsFailStorage:
		metricUnifiedDNSCommitStorage.Add(1)
	case dnsFailQueueDeadline:
		metricUnifiedDNSQueueDeadline.Add(1)
	}
}

// errUnifiedDNSStaleCapture marks a managed answer whose captured snapshot was
// invalidated by a policy revision before the reply. The PeerAPI handler retries
// it once with a fresh capture; only a still-stale second attempt is a managed
// failure. This is the documented transient boundary of fence churn.
var errUnifiedDNSStaleCapture = errors.New("unified DNS stale capture")

var metricUnifiedDNSStaleRetry = clientmetric.NewCounter("unified_dns_stale_capture_retry")
var metricUnifiedDNSStaleFinal = clientmetric.NewCounter("unified_dns_stale_capture_final")
var metricUnifiedDNSStaleSeen = clientmetric.NewCounter("unified_dns_stale_capture_seen")

// isTimeoutError reports an upstream network timeout without depending on a
// concrete resolver error type.
func isTimeoutError(err error) bool {
	var te interface{ Timeout() bool }
	return errors.As(err, &te) && te.Timeout()
}

// captureUnifiedDNS captures policy and assignment before upstream resolution.
// No callback holds b.mu during resolver or durable-store I/O.
func (b *LocalBackend) captureUnifiedDNS(ctx context.Context) (appc.DNSPolicy, func() bool, func([]byte) error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	s := b.unifiedSnapshot
	if s == nil || !s.Enabled() || b.appConnector == nil {
		return appc.DNSPolicy{}, func() bool { return true }, nil
	}
	c := s.Config()
	if !c.Lease.Enabled && !c.DNSIPv4Only.Enabled {
		return appc.DNSPolicy{}, func() bool { return true }, nil
	}
	p := appc.DNSPolicy{Assigned: slices.Clone(b.unifiedDomains), Targets: slices.Clone(c.DNSIPv4Only.Targets), IPv4Only: c.DNSIPv4Only.Enabled, NegativeTTL: uint32(c.DNSIPv4Only.NegativeTTLSeconds), MaxDepth: c.DNSIPv4Only.MaxChainDepth}
	if c.Lease.Enabled {
		p.TTLCap = uint32(c.Lease.TTLCapSeconds)
	}
	fence, revision, connector := s.Fence(), b.unifiedRevision, b.appConnector
	observer := connector.CaptureDNSObserver()
	if s.OwnershipEnabled() {
		rawObserver := observer
		batchObserver := connector.CaptureDNSBatchObserver()
		runtime, done := b.unifiedRuntime, b.unifiedDone

		wait := time.Duration(min(c.DNSIPv4Only.LocalRouteWaitMS, 2000)) * time.Millisecond
		observer = func(wire []byte) error {
			if runtime == nil || done == nil {
				return fmt.Errorf("DNS queue unavailable")
			}
			return runtime.enqueueDNS(ctx, done, fence, wait, func() error { return rawObserver(wire) }, unifiedDNSBatch{wire: wire, observe: batchObserver})
		}
	}
	ready := !s.OwnershipEnabled() || b.unifiedConsumerFence == fence
	return p, func() bool {
		b.mu.Lock()
		defer b.mu.Unlock()
		return ready && b.appConnector == connector && b.unifiedSnapshot == s && b.unifiedSnapshot.Fence() == fence && b.unifiedRevision == revision && b.unifiedPublishedRevision == revision
	}, observer
}

// processUnifiedDNS uses a single returned result for both observation and wire
// output. Local persistence is not an acknowledgement of client route delivery.
func processUnifiedDNS(ctx context.Context, q []byte, p appc.DNSPolicy, valid func() bool, observe func([]byte) error, resolve func(context.Context, []byte) ([]byte, error)) (appc.DNSPolicyResult, error) {
	managed, queryFailure := p.CheckQuery(q)
	if queryFailure != nil {
		metricUnifiedDNSFailure.Add(1)
		return *queryFailure, nil
	}
	// Cancellation is cooperative: never spawn a goroutine to abandon legacy
	// resolver/store I/O. Check again when such a call finally returns.
	failed := func(e error) (appc.DNSPolicyResult, error) {
		if managed {
			metricUnifiedDNSFailure.Add(1)
			wire, err := appc.LeaseFailureResponse(q)
			return appc.DNSPolicyResult{Wire: wire, Managed: true, CacheControl: "no-store"}, err
		}
		return appc.DNSPolicyResult{}, e
	}
	if err := ctx.Err(); err != nil {
		return failed(err)
	}
	wire, e := resolve(ctx, q)
	if err := ctx.Err(); err != nil {
		return failed(err)
	}
	if e != nil {
		if errors.Is(e, context.DeadlineExceeded) || isTimeoutError(e) {
			metricUnifiedDNSUpstreamTimeout.Add(1)
		} else {
			metricUnifiedDNSUpstreamError.Add(1)
		}
		return failed(e)
	}
	out, e := p.Transform(q, wire)
	if out.Managed {
		metricUnifiedDNSManaged.Add(1)
	}
	if out.Changed {
		metricUnifiedDNSChanged.Add(1)
	}
	failure := func() (appc.DNSPolicyResult, error) {
		metricUnifiedDNSFailure.Add(1)
		w, e := appc.LeaseFailureResponse(q)
		return appc.DNSPolicyResult{Wire: w, Managed: true, CacheControl: "no-store"}, e
	}
	if err := ctx.Err(); err != nil {
		return failed(err)
	}
	if e != nil {
		return failure()
	}
	if out.Managed && !valid() {
		metricUnifiedDNSStaleSeen.Add(1)
		w, _ := appc.LeaseFailureResponse(q)
		return appc.DNSPolicyResult{Wire: w, Managed: true, CacheControl: "no-store"}, errUnifiedDNSStaleCapture
	}
	if err := ctx.Err(); err != nil {
		return failed(err)
	}
	if observe != nil {
		observation := out.Wire
		if out.Managed && p.IPv4Only {
			// Learn both address families before releasing the filtered answer.
			// Use the validated policy view, never unvalidated upstream bytes.
			routes, err := p.TransformForRoutes(q, wire)
			if err != nil {
				return failure()
			}
			observation = routes.Wire
		}
		if e := observe(observation); e != nil {
			metricUnifiedDNSObserveError.Add(1)
			// Only a managed answer is withheld on observation failure. An
			// unmanaged query keeps its upstream bytes: the observation parser
			// is best-effort outside the policy's managed set (for example a
			// _dmarc TXT QNAME outside the LDH A-label grammar).
			if out.Managed {
				return failure()
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return failed(err)
	}
	if out.Managed && !valid() {
		metricUnifiedDNSStaleSeen.Add(1)
		w, _ := appc.LeaseFailureResponse(q)
		return appc.DNSPolicyResult{Wire: w, Managed: true, CacheControl: "no-store"}, errUnifiedDNSStaleCapture
	}
	if err := ctx.Err(); err != nil {
		return failed(err)
	}
	return out, nil
}

// One bounded mailbox is drained by the existing lifecycle worker. Requests
// waiting for disk/route I/O may cancel without spawning an abandoned goroutine.
// StateStore has no cancellation API: an in-progress write finishes on the
// worker, remains fenced, and is joined by shutdown.
type unifiedDNSBatch struct {
	wire    []byte
	observe func([][]byte) []error
}

type unifiedDNSCall struct {
	batch     unifiedDNSBatch
	ctx       context.Context
	fence     featurepolicy.Fence
	queueOnly bool
	observe   func() error
	reply     chan error
}

func (r *unifiedPolicyRuntime) enqueueDNS(ctx context.Context, done <-chan struct{}, f featurepolicy.Fence, wait time.Duration, observe func() error, batch ...unifiedDNSBatch) error {
	if wait > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, min(wait, 2*time.Second))
		defer cancel()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	call := unifiedDNSCall{ctx: ctx, fence: f, queueOnly: wait == 0, observe: observe, reply: make(chan error, 1)}
	if len(batch) > 0 {
		call.batch = batch[0]
	}
	select {
	case <-done:
		return fmt.Errorf("DNS queue stopped")
	default:
	}
	select {
	case r.dns <- call:
	default:
		metricUnifiedDNSQueueFull.Add(1)
		return fmt.Errorf("DNS queue full")
	}
	select {
	case err := <-call.reply:
		return err
	case <-ctx.Done():
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			metricUnifiedDNSQueueDeadline.Add(1)
		}
		return ctx.Err()
	case <-done:
		metricUnifiedDNSQueueStoppedCount.Add(1)
		return fmt.Errorf("DNS queue stopped")
	}
}
func (b *LocalBackend) handleUnifiedDNS(r *unifiedPolicyRuntime, call unifiedDNSCall) {
	if err := call.ctx.Err(); err != nil {
		call.reply <- err
		return
	}
	current := r.manager.Current()
	if current.Fence() != call.fence || r.ownerSnapshot != current {
		// A captured request whose snapshot moved is expected during churn. It
		// is not a durable commit failure and must not be counted as one.
		metricUnifiedDNSQueueStale.Add(1)
		call.reply <- fmt.Errorf("DNS queue stale fence: captured generation=%d current generation=%d", call.fence.Generation, current.Fence().Generation)
		return
	}
	err := call.observe()
	if call.queueOnly || err != nil {
		call.reply <- err
	}
	if !call.queueOnly && err == nil {
		err = call.ctx.Err()
	}
	if !call.queueOnly {
		select {
		case call.reply <- err:
		default:
		}
	}
	if err == nil {
		b.mu.Lock()
		b.waitUnifiedPrefsTransactionLocked()
		b.clearUnifiedIssueLocked(unifiedCauseDNSQueue, &call.fence)
		b.unifiedStatus.Degraded = b.unifiedDegradedFromHealthLocked()
		b.mu.Unlock()
		return
	}
	class, phase, action, persistent := classifyUnifiedDNSFailure(err)
	if class != dnsFailQueueDeadline {
		countUnifiedDNSFailure(class)
	}
	b.mu.Lock()
	b.waitUnifiedPrefsTransactionLocked()
	ttlBlocked := b.unifiedTTLBlocked || b.appConnector != nil && b.appConnector.TTLBlocked()
	if persistent {
		b.noteUnifiedIssueLocked(unifiedCauseDNSQueue, err)
	}
	degraded := b.unifiedDegradedFromHealthLocked()
	if degraded == "" {
		degraded = "DNS route queue commit failed class=" + string(class)
	}
	b.unifiedStatus.Degraded = degraded
	b.unifiedStatus.Reconciling = true
	b.unifiedStatus.Applied = featurepolicy.Fence{}
	b.mu.Unlock()
	b.logf("unified DNS route queue: commit failed class=%s phase=%s action=%s captured_generation=%d captured_assigned=%d captured_identity=%d queue_only=%t persistent=%t ttl_blocked=%t err=%v",
		class, phase, action, call.fence.Generation, call.fence.AssignedDomainsEpoch, call.fence.PeerIdentityEpoch, call.queueOnly, persistent, ttlBlocked, err)
}

// Drain only the already available bounded mailbox. Never delay a sparse
// query to fill a batch, and never merge across authorization fences.
func (b *LocalBackend) handleUnifiedDNSBatch(r *unifiedPolicyRuntime, first unifiedDNSCall) {
	calls := []unifiedDNSCall{first}
	for len(calls) < 64 {
		select {
		case c := <-r.dns:
			calls = append(calls, c)
		default:
			goto drained
		}
	}
drained:
	for len(calls) > 0 {
		c := calls[0]
		calls = calls[1:]
		if c.batch.observe == nil || c.ctx.Err() != nil {
			b.handleUnifiedDNS(r, c)
			continue
		}
		current := r.manager.Current()
		if current.Fence() != c.fence || r.ownerSnapshot != current {
			b.handleUnifiedDNS(r, c)
			continue
		}
		group := []unifiedDNSCall{c}
		rest := make([]unifiedDNSCall, 0, len(calls))
		for _, v := range calls {
			if v.batch.observe != nil && v.fence == c.fence && v.ctx.Err() == nil {
				group = append(group, v)
			} else {
				rest = append(rest, v)
			}
		}
		calls = rest
		wires := make([][]byte, len(group))
		for i, v := range group {
			wires[i] = v.batch.wire
		}
		errs := c.batch.observe(wires)
		for i, v := range group {
			err := errs[i]
			v.observe = func() error { return err }
			b.handleUnifiedDNS(r, v)
		}
	}
}

// Wait only for publication/consumer convergence, never relax a fence check.
// The retry remains bounded by both the caller and this short readiness wait.
func (b *LocalBackend) waitUnifiedDNSReady(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, 250*time.Millisecond)
	defer cancel()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		b.mu.Lock()
		s := b.unifiedSnapshot
		ready := s == nil || b.unifiedRevision == b.unifiedPublishedRevision && (!s.OwnershipEnabled() || b.unifiedConsumerFence == s.Fence())
		b.mu.Unlock()
		if ready {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
