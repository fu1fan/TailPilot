// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"tailscale.com/appc"
	"time"

	"tailscale.com/featurepolicy"
	"tailscale.com/util/clientmetric"
	"tailscale.com/wgengine/magicsock"
)

var unifiedDebugReloadOK = clientmetric.NewCounter("unified_policy_reload_accepted")
var unifiedDebugReloadError = clientmetric.NewCounter("unified_policy_reload_rejected")

// UnifiedDebugRequest is internal debug input; no credentials or policy body.
type UnifiedDebugRequest struct {
	Manifest         *appc.ControlProofManifest `json:"manifest,omitempty"`
	ExpectSourceID   uint64                     `json:"expect_source_id,omitempty"`
	Claims           []appc.LegacyDNSReference  `json:"claims,omitempty"`
	ConfirmTime      bool                       `json:"confirm_time,omitempty"`
	Source           string                     `json:"source,omitempty"`
	File             string                     `json:"file,omitempty"`
	ExpectGeneration uint64                     `json:"expect_generation"`
	ExpectSHA256     string                     `json:"expect_sha256,omitempty"`
}
type unifiedDebugCall struct {
	ctx    context.Context
	action string
	req    UnifiedDebugRequest
	reply  chan unifiedDebugReply
}
type unifiedDebugReply struct {
	result featurepolicy.Inspection
	err    error
}

// UnifiedPolicyInspect runs on the existing lifecycle writer. Cancellation
// before execution prevents writes; cancellation after commit cannot undo it.
func (b *LocalBackend) UnifiedPolicyInspect(ctx context.Context, action string, req UnifiedDebugRequest) (featurepolicy.Inspection, error) {
	b.mu.Lock()
	r, done := b.unifiedRuntime, b.unifiedDone
	stopped := b.unifiedWorkerStopped
	b.mu.Unlock()
	if r == nil || done == nil || stopped {
		return featurepolicy.Inspection{}, errors.New("policy_worker_unavailable")
	}
	call := unifiedDebugCall{ctx, action, req, make(chan unifiedDebugReply, 1)}
	select {
	case r.debug <- call:
	case <-ctx.Done():
		return featurepolicy.Inspection{}, ctx.Err()
	case <-done:
		return featurepolicy.Inspection{}, errors.New("policy_worker_stopped")
	}
	select {
	case v := <-call.reply:
		return v.result, v.err
	case <-ctx.Done():
		return featurepolicy.Inspection{}, ctx.Err()
	case <-done:
		return featurepolicy.Inspection{}, errors.New("policy_worker_stopped")
	}
}

func (b *LocalBackend) handleUnifiedDebug(r *unifiedPolicyRuntime, call unifiedDebugCall) bool {
	result, err := b.inspectUnifiedPolicy(r, call)
	if call.action == "unified-time-confirm" || call.action == "unified-auto-clear" || call.action == "unified-auto-clear-preview" {
		b.logf("unified debug action=%s accepted=%t error=%t", call.action, result.Accepted, err != nil)
	}
	if call.action == "unified-policy-reload" {
		if err == nil {
			unifiedDebugReloadOK.Add(1)
		} else {
			unifiedDebugReloadError.Add(1)
		}
	}
	call.reply <- unifiedDebugReply{result, err}
	return call.action == "unified-auto-clear" || err == nil && result.Accepted
}
func (b *LocalBackend) inspectUnifiedPolicy(r *unifiedPolicyRuntime, call unifiedDebugCall) (featurepolicy.Inspection, error) {
	var out featurepolicy.Inspection
	if err := call.ctx.Err(); err != nil {
		return out, err
	}
	if r.manager == nil || !r.started {
		return out, errors.New("policy_not_ready")
	}
	b.mu.Lock()
	b.waitUnifiedPrefsTransactionLocked()
	valid := b.unifiedRevision == r.input.PeerIdentityEpoch && b.unifiedProfileID == r.input.ProfileID
	b.mu.Unlock()
	if !valid {
		return out, errors.New("policy_inputs_changed_retry")
	}
	if strings.HasPrefix(call.action, "appc-route-") {
		plan, err := b.connectorAction(r, call.action, call.req)
		out.ClearPreview, _ = json.Marshal(plan)
		out.RequestedSHA256 = plan.SnapshotHash
		out.AcceptedGeneration = plan.Fence.Generation
		out.Accepted = err == nil && !strings.HasSuffix(call.action, "-preview")
		out.Applied = out.Accepted
		return out, err
	}
	if call.action == "unified-auto-clear-preview" || call.action == "unified-auto-clear" {
		if r.connector != nil {
			return out, errors.New("use appc-route-reset-preview and appc-route-reset")
		}
		plan, err := b.clearUnifiedAutomatic(r, call.req, call.action == "unified-auto-clear-preview")
		out.ClearPreview, _ = json.Marshal(plan)
		out.RequestedSHA256 = plan.SnapshotHash
		out.AcceptedGeneration = plan.Fence.Generation
		out.Accepted = err == nil && call.action == "unified-auto-clear"
		return out, err
	}
	if call.action == "unified-time-confirm" {
		snap := r.manager.Current()
		if !call.req.ConfirmTime || call.req.Source == "" || len(call.req.Source) > 200 {
			return out, errors.New("explicit_lead_time_confirmation_required")
		}
		if snap.Fence().Generation != call.req.ExpectGeneration || r.manager.SourceHash() != call.req.ExpectSHA256 || call.req.ExpectSHA256 == "" {
			return out, errors.New("policy_cas_conflict")
		}
		if r.connector == nil || r.ownerSnapshot != snap || !snap.Config().Lease.Enabled {
			return out, errors.New("lease_consumer_not_ready")
		}
		err := r.connector.ConfirmTTLTime(snap.Fence(), "localapi-lead:"+call.req.Source)
		b.logf("unified time confirmation: generation=%d accepted=%t", snap.Fence().Generation, err == nil)
		if err != nil {
			return out, err
		}
		out.Accepted = true
		out.AcceptedGeneration = snap.Fence().Generation
		r.nextSweep = time.Now()
		return out, nil
	}
	read := r.read
	if call.req.File != "" {
		if call.action != "unified-policy-preview" {
			return out, errors.New("reload_uses_current_file")
		}
		read = func() ([]byte, error) { return featurepolicy.ReadFile(call.req.File) }
	}
	data, err := read()
	if err != nil {
		return out, errors.New("policy_file_unreadable_or_untrusted")
	}
	b.mu.Lock()
	b.waitUnifiedPrefsTransactionLocked()
	valid = b.unifiedRevision == r.input.PeerIdentityEpoch && b.unifiedProfileID == r.input.ProfileID
	b.mu.Unlock()
	if !valid {
		return out, errors.New("policy_inputs_changed_retry")
	}
	out = featurepolicy.Inspect(data, &r.input, r.manager.Current())
	if call.action == "unified-policy-preview" {
		if out.SchemaValid {
			c, _ := featurepolicy.Parse(data)
			if c.Enabled && !r.manager.Durable() {
				out.RuntimeReady = false
				out.Error = "durable_store_unavailable"
			}
			b.mu.Lock()
			b.waitUnifiedPrefsTransactionLocked()
			connectorReady := b.appConnector != nil
			pathReady := false
			if b.sys != nil {
				if ms, ok := b.sys.MagicSock.GetOK(); ok && ms != nil {
					pathReady = ms.PathPolicyAvailable()
				}
			}
			b.mu.Unlock()
			if c.Enabled && ((c.Lease.Enabled || c.AutoIPv6.Enabled || c.DNSIPv4Only.Enabled) && !connectorReady || c.PathPolicy.Enabled && !pathReady) {
				out.RuntimeReady = false
				out.Error = "consumer_unavailable"
			}
		}
		return out, nil
	}
	if call.action != "unified-policy-reload" {
		return out, errors.New("unknown_policy_action")
	}
	if call.req.ExpectSHA256 == "" {
		return out, errors.New("expected_sha256_required")
	}
	if err := call.ctx.Err(); err != nil {
		return out, err
	}
	if r.manager.Current().Fence().Generation != call.req.ExpectGeneration || out.RequestedSHA256 != call.req.ExpectSHA256 {
		return out, errors.New("policy_cas_conflict")
	}
	if !out.SchemaValid {
		return out, errors.New("invalid_configuration")
	}
	if err := r.manager.Reload(data, call.req.ExpectGeneration, call.req.ExpectSHA256); err != nil {
		return out, errors.New("policy_reload_rejected_lkg_retained")
	}
	out.Accepted = true
	out.AcceptedGeneration = r.manager.Current().Fence().Generation
	out.PendingSideEffects = true
	// Applied remains false until the normal consumer reconciliation completes.
	return out, nil
}

// UnifiedDebugStatus contains only counts, fixed enum values and fences.
// Raw internal errors, rules, peer identifiers, domains and IPs are excluded.
type UnifiedDebugStatus struct {
	PathEvidence              magicsock.PathPolicyEvidence `json:"pathEvidence"`
	DropCounters              map[string]uint64            `json:"dropCounters"`
	OwnerConflicts            int                          `json:"ownerConflicts"`
	ModuleApplied             map[string]bool              `json:"moduleApplied"`
	SchemaValid               bool                         `json:"schemaValid"`
	RuntimeReady              bool                         `json:"runtimeReady"`
	Accepted                  bool                         `json:"accepted"`
	Applied                   bool                         `json:"applied"`
	AcceptedFence             featurepolicy.Fence          `json:"acceptedFence"`
	AppliedFence              featurepolicy.Fence          `json:"appliedFence"`
	SourceSHA256              string                       `json:"source_sha256"`
	CanonicalSHA256           string                       `json:"canonical_sha256"`
	Reconciling               bool                         `json:"reconciling"`
	Degraded                  bool                         `json:"degraded"`
	PendingRules              int                          `json:"pendingRules"`
	Modules                   map[string]bool              `json:"enabledModules"`
	OwnerPrefixes             int                          `json:"ownerPrefixes"`
	IPv6Shared                int                          `json:"ipv6Shared"`
	IPv6Unknown               int                          `json:"ipv6Unknown"`
	Paths                     map[string]int               `json:"paths"`
	LeaseCount                int                          `json:"leaseCount"`
	TimeUncertain             *bool                        `json:"timeUncertain"`
	OldestExpiredLeaseSeconds *float64                     `json:"oldestExpiredLeaseSeconds"`
	OwnerQueueAgeSeconds      *float64                     `json:"ownerQueueAgeSeconds"`

	// Consumer/commit diagnostics. These are fixed enums and counters, never
	// raw error text, domains or identities.
	ConsumerFence     featurepolicy.Fence `json:"consumerFence"`
	ConsumerReady     bool                `json:"consumerReady"`
	TTLBlocked        bool                `json:"ttlBlocked"`
	DegradedCause     string              `json:"degradedCause,omitempty"`
	CurrentRevision   uint64              `json:"currentRevision"`
	PublishedRevision uint64              `json:"publishedRevision"`
}

func (b *LocalBackend) UnifiedPolicyDebugStatus() UnifiedDebugStatus {
	b.mu.Lock()
	st, snap := b.unifiedStatus, b.unifiedSnapshot
	out := UnifiedDebugStatus{AcceptedFence: st.Accepted, AppliedFence: st.Applied, SourceSHA256: st.SourceSHA256, Reconciling: st.Reconciling, Degraded: st.Degraded != "", OwnerPrefixes: len(b.unifiedOwners), Modules: map[string]bool{}, Paths: map[string]int{}}
	if b.unifiedPublishedRevision != b.unifiedRevision {
		out.Reconciling = true
		out.AppliedFence = featurepolicy.Fence{}
	}
	out.ConsumerFence = b.unifiedConsumerFence
	out.CurrentRevision = b.unifiedRevision
	out.PublishedRevision = b.unifiedPublishedRevision
	out.TTLBlocked = b.unifiedTTLBlocked || b.appConnector != nil && b.appConnector.TTLBlocked()
	for _, i := range []*unifiedHealthIssue{b.unifiedHealth.consumer, b.unifiedHealth.sweep, b.unifiedHealth.dns, b.unifiedHealth.policy, b.unifiedHealth.path} {
		if i != nil {
			if out.DegradedCause != "" {
				out.DegradedCause += ","
			}
			out.DegradedCause += i.Cause + ":" + i.Phase
		}
	}
	if snap != nil {
		c := snap.Config()
		v := featurepolicy.Inspect(c.JSON(), nil, nil)
		out.SchemaValid, out.Accepted, out.CanonicalSHA256 = true, true, v.CanonicalSHA256
		out.PendingRules = len(snap.PendingRules())
		// A published snapshot is not the same as an installed consumer. Readiness
		// requires the synchronous consumer fence to match the accepted fence and
		// no quarantined TTL lifecycle, not only a cleared per-publication error.
		out.ConsumerReady = b.unifiedConsumerFence == snap.Fence()
		out.RuntimeReady = out.PendingRules == 0 && !out.Degraded && out.ConsumerReady &&
			b.unifiedPublishedRevision == b.unifiedRevision && !out.TTLBlocked
		out.Applied = out.AppliedFence == out.AcceptedFence && !out.Reconciling
		out.Modules = map[string]bool{"root": c.Enabled, "lease": c.Enabled && c.Lease.Enabled, "auto_ipv6": c.Enabled && c.AutoIPv6.Enabled, "dns_ipv4_only": c.Enabled && c.DNSIPv4Only.Enabled, "path_policy": c.Enabled && c.PathPolicy.Enabled}
	}
	age := float64(0)
	if b.unifiedPrefsPending != nil && !b.unifiedPrefsPendingSince.IsZero() {
		age = max(0, time.Since(b.unifiedPrefsPendingSince).Seconds())
	}
	out.OwnerQueueAgeSeconds = &age
	out.ModuleApplied = map[string]bool{}
	for name := range out.Modules {
		out.ModuleApplied[name] = out.Applied
	}
	for p, o := range b.unifiedOwners {
		if len(o.Auto) > 0 && o.nonAuto() {
			out.OwnerConflicts++
		}
		if p.Addr().Is6() && p.IsSingleIP() {
			if o.LegacyUnknown {
				out.IPv6Unknown++
			}
			if o.AutoIPv6Blocked && o.nonAuto() {
				out.IPv6Shared++
			}
		}
	}
	if b.sys != nil {
		if ms, ok := b.sys.MagicSock.GetOK(); ok && ms != nil {
			out.DropCounters = ms.PathPolicyDropCounters()
			out.PathEvidence = ms.PathPolicyEvidenceState()
			_, paths, _ := ms.PathPolicyState()
			for _, p := range paths {
				out.Paths[fmt.Sprintf("%s/%s/%s", p.State, p.Active, p.Reason)]++
			}
		}
	}
	out.LeaseCount, out.TimeUncertain, out.OldestExpiredLeaseSeconds = st.LeaseCount, st.TimeUncertain, st.OldestExpiredLeaseSeconds
	b.mu.Unlock()
	return out
}
