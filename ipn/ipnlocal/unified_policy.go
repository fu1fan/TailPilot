// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strings"
	"time"

	"tailscale.com/appc"
	"tailscale.com/envknob"
	"tailscale.com/featurepolicy"
	"tailscale.com/ipn"
)

var unifiedPolicyFile = envknob.RegisterString("TS_UNIFIED_POLICY_FILE")

// UnifiedPolicyStatus separates policy acceptance from consumer application.
// LocalAPI exposes a separate redacted projection.
type UnifiedPolicyStatus struct {
	SourceSHA256              string
	LeaseCount                int
	TimeUncertain             *bool
	OldestExpiredLeaseSeconds *float64
	Accepted                  featurepolicy.Fence
	Applied                   featurepolicy.Fence
	Reconciling               bool
	Degraded                  string
}

type unifiedPolicyRuntime struct {
	dns              chan unifiedDNSCall
	debug            chan unifiedDebugCall
	read             func() ([]byte, error)
	manager          *featurepolicy.Manager
	input            featurepolicy.Inputs
	profile          string
	started          bool
	ownerSnapshot    *featurepolicy.PolicySnapshot
	connector        *appc.AppConnector
	connectorAdapter *connectorBackend
	packets          *appc.PacketActivity
	leaseProfile     string
	nextSweep        time.Time
}

func newUnifiedPolicyRuntime(read func() ([]byte, error)) *unifiedPolicyRuntime {
	return &unifiedPolicyRuntime{read: read, debug: make(chan unifiedDebugCall), dns: make(chan unifiedDNSCall, 64)}
}

// unifiedHealthState keeps consumer failures across policy publications.
// A successful publication is not evidence that an earlier queue or consumer
// failure cleared; only a matching success, or a consumer fence that caught up
// with a newer snapshot, retires the issue. This prevents a timer-driven publish
// from silently flipping runtimeReady back to true.
type unifiedHealthState struct {
	consumer *unifiedHealthIssue
	sweep    *unifiedHealthIssue
	dns      *unifiedHealthIssue
	policy   *unifiedHealthIssue
	path     *unifiedHealthIssue
}

type unifiedHealthIssue struct {
	Cause    string // fixed vocabulary: owner-consumer, sweep, dns-queue
	Phase    string // prewrite | uncertain | journal-* | observer | queue
	Action   string
	Fence    featurepolicy.Fence
	Revision uint64
	Epoch    uint64
	Since    time.Time
}

const (
	unifiedCauseOwner    = "owner-consumer"
	unifiedCauseSweep    = "sweep"
	unifiedCauseDNSQueue = "dns-queue"
	unifiedCausePolicy   = "policy-refresh"
	unifiedCausePath     = "path-policy"
)

func newUnifiedHealthIssue(cause string, err error) *unifiedHealthIssue {
	issue := &unifiedHealthIssue{Cause: cause, Since: time.Now()}
	var te *appc.TTLTransitionError
	if errors.As(err, &te) {
		issue.Phase = string(te.Phase)
		issue.Action = te.Action
		issue.Fence = te.Fence
		issue.Revision = te.Revision
		issue.Epoch = te.Epoch
	}
	var ce *connectorCommitError
	if errors.As(err, &ce) && issue.Phase == "" {
		issue.Phase = ce.Stage
	}
	if issue.Phase == "" {
		issue.Phase = "state"
	}
	return issue
}

// unifiedDegradedString is bounded, fixed-vocabulary text safe for status.
func (i *unifiedHealthIssue) unifiedDegradedString() string {
	return fmt.Sprintf("%s cause=%s action=%s generation=%d assigned=%d identity=%d revision=%d epoch=%d",
		i.Cause, i.Phase, i.Action, i.Fence.Generation, i.Fence.AssignedDomainsEpoch, i.Fence.PeerIdentityEpoch, i.Revision, i.Epoch)
}

func (b *LocalBackend) noteUnifiedIssueLocked(cause string, err error) {
	issue := newUnifiedHealthIssue(cause, err)
	switch cause {
	case unifiedCauseOwner:
		b.unifiedHealth.consumer = issue
	case unifiedCauseSweep:
		b.unifiedHealth.sweep = issue
	case unifiedCauseDNSQueue:
		b.unifiedHealth.dns = issue
	case unifiedCausePolicy:
		b.unifiedHealth.policy = issue
	case unifiedCausePath:
		b.unifiedHealth.path = issue
	}
}

func (b *LocalBackend) clearUnifiedIssueLocked(cause string, fence *featurepolicy.Fence) {
	switch cause {
	case unifiedCauseOwner:
		b.unifiedHealth.consumer = nil
	case unifiedCauseSweep:
		b.unifiedHealth.sweep = nil
	case unifiedCauseDNSQueue:
		if b.unifiedHealth.dns == nil {
			return
		}
		if fence == nil || b.unifiedHealth.dns.Fence == *fence {
			b.unifiedHealth.dns = nil
		}
	case unifiedCausePolicy:
		b.unifiedHealth.policy = nil
	case unifiedCausePath:
		b.unifiedHealth.path = nil
	}
}

// clearStaleUnifiedDNSIssueLocked retires a DNS failure captured under an older
// snapshot once the consumer fence has caught up with the current one.
func (b *LocalBackend) clearStaleUnifiedDNSIssueLocked(current featurepolicy.Fence) {
	if i := b.unifiedHealth.dns; i != nil && i.Fence != current {
		b.unifiedHealth.dns = nil
	}
}

func (b *LocalBackend) unifiedDegradedFromHealthLocked() string {
	var parts []string
	for _, i := range []*unifiedHealthIssue{b.unifiedHealth.consumer, b.unifiedHealth.sweep, b.unifiedHealth.dns, b.unifiedHealth.policy, b.unifiedHealth.path} {
		if i != nil {
			parts = append(parts, i.unifiedDegradedString())
		}
	}
	return strings.Join(parts, "; ")
}

// rebuildUnifiedDegradedLocked records or clears the per-publication causes and
// returns the joined persistent health text. Callers hold b.mu. A later timer
// publication therefore cannot erase a still-present consumer failure.
func (b *LocalBackend) rebuildUnifiedDegradedLocked(pathErr, refreshErr error) string {
	if pathErr != nil {
		b.noteUnifiedIssueLocked(unifiedCausePath, pathErr)
	} else {
		b.clearUnifiedIssueLocked(unifiedCausePath, nil)
	}
	if refreshErr != nil {
		b.noteUnifiedIssueLocked(unifiedCausePolicy, refreshErr)
	} else {
		b.clearUnifiedIssueLocked(unifiedCausePolicy, nil)
	}
	return b.unifiedDegradedFromHealthLocked()
}

func joinUnifiedDegraded(a, b string) string {
	switch {
	case a == "":
		return b
	case b == "":
		return a
	default:
		return a + "; " + b
	}
}

// refresh is used only by the lifecycle worker. All file/store I/O is outside
// b.mu. A profile switch discards the old manager even if new startup fails.
func (r *unifiedPolicyRuntime) refresh(in featurepolicy.Inputs, store UnifiedPolicyStore) error {
	if r.manager == nil || r.profile != in.ProfileID {
		var durable featurepolicy.Store
		if store.Store != nil && store.ProfileKey != "" && in.ProfileID != "" {
			durable = store
		}
		r.manager = featurepolicy.NewManager(durable)
		r.profile = in.ProfileID
		r.started = false
	}
	if !r.started {
		warning, err := r.manager.Start(in, r.read)
		if err != nil {
			return err
		}
		r.input = in
		r.started = true
		if warning != "" {
			return fmt.Errorf("%s", warning)
		}
		return nil
	}
	if in.PeerIdentityEpoch != r.input.PeerIdentityEpoch || in.AssignedDomainsEpoch != r.input.AssignedDomainsEpoch {
		if err := r.manager.Recompile(in); err != nil {
			return err
		}
		r.input = in
	}
	data, err := r.read()
	if err != nil {
		// Missing configuration remains a quiet default-off installation, but a
		// removed previously accepted file is a degraded state, never a disable.
		if errors.Is(err, fs.ErrNotExist) && !r.manager.Current().Enabled() {
			return nil
		}
		return err
	}
	sum := sha256.Sum256(data)
	return r.manager.Reload(data, r.manager.Current().Fence().Generation, hex.EncodeToString(sum[:]))
}

// signalUnifiedPolicyLocked invalidates access immediately, before a worker can
// perform I/O. Never acquire Manager or appc locks while holding b.mu.
func (b *LocalBackend) signalUnifiedPolicyLocked() {
	b.unifiedRevision++
	select {
	case b.unifiedWake <- struct{}{}:
	default:
	}
}

func (b *LocalBackend) unifiedInputsLocked() (featurepolicy.Inputs, UnifiedPolicyStore, uint64) {
	p := b.pm.CurrentProfile()
	in := featurepolicy.Inputs{ProfileID: string(p.ID()), PeerIdentityEpoch: b.unifiedRevision, AssignedDomainsEpoch: b.unifiedDomainsEpoch, AssignedDomains: slices.Clone(b.unifiedDomains), Peers: b.currentNode().Peers()}
	return in, UnifiedPolicyStore{Store: b.store, ProfileID: in.ProfileID, ProfileKey: p.Key()}, b.unifiedRevision
}

// startUnifiedPolicy starts one backend-lifetime service. goTracker is for
// finite work: callers drain it on Logout while the backend is still alive.
// This service instead has an explicit stop/join contract, used by Shutdown.
func (b *LocalBackend) startUnifiedPolicy(r *unifiedPolicyRuntime) {
	b.mu.Lock()
	b.waitUnifiedPrefsTransactionLocked()
	defer b.mu.Unlock()
	b.startUnifiedPolicyLocked(r)
}

// startUnifiedPolicyLocked is called at Start, after construction and caller
// dependency injection. b.mu also orders the first input capture after Start.
// A nil runtime supports backends constructed directly by upstream tests.
func (b *LocalBackend) startUnifiedPolicyLocked(r *unifiedPolicyRuntime) {
	if r == nil || b.unifiedDone != nil || b.unifiedWorkerStopped || b.shutdownCalled || b.ctx.Err() != nil {
		return
	}
	b.unifiedStop = make(chan struct{})
	b.unifiedDone = make(chan struct{})
	go b.runUnifiedPolicy(r)
}

// stopUnifiedPolicy is terminal and idempotent, including before Start and for
// concurrent callers. Join outside b.mu so an in-flight refresh can finish.
// StateStore and file reads are synchronous APIs: shutdown waits for in-flight
// I/O, never abandons a writer in an untracked helper goroutine.
func (b *LocalBackend) stopUnifiedPolicy() {
	b.mu.Lock()
	b.waitUnifiedPrefsTransactionLocked()
	if !b.unifiedWorkerStopped {
		b.unifiedWorkerStopped = true
		if b.unifiedStop != nil {
			close(b.unifiedStop)
		}
	}
	done := b.unifiedDone
	b.mu.Unlock()
	if done != nil {
		<-done
	}
}

func (b *LocalBackend) unifiedPolicyStopping() bool {
	select {
	case <-b.ctx.Done():
		return true
	case <-b.unifiedStop:
		return true
	default:
		return false
	}
}

func (b *LocalBackend) runUnifiedPolicy(r *unifiedPolicyRuntime) {
	defer close(b.unifiedDone)
	defer b.clearUnifiedActivity()
	for {
		if b.unifiedPolicyStopping() {
			return
		}
		b.mu.Lock()
		b.waitUnifiedPrefsTransactionLocked()
		in, store, rev := b.unifiedInputsLocked()
		b.mu.Unlock()
		err := r.refresh(in, store)
		// Manager locks are never nested under b.mu.
		s := r.manager.Current()
		sourceHash := r.manager.SourceHash()
		handoffPending, handoffErr := store.HandoffPending()
		if handoffErr != nil {
			err = handoffErr
			handoffPending = true
		}
		b.mu.Lock()
		b.waitUnifiedPrefsTransactionLocked()
		if b.unifiedPolicyStopping() {
			b.mu.Unlock()
			return
		}
		if rev == b.unifiedRevision {
			pathApplied := false
			var pathErr error
			if policyMatchesInput(s, in) && b.sys != nil {
				if ms, ok := b.sys.MagicSock.GetOK(); ok && ms != nil {
					// Existing backend -> Conn -> endpoint lock order; no callback into
					// the backend or WG from policy publication. Identity is rebound from
					// magicsock's current control netmap before returning.
					pathErr = ms.SetPathPolicy(s)
					pathApplied = pathErr == nil
				}
			}
			if policyMatchesInput(s, in) {
				b.unifiedSnapshot = s
				if s.OwnershipEnabled() || handoffPending {
					b.unifiedOwnership = true
				}
				b.unifiedPublishedRevision = rev
			} else {
				// A failed recompile must not relabel an old identity/domain snapshot
				// with the new revision, even though its LKG configuration is valid.
				b.unifiedSnapshot = nil
			}
			previousStatus := b.unifiedStatus
			b.unifiedStatus = UnifiedPolicyStatus{Accepted: s.Fence(), SourceSHA256: sourceHash}
			// A same-profile policy publication must not briefly erase the
			// sampled lease health while the unchanged book is reconciled.
			if previousStatus.Accepted.ProfileID == s.Fence().ProfileID && s.Config().Lease.Enabled {
				b.unifiedStatus.LeaseCount = previousStatus.LeaseCount
				b.unifiedStatus.TimeUncertain = previousStatus.TimeUncertain
				b.unifiedStatus.OldestExpiredLeaseSeconds = previousStatus.OldestExpiredLeaseSeconds
			}
			// Rebuild the per-publication view but keep persistent consumer
			// failures. A timer tick is not evidence that a queue/consumer
			// failure cleared; only the matching success paths clear it.
			b.unifiedStatus.Degraded = b.rebuildUnifiedDegradedLocked(pathErr, err)
			c := s.Config()
			// UNVERIFIED consumers are not reported applied merely because compilation
			// succeeded. Later patches advance Applied after their durable barrier.
			if b.unifiedOwnership || !policyMatchesInput(s, in) || s.Enabled() && (c.Lease.Enabled || c.AutoIPv6.Enabled || c.DNSIPv4Only.Enabled || c.PathPolicy.Enabled && !pathApplied) {
				b.unifiedStatus.Reconciling = true
			} else {
				b.unifiedStatus.Applied = s.Fence()
			}
		}
		b.mu.Unlock()
		if s != r.ownerSnapshot {
			if ownerErr := b.reconcileUnifiedOwnerConsumer(r, s); ownerErr != nil {
				b.logf("unified owner consumer: generation=%d revision=%d cause=owner-consumer err=%v", s.Fence().Generation, rev, ownerErr)
				b.mu.Lock()
				b.waitUnifiedPrefsTransactionLocked()
				b.noteUnifiedIssueLocked(unifiedCauseOwner, ownerErr)
				b.unifiedStatus.Reconciling = true
				b.unifiedStatus.Degraded = b.unifiedDegradedFromHealthLocked()
				b.mu.Unlock()
			} else {
				r.ownerSnapshot = s
				b.mu.Lock()
				b.waitUnifiedPrefsTransactionLocked()
				b.clearUnifiedIssueLocked(unifiedCauseOwner, nil)
				b.clearStaleUnifiedDNSIssueLocked(s.Fence())
				b.unifiedStatus.Degraded = b.unifiedDegradedFromHealthLocked()
				b.mu.Unlock()
			}
		}
		delay := time.Duration(r.manager.Current().Config().ReloadSeconds) * time.Second
		// Startup/profile publications may briefly leave the connector or its
		// fence unavailable. Retry an unfinished installation promptly instead
		// of waiting for the (potentially long) configuration reload interval.
		// The next iteration captures fresh inputs and repeats all fence checks.
		if r.ownerSnapshot != s {
			delay = min(delay, time.Second)
		}
		if s.OwnershipEnabled() && s.Config().Lease.Enabled && r.ownerSnapshot == s {
			if sweepErr := b.sweepUnifiedLeases(r, s); sweepErr != nil {
				b.mu.Lock()
				b.waitUnifiedPrefsTransactionLocked()
				b.noteUnifiedIssueLocked(unifiedCauseSweep, sweepErr)
				b.unifiedStatus.Degraded = b.unifiedDegradedFromHealthLocked()
				b.unifiedStatus.Reconciling = true
				b.unifiedStatus.Applied = featurepolicy.Fence{}
				b.mu.Unlock()
			} else {
				b.mu.Lock()
				b.waitUnifiedPrefsTransactionLocked()
				b.clearUnifiedIssueLocked(unifiedCauseSweep, nil)
				if b.unifiedStatus.Degraded != b.unifiedDegradedFromHealthLocked() {
					b.unifiedStatus.Degraded = b.unifiedDegradedFromHealthLocked()
				}
				b.mu.Unlock()
			}
			delay = min(delay, max(time.Millisecond, time.Until(r.nextSweep)))
		}
		if r.connector != nil && r.leaseProfile == s.Fence().ProfileID {
			// Diagnostic samples only; no prefs, owner, fence or lease mutation.
			// Keep status responsive while a prefs transaction persists.
			count, uncertain, age := r.connector.TTLDebugSummary(time.Now())
			b.mu.Lock()
			b.unifiedStatus.LeaseCount = count
			b.unifiedStatus.TimeUncertain = &uncertain
			b.unifiedStatus.OldestExpiredLeaseSeconds = &age
			b.mu.Unlock()
		}
		timer := time.NewTimer(delay)
	waitLoop:
		for {
			select {
			case <-b.unifiedStop:
				timer.Stop()
				return
			case <-b.ctx.Done():
				timer.Stop()
				return
			case call := <-r.dns:
				b.handleUnifiedDNSBatch(r, call)
			case call := <-r.debug:
				if b.handleUnifiedDebug(r, call) {
					timer.Stop()
					break waitLoop
				}
			case <-b.unifiedWake:
				timer.Stop()
				break waitLoop
			case <-timer.C:
				break waitLoop
			}
		}
	}
}

// UnifiedPolicyState is an internal status accessor. A changed control/profile
// input immediately makes the previous generation unavailable for side effects.
func (b *LocalBackend) UnifiedPolicyState() UnifiedPolicyStatus {
	b.mu.Lock()
	b.waitUnifiedPrefsTransactionLocked()
	defer b.mu.Unlock()
	s := b.unifiedStatus
	if b.unifiedPublishedRevision != b.unifiedRevision {
		s.Reconciling = true
		s.Applied = featurepolicy.Fence{}
	}
	return s
}

// unifiedProfileChanged is called under b.mu by profileManager. No store I/O.
func (b *LocalBackend) unifiedProfileChanged(p ipn.LoginProfileView, _ ipn.PrefsView, sameNode bool) {
	if sameNode && b.unifiedProfileID == string(p.ID()) {
		return
	}
	if b.unifiedProfileID != string(p.ID()) {
		b.unifiedOwnership = false
		b.unifiedOwners = nil
		b.unifiedOwnersProfile = ""
	}
	b.unifiedProfileID = string(p.ID())
	if !sameNode {
		b.unifiedControlRoutes = nil
		b.unifiedDomains = nil
		b.unifiedDomainsEpoch++
	}
	b.signalUnifiedPolicyLocked()
}

func policyMatchesInput(s *featurepolicy.PolicySnapshot, in featurepolicy.Inputs) bool {
	f := s.Fence()
	return f.ProfileID == in.ProfileID && f.PeerIdentityEpoch == in.PeerIdentityEpoch && f.AssignedDomainsEpoch == in.AssignedDomainsEpoch
}
