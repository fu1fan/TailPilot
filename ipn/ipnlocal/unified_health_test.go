package ipnlocal

import (
	"fmt"
	"testing"

	"tailscale.com/appc"
	"tailscale.com/featurepolicy"
	"tailscale.com/ipn/store/mem"
)

// A successful publication is not proof that a consumer failure cleared. This
// guards the RCA finding that a timer-driven publish rebuilt unifiedStatus and
// dropped degraded/runtimeReady evidence.
func TestUnifiedDegradedSurvivesLaterPublication(t *testing.T) {
	b := &LocalBackend{}
	f := featurepolicy.Fence{ProfileID: "p", Generation: 3, AssignedDomainsEpoch: 1, PeerIdentityEpoch: 4}
	issue := fmt.Errorf("wrap: %w", &appc.TTLTransitionError{Phase: appc.TTLCommitPrewrite, Action: "dns", Fence: f, Revision: 2, Epoch: 6, Err: fmt.Errorf("%w: stale backend fence", appc.ErrTTLCommitNotStarted)})
	b.mu.Lock()
	b.noteUnifiedIssueLocked(unifiedCauseDNSQueue, issue)
	b.unifiedStatus.Degraded = b.unifiedDegradedFromHealthLocked()
	b.mu.Unlock()
	if b.unifiedStatus.Degraded == "" {
		t.Fatal("dns failure not recorded")
	}
	// Simulate the next periodic publication with no fresh error.
	b.mu.Lock()
	got := b.rebuildUnifiedDegradedLocked(nil, nil)
	b.mu.Unlock()
	if got == "" {
		t.Fatal("degraded was cleared by a later publication")
	}
	// A success at the same consumer fence retires it.
	b.mu.Lock()
	b.clearUnifiedIssueLocked(unifiedCauseDNSQueue, &f)
	got = b.rebuildUnifiedDegradedLocked(nil, nil)
	b.mu.Unlock()
	if got != "" {
		t.Fatalf("degraded retained after matching success: %q", got)
	}
}

// runtimeReady must reflect consumer installation, not only a cleared
// per-publication error string.
func TestUnifiedRuntimeReadyRequiresConsumerFence(t *testing.T) {
	m := featurepolicy.NewManager(UnifiedPolicyStore{Store: new(mem.Store), ProfileID: "p", ProfileKey: "profile-p"})
	if _, err := m.Start(featurepolicy.Inputs{ProfileID: "p"}, func() ([]byte, error) {
		return []byte(`{"schema_version":2,"enabled":true}`), nil
	}); err != nil {
		t.Fatal(err)
	}
	snap := m.Current()
	if snap.Fence().Generation == 0 {
		t.Fatal("fixture fence is zero")
	}
	b := &LocalBackend{
		unifiedSnapshot:          snap,
		unifiedRevision:          1,
		unifiedPublishedRevision: 1,
		unifiedConsumerFence:     snap.Fence(),
		unifiedStatus:            UnifiedPolicyStatus{Accepted: snap.Fence()},
	}
	if out := b.UnifiedPolicyDebugStatus(); !out.RuntimeReady || !out.ConsumerReady {
		t.Fatalf("ready consumer rejected: %+v", out)
	}
	b.unifiedConsumerFence = featurepolicy.Fence{}
	if out := b.UnifiedPolicyDebugStatus(); out.RuntimeReady || out.ConsumerReady {
		t.Fatalf("missing consumer fence reported ready: %+v", out)
	}
	b.unifiedConsumerFence = snap.Fence()
	b.unifiedTTLBlocked = true
	if out := b.UnifiedPolicyDebugStatus(); out.RuntimeReady || !out.TTLBlocked {
		t.Fatalf("blocked TTL reported ready: %+v", out)
	}
}
