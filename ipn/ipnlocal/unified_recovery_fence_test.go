package ipnlocal

import (
	"errors"
	"testing"
	"time"

	"tailscale.com/appc"
	"tailscale.com/ipn"
)

// A real prefs publication can invalidate the snapshot while replay completes.
// Previously InstallTTLTakeover published a permanently blocked TTL consumer
// under that stale fence, so later lifecycle retries reported already installed.
func TestConnectorRecoveryDefersInstallAfterInputChange(t *testing.T) {
	b, r, st := newConnectorDaemon(t, 0)
	mustTakeover(t, r.connector.ObserveDNSResponse(takeoverWire(t, "www.example.test", [4]byte{192, 0, 2, 7})))
	_, req := daemonPreview(t, b, r, "appc-route-reset", UnifiedDebugRequest{Source: "recovery-fence"})
	st.after = true
	st.nth.Store(st.calls.Load() + 1)
	if _, err := b.connectorAction(r, "appc-route-reset", req); err == nil {
		t.Fatal("missing cut")
	}
	st.nth.Store(0)
	b.unifiedTTLBlocked = false
	b.appConnector.Close()
	b.appConnector = appc.NewAppConnector(appc.Config{SourceID: 100, Logf: t.Logf, EventBus: b.sys.Bus.Get()})
	t.Cleanup(b.appConnector.Close)
	r.connector = nil
	r.connectorAdapter = nil
	r.ownerSnapshot = nil
	b.pm.StateChangeHook = func(ipn.LoginProfileView, ipn.PrefsView, bool) { b.signalUnifiedPolicyLocked() }
	if err := b.reconcileUnifiedOwnerConsumer(r, r.manager.Current()); err == nil {
		t.Fatal("stale install accepted")
	}
	if _, err := b.appConnector.TTLState(); err == nil {
		t.Fatal("stale recovery poisoned TTL installation")
	}
	saved, err := readConnectorIntent(st, "profile-p")
	mustTakeover(t, err)
	if !saved.Complete {
		t.Fatal("replay did not complete")
	}
	b.pm.StateChangeHook = nil
	b.mu.Lock()
	in, _, rev := b.unifiedInputsLocked()
	b.mu.Unlock()
	mustTakeover(t, r.manager.Recompile(in))
	b.unifiedSnapshot = r.manager.Current()
	b.unifiedPublishedRevision = rev
	mustTakeover(t, b.reconcileUnifiedOwnerConsumer(r, r.manager.Current()))
	if b.Prefs().AdvertiseRoutes().Len() != 0 {
		t.Fatal("reset routes resurrected")
	}
	if _, err := b.appConnector.TTLState(); err != nil {
		t.Fatal(err)
	}
}

func TestConnectorStaleFenceDoesNotStartPersistence(t *testing.T) {
	b, r, st := newConnectorDaemon(t, 0)
	fence := r.manager.Current().Fence()
	calls := st.calls.Load()
	b.mu.Lock()
	b.signalUnifiedPolicyLocked()
	b.mu.Unlock()
	if _, err := b.connectorTransaction(fence, nil); !errors.Is(err, appc.ErrTTLCommitNotStarted) {
		t.Fatalf("missing prewrite rejection: %v", err)
	}
	if st.calls.Load() != calls {
		t.Fatal("prewrite rejection performed persistence")
	}
}

// TestConnectorPrewriteFenceRecoversWithNewFence is RCA section 6.B with a
// deterministic barrier: a captured DNS request passes the queue snapshot check,
// then a policy signal invalidates the published revision before the backend
// commit. That is a real prewrite stale rejection: it must not persist anything,
// must not quarantine the lifecycle, and a newer published fence must converge
// without a daemon restart.
func TestConnectorPrewriteFenceRecoversWithNewFence(t *testing.T) {
	b, r, st := newConnectorDaemon(t, 0)
	manager := r.manager
	oldObserver := r.connector.CaptureDNSObserver()
	oldFence := manager.Current().Fence()
	entered, release := make(chan struct{}), make(chan struct{})
	reply := make(chan error, 1)
	calls := st.calls.Load()
	// queueOnly avoids waiting on the LocalRouteWaitMS deadline; the barrier
	// replaces the real capture->consume race with a scheduled one.
	go func() {
		b.handleUnifiedDNS(r, unifiedDNSCall{ctx: t.Context(), fence: oldFence, queueOnly: true, reply: reply, observe: func() error {
			close(entered)
			<-release
			return oldObserver(takeoverWire(t, "www.example.test", [4]byte{192, 0, 2, 9}))
		}})
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("barrier not reached")
	}
	b.mu.Lock()
	b.signalUnifiedPolicyLocked() // published revision now lags; no new snapshot yet
	b.mu.Unlock()
	close(release)
	select {
	case err := <-reply:
		if !errors.Is(err, appc.ErrTTLCommitNotStarted) {
			t.Fatalf("want real prewrite rejection, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("DNS commit did not finish")
	}
	if st.calls.Load() != calls {
		t.Fatal("prewrite rejection persisted state")
	}
	b.mu.Lock()
	blocked := b.unifiedTTLBlocked
	b.mu.Unlock()
	if blocked {
		t.Fatal("prewrite rejection quarantined the backend")
	}
	if _, err := b.appConnector.TTLState(); err != nil {
		t.Fatalf("prewrite rejection poisoned appc consumer: %v", err)
	}
	if diag := b.appConnector.TTLDiagnostics(); diag.Blocked || diag.PrewriteRejects == 0 {
		t.Fatalf("prewrite diagnostics missing: %+v", diag)
	}

	// Publish F2 exactly as the lifecycle worker would after the signal.
	b.mu.Lock()
	in, _, rev := b.unifiedInputsLocked()
	b.mu.Unlock()
	mustTakeover(t, manager.Recompile(in))
	b.mu.Lock()
	b.unifiedSnapshot = manager.Current()
	b.unifiedPublishedRevision = rev
	b.mu.Unlock()
	mustTakeover(t, b.reconcileUnifiedOwnerConsumer(r, manager.Current()))
	r.ownerSnapshot = manager.Current()
	if b.appConnector.TTLBlocked() {
		t.Fatal("lifecycle still blocked after new fence")
	}
	newFence := manager.Current().Fence()
	if newFence == oldFence {
		t.Fatal("fence did not advance")
	}
	if diag := b.appConnector.TTLDiagnostics(); diag.CommittedFence != newFence {
		t.Fatalf("consumer did not converge to new fence: %+v", diag)
	}
	// Old captured request stays failed and cannot inject stale DNS evidence.
	if err := oldObserver(takeoverWire(t, "www.example.test", [4]byte{192, 0, 2, 9})); err == nil {
		t.Fatal("old observer committed after recovery")
	}
	newObserver := b.appConnector.CaptureDNSObserver()
	if err := newObserver(takeoverWire(t, "www.example.test", [4]byte{192, 0, 2, 9})); err != nil {
		t.Fatalf("new observer failed: %v", err)
	}

	// Revoking the assigned root must reject a request captured under the now
	// previous fence even though its lease epoch was valid when captured.
	revokedObserver := b.appConnector.CaptureDNSObserver()
	b.mu.Lock()
	b.unifiedDomains = nil
	b.unifiedDomainsEpoch++
	in2, _, rev2 := b.unifiedInputsLocked()
	b.mu.Unlock()
	mustTakeover(t, manager.Recompile(in2))
	b.mu.Lock()
	b.unifiedSnapshot = manager.Current()
	b.unifiedPublishedRevision = rev2
	b.mu.Unlock()
	mustTakeover(t, b.reconcileUnifiedOwnerConsumer(r, manager.Current()))
	r.ownerSnapshot = manager.Current()
	if err := revokedObserver(takeoverWire(t, "www.example.test", [4]byte{192, 0, 2, 9})); err == nil {
		t.Fatal("revoked-domain observer committed")
	}
	state, err := b.appConnector.TTLState()
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Roots) != 0 {
		t.Fatalf("revoked roots retained: %v", state.Roots)
	}
}
