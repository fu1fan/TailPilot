package ipnlocal

import (
	"context"
	"io/fs"
	"sync"
	"sync/atomic"
	"tailscale.com/featurepolicy"
	"tailscale.com/ipn"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/tailcfg"
	"testing"
	"time"
)

func TestUnifiedPolicyRuntime(t *testing.T) {
	r := newUnifiedPolicyRuntime(func() ([]byte, error) { return nil, fs.ErrNotExist })
	in := featurepolicy.Inputs{ProfileID: "a", PeerIdentityEpoch: 1}
	store := UnifiedPolicyStore{Store: new(mem.Store), ProfileID: "a", ProfileKey: ipn.StateKey("profile-a")}
	if err := r.refresh(in, store); err != nil {
		t.Fatal(err)
	}
	if r.manager.Current().Enabled() {
		t.Fatal("missing file enabled policy")
	}
	r.read = func() ([]byte, error) { return []byte(`{"schema_version":1,"enabled":true}`), nil }
	if err := r.refresh(in, store); err != nil {
		t.Fatal(err)
	}
	if !r.manager.Current().Enabled() {
		t.Fatal("reload not applied")
	}
	r.read = func() ([]byte, error) { return []byte(`bad`), nil }
	old := r.manager.Current().Fence()
	if err := r.refresh(in, store); err == nil {
		t.Fatal("invalid reload accepted")
	}
	if r.manager.Current().Fence() != old {
		t.Fatal("invalid reload changed generation")
	}
	in.ProfileID = "b"
	if err := r.refresh(in, UnifiedPolicyStore{Store: store.Store, ProfileID: "b", ProfileKey: "profile-b"}); err == nil {
		t.Fatal("invalid first file accepted")
	}
	if r.manager.Current().Enabled() {
		t.Fatal("old profile policy leaked")
	}
}

func TestUnifiedPolicyInvalidation(t *testing.T) {
	b := &LocalBackend{unifiedWake: make(chan struct{}, 1), unifiedRevision: 4, unifiedPublishedRevision: 4, unifiedStatus: UnifiedPolicyStatus{Applied: featurepolicy.Fence{Generation: 9}}}
	b.mu.Lock()
	b.signalUnifiedPolicyLocked()
	b.signalUnifiedPolicyLocked()
	b.mu.Unlock()
	s := b.UnifiedPolicyState()
	if !s.Reconciling || s.Applied.Generation != 0 {
		t.Fatal("stale generation accessible", s)
	}
	if len(b.unifiedWake) != 1 {
		t.Fatal("notifications not coalesced")
	}
}

func TestUnifiedPolicyFailedRecompileFence(t *testing.T) {
	r := newUnifiedPolicyRuntime(func() ([]byte, error) { return []byte(`{"schema_version":1}`), nil })
	in := featurepolicy.Inputs{ProfileID: "p", PeerIdentityEpoch: 1}
	if err := r.refresh(in, UnifiedPolicyStore{Store: new(mem.Store), ProfileID: "p", ProfileKey: "profile-p"}); err != nil {
		t.Fatal(err)
	}
	in.PeerIdentityEpoch++
	if policyMatchesInput(r.manager.Current(), in) {
		t.Fatal("old epoch relabeled current")
	}
}

func TestUnifiedPolicyFallbackReportsDegraded(t *testing.T) {
	store := UnifiedPolicyStore{Store: new(mem.Store), ProfileID: "p", ProfileKey: "profile-p"}
	in := featurepolicy.Inputs{ProfileID: "p"}
	r := newUnifiedPolicyRuntime(func() ([]byte, error) { return []byte(`{"schema_version":1,"enabled":true}`), nil })
	if err := r.refresh(in, store); err != nil {
		t.Fatal(err)
	}
	restored := newUnifiedPolicyRuntime(func() ([]byte, error) { return []byte(`broken`), nil })
	if err := restored.refresh(in, store); err == nil {
		t.Fatal("LKG fallback warning lost")
	}
	if !restored.started || !restored.manager.Current().Enabled() {
		t.Fatal("valid LKG not installed")
	}
}

func TestUnifiedPolicyAbsentOnRestart(t *testing.T) {
	store := UnifiedPolicyStore{Store: new(mem.Store), ProfileID: "p", ProfileKey: "profile-p"}
	in := featurepolicy.Inputs{ProfileID: "p"}
	for range 2 {
		r := newUnifiedPolicyRuntime(func() ([]byte, error) { return nil, fs.ErrNotExist })
		if err := r.refresh(in, store); err != nil {
			t.Fatal("optional absent file degraded", err)
		}
	}
}

// No fake engine or sockets: this exercises the actual backend worker and the
// exact stop/join used by LocalBackend.Shutdown.
func TestUnifiedPolicyWorkerShutdown(t *testing.T) {
	for _, mode := range []string{"stop", "context", "stop-before-start"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			b := &LocalBackend{ctx: ctx, unifiedWake: make(chan struct{}, 1), pm: &profileManager{
				currentProfile: (&ipn.LoginProfile{}).View(), prefs: ipn.NewPrefs().View(),
			}}
			b.currentNodeAtomic.Store(&nodeBackend{})
			entered, release := make(chan struct{}), make(chan struct{})
			var reads atomic.Int32
			r := newUnifiedPolicyRuntime(func() ([]byte, error) {
				if reads.Add(1) == 1 {
					close(entered)
					<-release
				}
				return nil, fs.ErrNotExist
			})
			if mode == "stop-before-start" {
				b.stopUnifiedPolicy()
				b.startUnifiedPolicy(r)
				if b.unifiedDone != nil || reads.Load() != 0 {
					t.Fatal("started after terminal stop")
				}
				return
			}
			b.startUnifiedPolicy(r)
			b.startUnifiedPolicy(r)
			select {
			case <-entered:
			case <-time.After(2 * time.Second):
				t.Fatal("worker did not start")
			}
			// This is the StateMachine Logout contract, before backend Shutdown.
			b.goTracker.Go(func() {})
			b.awaitNoGoroutinesInTest()
			if mode == "context" {
				cancel()
				close(release)
				select {
				case <-b.unifiedDone:
				case <-time.After(2 * time.Second):
					t.Fatal("context did not stop worker")
				}
				b.stopUnifiedPolicy()
				return
			}
			joined := make(chan struct{})
			go func() { b.stopUnifiedPolicy(); close(joined) }()
			// Synchronize with stop closure, not a timing assumption.
			select {
			case <-b.unifiedStop:
			case <-time.After(2 * time.Second):
				t.Fatal("stop not closed")
			}
			select {
			case <-joined:
				t.Fatal("returned while I/O still running")
			default:
			}
			close(release)
			select {
			case <-joined:
			case <-time.After(2 * time.Second):
				t.Fatal("worker leaked")
			}
			b.stopUnifiedPolicy()
			b.startUnifiedPolicy(r)
			if reads.Load() != 1 {
				t.Fatal("duplicate/restarted worker", reads.Load())
			}
			select {
			case <-b.unifiedDone:
			default:
				t.Fatal("done not closed")
			}
			if b.unifiedSnapshot != nil {
				t.Fatal("published after shutdown began")
			}
			if n := b.goTracker.RunningGoroutines(); n != 0 {
				t.Fatal("finite work leaked", n)
			}
		})
	}
}

// Exercise the Start boundary without opening engine sockets. Dependency
// replacement is deliberately unlocked, as in newTestBackend. Starting the
// service before this boundary would race the input capture with these writes.
func TestUnifiedPolicyDeferredStart(t *testing.T) {
	b := &LocalBackend{ctx: t.Context(), unifiedWake: make(chan struct{}, 1)}
	b.currentNodeAtomic.Store(&nodeBackend{})
	read := make(chan struct{}, 1)
	b.unifiedRuntime = newUnifiedPolicyRuntime(func() ([]byte, error) {
		read <- struct{}{}
		return nil, fs.ErrNotExist
	})
	for range 100 {
		b.store = new(mem.Store)
		b.pm = &profileManager{currentProfile: (&ipn.LoginProfile{}).View(), prefs: ipn.NewPrefs().View()}
	}
	if b.unifiedDone != nil {
		t.Fatal("worker started before lifecycle boundary")
	}
	b.mu.Lock()
	b.startUnifiedPolicyLocked(b.unifiedRuntime)
	b.startUnifiedPolicyLocked(b.unifiedRuntime)
	b.mu.Unlock()
	t.Cleanup(b.stopUnifiedPolicy)
	select {
	case <-read:
	case <-time.After(2 * time.Second):
		t.Fatal("worker did not start at lifecycle boundary")
	}
	var stops sync.WaitGroup
	for range 8 {
		stops.Go(b.stopUnifiedPolicy)
	}
	stops.Wait()
	if b.unifiedDone == nil {
		t.Fatal("worker never started")
	}
	select {
	case <-b.unifiedDone:
	default:
		t.Fatal("concurrent stop did not join")
	}
}

// Run by Lead with socket access. In addition to the no-engine race tests,
// guard the actual constructor/helper contract responsible for the R3 races.
func TestUnifiedBackendConstructorDefersPolicy(t *testing.T) {
	b := newTestBackend(t)
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.unifiedDone != nil || b.unifiedRuntime == nil {
		t.Fatal("constructor must prepare, but not start, policy worker")
	}
}

func TestUnifiedPolicyDisabledAppConnectorIdempotent(t *testing.T) {
	b := &LocalBackend{unifiedDomains: []string{"example.test"}, unifiedWake: make(chan struct{}, 1)}
	prefs := ipn.NewPrefs().View()
	b.reconfigAppConnectorLocked(tailcfg.NodeView{}, prefs)
	revision, epoch := b.unifiedRevision, b.unifiedDomainsEpoch
	if revision == 0 || epoch == 0 {
		t.Fatal("disable did not invalidate previous domains")
	}
	for range 3 {
		b.reconfigAppConnectorLocked(tailcfg.NodeView{}, prefs)
	}
	if b.unifiedRevision != revision || b.unifiedDomainsEpoch != epoch {
		t.Fatal("disabled reconciliation invalidates its own fence")
	}
}

// Exercise the same writer/input-reader pair as the Backfill regression without
// requiring engine sockets. Both callers must honor the locked-helper contract.
func TestUnifiedPolicyInputLockContract(t *testing.T) {
	b := &LocalBackend{unifiedWake: make(chan struct{}, 1), pm: &profileManager{
		currentProfile: (&ipn.LoginProfile{}).View(), prefs: ipn.NewPrefs().View(),
	}}
	b.currentNodeAtomic.Store(&nodeBackend{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 1000 {
			b.mu.Lock()
			b.unifiedDomains = []string{"example.test"}
			b.reconfigAppConnectorLocked(tailcfg.NodeView{}, b.pm.prefs)
			b.mu.Unlock()
		}
	}()
	for range 1000 {
		b.mu.Lock()
		in, _, revision := b.unifiedInputsLocked()
		b.mu.Unlock()
		if in.PeerIdentityEpoch != revision {
			t.Error("input capture not coherent")
		}
	}
	<-done
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.unifiedRevision != 1000 {
		t.Fatalf("missed invalidations: %d", b.unifiedRevision)
	}
}
