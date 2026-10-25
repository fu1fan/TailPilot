package appc

import (
	"errors"
	"fmt"
	"tailscale.com/featurepolicy"
	"testing"
)

func TestTTLInstallRetryOnlyBeforePersistence(t *testing.T) {
	for _, prewrite := range []bool{true, false} {
		t.Run(fmt.Sprint(prewrite), func(t *testing.T) {
			ac := &AppConnector{sourceID: 99, logf: t.Logf}
			calls := 0
			cfg := ConnectorTTLConfig{Fence: featurepolicy.Fence{ProfileID: "p", Generation: 1}, Roots: []string{"*.example.com"}, Options: LeaseOptions{MaxEntries: 100}, Commit: func(ConnectorTTLTransition) error {
				calls++
				if calls == 1 {
					if prewrite {
						return fmt.Errorf("fence: %w", ErrTTLCommitNotStarted)
					}
					return errors.New("uncertain persistence failure")
				}
				return nil
			}}
			if ac.InstallTTLTakeover(cfg) == nil {
				t.Fatal("first install succeeded")
			}
			late := ac.CaptureDNSObserver()
			if ac.ObserveDNSResponse(ttlWire(t, "www.example.com", 30)) == nil {
				t.Fatal("failed install allowed DNS")
			}
			if calls != 1 {
				t.Fatal("DNS committed while installation incomplete")
			}
			cfg.Fence.Generation++
			err := ac.InstallTTLTakeover(cfg)
			if !prewrite {
				if err == nil || calls != 1 {
					t.Fatal("uncertain write bypassed quarantine")
				}
				return
			}
			mustTTL(t, err)
			if late(ttlWire(t, "www.example.com", 30)) == nil {
				t.Fatal("old observer survived replacement")
			}
			mustTTL(t, ac.ObserveDNSResponse(ttlWire(t, "www.example.com", 30)))
			if ac.InstallTTLTakeover(cfg) == nil {
				t.Fatal("successful consumer replaced")
			}
		})
	}
}

// TestTTLInstalledConsumerPrewriteStaleConverges is RCA section 6.A: after a
// consumer is durably installed, one prewrite stale rejection must not poison
// the lifecycle. A fresh ConfigureTTL fence has to converge, the old captured
// observer must keep failing, and no route may be persisted by the rejected
// attempt.
func TestTTLInstalledConsumerPrewriteStaleConverges(t *testing.T) {
	ac, backend, _, f1 := ttlFixture(t, nil)
	commits, attempts := backend.commits, backend.attempts
	backend.prewrite = true
	err := ac.ObserveDNSResponse(ttlWire(t, "www.example.com", 30))
	if !errors.Is(err, ErrTTLCommitNotStarted) {
		t.Fatalf("want retryable prewrite rejection, got %v", err)
	}
	if backend.commits != commits || backend.attempts != attempts+1 {
		t.Fatalf("prewrite rejection changed durable state: commits=%d attempts=%d", backend.commits, backend.attempts)
	}
	state, err := ac.TTLState()
	if err != nil {
		t.Fatalf("prewrite rejection permanently blocked consumer: %v", err)
	}
	if state.Fence != f1 {
		t.Fatalf("committed state advanced on prewrite reject: %+v", state.Fence)
	}
	if ac.TTLBlocked() {
		t.Fatal("prewrite rejection set the quarantine flag")
	}
	diag := ac.TTLDiagnostics()
	if !diag.Installed || diag.Blocked || diag.PrewriteRejects == 0 || diag.LastPrewrite == nil || diag.LastPrewrite.Phase != TTLCommitPrewrite {
		t.Fatalf("diagnostics lost prewrite classification: %+v", diag)
	}
	// A repeated request under the same stale fence keeps failing without
	// writing; the consumer still owns the old committed state.
	if err := ac.ObserveDNSResponse(ttlWire(t, "www.example.com", 30)); err == nil {
		t.Fatal("repeat request under stale fence succeeded")
	}
	oldObserver := ac.CaptureDNSObserver()

	f2 := f1
	f2.Generation++
	f2.PeerIdentityEpoch++
	backend.prewrite = false
	if err := ac.ConfigureTTL(f2, []string{"*.example.com"}, nil); err != nil {
		t.Fatalf("fresh fence did not converge: %v", err)
	}
	if ac.TTLBlocked() {
		t.Fatal("converged consumer still quarantined")
	}
	if diag2 := ac.TTLDiagnostics(); diag2.Blocked || diag2.CommittedFence != f2 {
		t.Fatalf("consumer did not advance to new fence: %+v", diag2)
	}
	if oldObserver(ttlWire(t, "www.example.com", 30)) == nil {
		t.Fatal("old captured observer survived reconfigure")
	}
	if err := ac.ObserveDNSResponse(ttlWire(t, "www.example.com", 30)); err != nil {
		t.Fatalf("new observer failed: %v", err)
	}
	if !hasTTLRoute(backend) {
		t.Fatal("new fence did not commit learning")
	}
	if diag3 := ac.TTLDiagnostics(); diag3.Blocked || diag3.LastPrewrite == nil {
		t.Fatalf("diagnostics changed after recovery: %+v", diag3)
	}
}

// TestTTLInstalledConsumerUncertainStaysQuarantined proves the other side of
// the distinction: an error that may have written must keep the lifecycle
// quarantined and a new fence must not silently resume DNS observation.
func TestTTLInstalledConsumerUncertainStaysQuarantined(t *testing.T) {
	ac, backend, _, f1 := ttlFixture(t, nil)
	backend.uncertain = true
	if err := ac.ObserveDNSResponse(ttlWire(t, "www.example.com", 30)); err == nil {
		t.Fatal("uncertain failure acknowledged")
	}
	backend.uncertain = false
	if !ac.TTLBlocked() {
		t.Fatal("uncertain write did not quarantine")
	}
	if _, err := ac.TTLState(); err == nil {
		t.Fatal("quarantined consumer reported committed state")
	}
	if diag := ac.TTLDiagnostics(); !diag.Blocked || diag.BlockedCause != string(TTLCommitUncertain) || diag.BlockedAction != "dns" {
		t.Fatalf("quarantine diagnostics missing: %+v", diag)
	}
	f2 := f1
	f2.Generation++
	if err := ac.ConfigureTTL(f2, []string{"*.example.com"}, nil); err == nil {
		t.Fatal("new fence bypassed quarantine")
	}
	if err := ac.ObserveDNSResponse(ttlWire(t, "www.example.com", 30)); err == nil {
		t.Fatal("DNS observed through quarantined consumer")
	}
}
