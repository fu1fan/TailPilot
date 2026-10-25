package ipnlocal

import (
	"errors"
	"tailscale.com/featurepolicy"
	"tailscale.com/ipn"
	"tailscale.com/ipn/store/mem"
	"testing"
)

type handoffFailStore struct {
	mem.Store
	fail  ipn.StateKey
	after bool
}

func (s *handoffFailStore) WriteState(k ipn.StateKey, b []byte) error {
	if k == s.fail && !s.after {
		return errors.New("power loss before write")
	}
	if err := s.Store.WriteState(k, b); err != nil {
		return err
	}
	if k == s.fail {
		return errors.New("power loss after write")
	}
	return nil
}
func TestUnifiedHandoffAcceptancePowerCuts(t *testing.T) {
	for _, key := range []ipn.StateKey{"profile-p||_unifiedHandoffV1", "profile-p||_unifiedPolicyV1"} {
		for _, after := range []bool{false, true} {
			t.Run(string(key)+map[bool]string{false: "/before", true: "/after"}[after], func(t *testing.T) {
				st := new(handoffFailStore)
				store := UnifiedPolicyStore{Store: st, ProfileID: "p", ProfileKey: "profile-p"}
				m := featurepolicy.NewManager(store)
				if _, err := m.Start(featurepolicy.Inputs{ProfileID: "p"}, func() ([]byte, error) {
					return []byte(`{"schema_version":1,"enabled":true,"lease":{"enabled":true}}`), nil
				}); err != nil {
					t.Fatal(err)
				}
				st.fail, st.after = key, after
				disabled := []byte(`{"schema_version":1}`)
				inspect := featurepolicy.Inspect(disabled, nil, nil)
				if err := m.Reload(disabled, m.Current().Fence().Generation, inspect.RequestedSHA256); err == nil {
					t.Fatal("failure acknowledged")
				}
				if !m.Current().OwnershipEnabled() {
					t.Fatal("failed write published")
				}
				st.fail = ""
				raw, err := store.Load("p")
				if err != nil {
					t.Fatal(err)
				}
				_ = raw
				pending, err := store.HandoffPending()
				if err != nil {
					t.Fatal(err)
				}
				// Only a failure before the first marker may leave no intent. Every
				// accepted disabled LKG has the intent, including write-then-error stores.
				if pending != (key != "profile-p||_unifiedHandoffV1" || after) {
					t.Fatalf("pending=%v", pending)
				}
				restarted := featurepolicy.NewManager(store)
				if _, err := restarted.Start(featurepolicy.Inputs{ProfileID: "p"}, func() ([]byte, error) { return disabled, nil }); err != nil {
					t.Fatal(err)
				}
				if pending, err := store.HandoffPending(); err != nil || !pending {
					t.Fatal("restart lost handoff", pending, err)
				}
			})
		}
	}
}

func TestUnifiedHandoffStartupGatesLegacy(t *testing.T) {
	b := &LocalBackend{logf: t.Logf}
	store, _ := prepareUnifiedTransactionTest(t, b, false)
	store.block.Store(false)
	if err := store.WriteState("profile-p||_routeInfo", []byte(`{"Domains":{"stale.test":["192.0.2.1"]}}`)); err != nil {
		t.Fatal(err)
	}
	if err := store.WriteState("profile-p||_unifiedHandoffV1", []byte("pending")); err != nil {
		t.Fatal(err)
	}
	b.unifiedOwnership = false
	b.unifiedSnapshot = nil
	b.mu.Lock()
	ri, err := b.readRouteInfoLocked()
	b.mu.Unlock()
	if err != nil || !b.unifiedOwnership || len(ri.Domains) != 0 {
		t.Fatal("cold startup released legacy writer", ri, err)
	}
}
