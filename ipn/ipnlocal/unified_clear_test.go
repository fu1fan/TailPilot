package ipnlocal

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"tailscale.com/appc"
	"tailscale.com/featurepolicy"
	"tailscale.com/ipn"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/types/appctype"
	"testing"
	"time"
)

type clearFaultStore struct {
	mem.Store
	nth, calls int
	after      bool
}

func (s *clearFaultStore) WriteState(k ipn.StateKey, data []byte) error {
	s.calls++
	if s.calls == s.nth && !s.after {
		return errors.New("power before")
	}
	if err := s.Store.WriteState(k, data); err != nil {
		return err
	}
	if s.calls == s.nth {
		return errors.New("power after")
	}
	return nil
}
func TestUnifiedClearPowerCuts(t *testing.T) {
	for n := 1; n <= 6; n++ {
		for _, after := range []bool{false, true} {
			t.Run(fmt.Sprintf("write-%d-after-%v", n, after), func(t *testing.T) {
				st := new(clearFaultStore)
				key := ipn.StateKey("p")
				auto, shared, unknown, external := prefix("192.0.2.1/32"), prefix("192.0.2.2/32"), prefix("192.0.2.3/32"), prefix("192.0.2.4/32")
				fixture := new(ledgerFixture)
				ledger := newLedgerTest(t, fixture)
				f := ledger.fence
				for i, event := range []appctype.RouteOwnerEvent{
					{Source: appctype.RouteOwnerAuto, OwnerID: "leases", Prefixes: []netip.Prefix{auto, shared, unknown}},
					{Source: appctype.RouteOwnerManual, Prefixes: []netip.Prefix{shared}},
				} {
					event.Fence = f
					event.Sequence = uint64(i + 1)
					if err := ledger.Update(event); err != nil {
						t.Fatal(err)
					}
				}
				state := cloneLedger(ledger.state)
				o := state.Owners[unknown]
				o.LegacyUnknown = true
				state.Owners[unknown] = o
				before := slices.Clone(state.Desired)
				o = state.Owners[auto]
				o.Auto = nil
				state.Owners[auto] = o
				state.Sequence++
				state.Pending = true
				state.Before = before
				state.Desired = desiredRoutes(state, before)
				payload, _ := json.Marshal(state)
				ledgerBytes, _ := json.Marshal(ledgerEnvelope{payload, sha256.Sum256(payload)})
				book := appc.NewLeaseBook(f, appc.LeaseOptions{MaxEntries: 10}, time.Now)
				leaseBytes, _ := book.MarshalState()
				intent := unifiedClearIntent{Schema: 1, Fence: f, PreviewHash: "bound-preview", Source: "test-lead", StartedAt: time.Now(), Leases: leaseBytes, Ledger: ledgerBytes}
				raw, _ := json.Marshal(before)
				if err := st.WriteState(key, raw); err != nil {
					t.Fatal(err)
				}
				adapter := UnifiedLedgerStore{Store: st, ProfileKey: key, ReadPrefs: func() ([]netip.Prefix, error) {
					raw, err := st.ReadState(key)
					if err != nil {
						return nil, err
					}
					var p []netip.Prefix
					err = json.Unmarshal(raw, &p)
					return p, err
				}, ApplyPrefs: func(before, desired []netip.Prefix) error {
					raw, _ := json.Marshal(desired)
					return ipn.WriteState(st, key, raw)
				}}
				st.calls = 0
				st.nth = n
				st.after = after
				err := writeClearIntent(st, key, intent)
				if err == nil {
					err = applyClearIntent(st, key, intent, adapter)
				}
				if err == nil {
					t.Fatal("power cut acknowledged")
				}
				st.nth = 0
				saved, err := readClearIntent(st, key)
				if err != nil {
					t.Fatal(err)
				}
				if saved.Schema == 0 { // first intent did not commit: no authority changed.
					if n != 1 || after {
						t.Fatal("lost intent")
					}
					return
				}
				// Unexplained concurrent additions survive recovery; this does not claim
				// that an out-of-process same-prefix manual assertion is distinguishable.
				current, _ := adapter.Current()
				current = append(current, external)
				raw, _ = json.Marshal(current)
				st.WriteState(key, raw)
				if err := applyClearIntent(st, key, saved, adapter); err != nil {
					t.Fatal(err)
				}
				current, _ = adapter.Current()
				if slices.Contains(current, auto) || !slices.Contains(current, shared) || !slices.Contains(current, unknown) || !slices.Contains(current, external) {
					t.Fatal("unsafe recovery", current)
				}
				saved, err = readClearIntent(st, key)
				if err != nil || !saved.Complete {
					t.Fatal("no completed audit", err)
				}
				if err := applyClearIntent(st, key, saved, adapter); err != nil {
					t.Fatal(err)
				}
				raw, err = (UnifiedLeaseStore{st, key}).Load()
				if err != nil || !slices.Equal(raw, leaseBytes) {
					t.Fatal("lease evidence not cleared", err)
				}
				// Cold controller recovery must not recreate withdrawn evidence. Use
				// the persisted sidecar, not the old in-memory book, on every boot.
				for range 3 {
					controller, err := appc.NewLeaseController(f, appc.LeaseOptions{MaxEntries: 10}, time.Now, UnifiedLeaseStore{st, key}, func(_ featurepolicy.Fence, leases []appc.Lease) error {
						if len(leases) != 0 {
							t.Fatal("cleared evidence resurrected")
						}
						return nil
					})
					if err != nil {
						t.Fatal(err)
					}
					if err := controller.ReconcileAt(f); err != nil {
						t.Fatal(err)
					}
					if len(controller.Snapshot()) != 0 {
						t.Fatal("cold snapshot not empty")
					}
				}

			})
		}
	}
}
