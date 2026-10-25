package ipnlocal

import (
	"errors"
	"io/fs"
	"tailscale.com/ipn"
	"tailscale.com/ipn/store/mem"
	"testing"
)

func TestUnifiedStoresProfileIsolation(t *testing.T) {
	store := new(mem.Store)
	a := UnifiedPolicyStore{Store: store, ProfileID: "a", ProfileKey: ipn.StateKey("profile-a")}
	b := UnifiedPolicyStore{Store: store, ProfileID: "b", ProfileKey: ipn.StateKey("profile-b")}
	if e := a.Save("b", []byte("wrong")); e == nil {
		t.Fatal("cross-profile save")
	}
	if e := a.Save("a", []byte(`{"Config":{"schema_version":1}}`)); e != nil {
		t.Fatal(e)
	}
	if _, e := b.Load("b"); !errors.Is(e, fs.ErrNotExist) {
		t.Fatalf("profile leaked: %v", e)
	}
	got, e := a.Load("a")
	if e != nil || string(got) != `{"Config":{"schema_version":1}}` {
		t.Fatalf("load: %s %v", got, e)
	}
	ledger := UnifiedLedgerStore{Store: store, ProfileKey: "profile-a"}
	if _, e := ledger.Load(); !errors.Is(e, fs.ErrNotExist) {
		t.Fatalf("namespace collision: %v", e)
	}
	if e := ledger.Save([]byte("ledger")); e != nil {
		t.Fatal(e)
	}
	got, e = a.Load("a")
	if e != nil || string(got) != `{"Config":{"schema_version":1}}` {
		t.Fatal("ledger overwrote policy")
	}
	if e := ledger.Apply(nil, nil); e == nil {
		t.Fatal("missing durable writer accepted")
	}
}

func TestUnifiedStoresLeaseIsolation(t *testing.T) {
	store := new(mem.Store)
	a := UnifiedLeaseStore{Store: store, ProfileKey: "profile-a"}
	b := UnifiedLeaseStore{Store: store, ProfileKey: "profile-b"}
	if err := a.Save([]byte("lease evidence")); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Load(); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("cross-profile lease state", err)
	}
	ledger := UnifiedLedgerStore{Store: store, ProfileKey: "profile-a"}
	if _, err := ledger.Load(); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("lease overwrote ledger", err)
	}
}

func TestUnifiedOrdinaryProfileWriterIsolation(t *testing.T) {
	store := new(mem.Store)
	pm := &profileManager{store: store, logf: t.Logf}
	keys := []ipn.StateKey{"profile-a||_unifiedPolicyV1", "profile-a||_unifiedRouteLedgerV1", "profile-a||_unifiedLeasesV1", "profile-a||_unifiedHandoffV1"}
	for _, k := range keys {
		if err := store.WriteState(k, []byte("authority")); err != nil {
			t.Fatal(err)
		}
		if err := pm.WriteState(k, []byte("ordinary writer")); err == nil {
			t.Fatal("authority writable", k)
		}
	}
	if err := pm.writePrefsToStore("profile-a", ipn.NewPrefs().View()); err != nil {
		t.Fatal(err)
	}
	if err := pm.WriteState(ipn.KnownProfilesStateKey, []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	for _, k := range keys {
		v, err := store.ReadState(k)
		if err != nil || string(v) != "authority" {
			t.Fatal("authority changed", k, err)
		}
	}
}
