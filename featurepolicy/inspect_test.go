// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package featurepolicy

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestInspectionOfflineAndReadOnly(t *testing.T) {
	store := &memoryStore{}
	m := NewManager(store)
	data := []byte(`{"schema_version":1}`)
	if _, err := m.Start(Inputs{ProfileID: "p"}, func() ([]byte, error) { return data, nil }); err != nil {
		t.Fatal(err)
	}
	before, stored := m.Current(), string(store.data["p"])
	next := []byte(`{"schema_version":1,"enabled":true}`)
	v := Inspect(next, nil, before)
	if !v.SchemaValid || v.RuntimeReady || v.Accepted || v.Applied || !v.Offline || !v.Changed {
		t.Fatalf("%+v", v)
	}
	v = Inspect(next, &Inputs{ProfileID: "p"}, before)
	if !v.RuntimeReady || v.Accepted || v.Applied {
		t.Fatalf("%+v", v)
	}
	if m.Current() != before || string(store.data["p"]) != stored {
		t.Fatal("preview mutated state")
	}
	v = Inspect([]byte(`{"secret-SENTINEL":1}`), nil, before)
	raw, _ := json.Marshal(v)
	if v.SchemaValid || strings.Contains(string(raw), "SENTINEL") {
		t.Fatalf("%s", raw)
	}
}
