// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package main

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
)

func fixture() snapshot {
	p := func(s string) netip.Prefix { return netip.MustParsePrefix(s) }
	s := snapshot{StableID: "device", Generation: 7, AdvertiseRoutes: []netip.Prefix{p("10.1.0.0/16")}, Tombstones: []tombstone{{p("10.0.0.1/32"), 7, true}, {p("10.1.0.1/32"), 7, true}, {p("0.0.0.0/0"), 7, true}, {p("10.2.0.1/32"), 7, false}}}
	s.Control.StableID, s.Control.Version = "device", "v7"
	s.Control.EnabledRoutes = []netip.Prefix{p("10.0.0.1/32"), p("10.1.0.1/32"), p("0.0.0.0/0"), p("10.2.0.1/32")}
	return s
}
func TestDryRun(t *testing.T) {
	s := fixture()
	before, _ := json.Marshal(s)
	p, e := reconcile(s, "device", 7, "v7")
	if e != nil || !p.DryRun || p.ApplySupported || len(p.Add) != 0 || len(p.RemoveCandidates) != 1 || len(p.Retain) != 3 {
		t.Fatalf("%+v %v", p, e)
	}
	after, _ := json.Marshal(s)
	if !bytes.Equal(before, after) {
		t.Fatal("mutated input")
	}
	var out bytes.Buffer
	if e := run([]string{"--device=device", "--expect-generation=7", "--expect-version=v7"}, bytes.NewReader(before), &out); e != nil {
		t.Fatal(e)
	}
}
func TestConflictAndNoCAS(t *testing.T) {
	for _, tc := range []struct {
		device     string
		generation uint64
		version    string
	}{{"other", 7, "v7"}, {"device", 8, "v7"}, {"device", 7, "v8"}} {
		if _, e := reconcile(fixture(), tc.device, tc.generation, tc.version); e == nil {
			t.Fatal("accepted conflict")
		}
	}
	// No transport exists: apply is rejected before parsing snapshots, including
	// hypothetical 429/412/partial-failure responses. No remote retry is possible.
	for _, input := range []string{`{"status":429}`, `{"status":412}`, `{"partial":true}`, `{"cas":true}`} {
		var out bytes.Buffer
		e := run([]string{"--apply"}, strings.NewReader(input), &out)
		if e == nil || e.Error() != "apply_disabled_no_verified_server_cas" || out.Len() != 0 {
			t.Fatalf("%v %s", e, out.String())
		}
	}
}
func TestCredentialRedaction(t *testing.T) {
	secret := "SENTINEL_CREDENTIAL"
	for _, args := range [][]string{{"--token=" + secret}, {"--expect-generation=" + secret}, {"--device=device", "--expect-generation=7", "--expect-version=v7"}} {
		var out bytes.Buffer
		e := run(args, strings.NewReader(`{"token":"`+secret+`"}`), &out)
		if e == nil || strings.Contains(e.Error()+out.String(), secret) {
			t.Fatalf("credential leaked or accepted: %v", e)
		}
	}
}

func TestMalformedSnapshots(t *testing.T) {
	for _, raw := range []string{`{"stableID":"one","stableID":"two"}`, `{} {}`, `{"control":{"version":"one","version":"two"}}`, strings.Repeat(" ", 4<<20) + `{}`} {
		var out bytes.Buffer
		if err := run([]string{"--device=device", "--expect-generation=7", "--expect-version=v7"}, strings.NewReader(raw), &out); err == nil || out.Len() != 0 {
			t.Fatal("accepted ambiguous/oversized snapshot")
		}
	}
}

func TestCompleteListsAndStaticProtection(t *testing.T) {
	s := fixture()
	static := netip.MustParsePrefix("203.0.113.0/24")
	exit := netip.MustParsePrefix("::/0")
	unknown := netip.MustParsePrefix("2001:db8::1/128")
	for _, r := range []netip.Prefix{static, exit, unknown} {
		s.Control.EnabledRoutes = append(s.Control.EnabledRoutes, r)
	}
	// A tombstone must never authorize removal of a static non-host prefix.
	s.Tombstones = append(s.Tombstones, tombstone{static, 7, true}, tombstone{exit, 7, true})
	p, err := reconcile(s, "device", 7, "v7")
	if err != nil {
		t.Fatal(err)
	}
	if len(p.RemoveCandidates) != 1 || len(p.ProposedEnabledRoutes) != 6 || len(p.RollbackEnabledRoutes) != 7 || len(p.SnapshotSHA256) != 64 {
		t.Fatal(p)
	}
	s.Control.EnabledRoutes = append(s.Control.EnabledRoutes, netip.MustParsePrefix("192.0.2.1/32"))
	q, err := reconcile(s, "device", 7, "v7")
	if err != nil {
		t.Fatal(err)
	}
	if p.SnapshotSHA256 == q.SnapshotSHA256 {
		t.Fatal("approval change not bound")
	}
}
