// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// route-reconcile produces an offline review plan. It has no network transport,
// credential input, approval writer, or automatic apply implementation.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"slices"
)

type tombstone struct {
	Prefix               netip.Prefix `json:"prefix"`
	Generation           uint64       `json:"generation"`
	ExclusiveModuleOwned bool         `json:"exclusiveModuleOwned"`
}
type snapshot struct {
	StableID        string         `json:"stableID"`
	Generation      uint64         `json:"generation"`
	AdvertiseRoutes []netip.Prefix `json:"advertiseRoutes"`
	Tombstones      []tombstone    `json:"tombstones"`
	Control         struct {
		StableID      string         `json:"stableID"`
		Version       string         `json:"version"`
		EnabledRoutes []netip.Prefix `json:"enabledRoutes"`
	} `json:"control"`
}
type plan struct {
	SnapshotSHA256 string `json:"snapshotSHA256"`
	// Both are complete lists for review, never executable API requests.
	ProposedEnabledRoutes []netip.Prefix `json:"proposedEnabledRoutes"`
	RollbackEnabledRoutes []netip.Prefix `json:"rollbackEnabledRoutes"`
	StableID              string         `json:"stableID"`
	Generation            uint64         `json:"generation"`
	ControlVersion        string         `json:"controlVersion"`
	DryRun                bool           `json:"dryRun"`
	ApplySupported        bool           `json:"applySupported"`
	Add                   []netip.Prefix `json:"add"`
	RemoveCandidates      []netip.Prefix `json:"removeCandidates"`
	Retain                []netip.Prefix `json:"retain"`
	Risks                 []string       `json:"risks"`
	Review                []string       `json:"review"`
}

func reconcile(s snapshot, device string, generation uint64, version string) (plan, error) {
	p := plan{StableID: device, Generation: s.Generation, ControlVersion: s.Control.Version, DryRun: true, Add: []netip.Prefix{}, RemoveCandidates: []netip.Prefix{}, Retain: []netip.Prefix{},
		Risks:  []string{"offline_snapshots_may_be_stale", "no_verified_server_cas_apply_disabled", "local_tombstones_do_not_prove_exclusive_control_plane_approval_ownership"},
		Review: []string{"Re-read this device's local generation, advertised routes, and tombstones.", "Re-read this device's enabledRoutes and control version; abort on any change.", "Confirm exclusive ownership of each candidate approval with the operator; retain shared, unknown and default routes.", "Review removals individually; never add approvals or modify autoApprovers or other devices.", "After any separately authorized manual operation, read back enabledRoutes; stop and reconcile on 429, 412, or partial failure. Do not blindly retry or roll back."}}
	if device == "" || device != s.StableID || device != s.Control.StableID {
		return plan{}, errors.New("device_scope_mismatch")
	}
	if s.Generation != generation || version == "" || version != s.Control.Version {
		return plan{}, errors.New("snapshot_cas_conflict")
	}
	valid := func(p netip.Prefix) bool { return p.IsValid() && p == p.Masked() && !p.Addr().Is4In6() }
	for _, routes := range [][]netip.Prefix{s.AdvertiseRoutes, s.Control.EnabledRoutes} {
		for _, r := range routes {
			if !valid(r) {
				return plan{}, errors.New("invalid_route")
			}
		}
	}
	dead := map[netip.Prefix]bool{}
	for _, t := range s.Tombstones {
		if !valid(t.Prefix) || t.Generation > s.Generation {
			return plan{}, errors.New("invalid_tombstone")
		}
		if _, exists := dead[t.Prefix]; exists {
			return plan{}, errors.New("duplicate_tombstone")
		}
		dead[t.Prefix] = t.ExclusiveModuleOwned && t.Generation == s.Generation
	}
	for _, r := range s.Control.EnabledRoutes {
		removable := r.IsSingleIP() && dead[r]
		for _, a := range s.AdvertiseRoutes {
			if r.Overlaps(a) {
				removable = false
			}
		}
		if removable {
			p.RemoveCandidates = append(p.RemoveCandidates, r)
		} else {
			p.Retain = append(p.Retain, r)
		}
	}
	sortRoutes := func(v []netip.Prefix) []netip.Prefix {
		slices.SortFunc(v, func(a, b netip.Prefix) int { return a.Compare(b) })
		return slices.Compact(v)
	}
	p.RemoveCandidates, p.Retain = sortRoutes(p.RemoveCandidates), sortRoutes(p.Retain)
	p.ProposedEnabledRoutes = slices.Clone(p.Retain)
	p.RollbackEnabledRoutes = sortRoutes(slices.Clone(s.Control.EnabledRoutes))
	raw, err := json.Marshal(s)
	if err != nil {
		return plan{}, errors.New("invalid_snapshot")
	}
	p.SnapshotSHA256 = fmt.Sprintf("%x", sha256.Sum256(raw))
	return p, nil
}

func run(args []string, in io.Reader, out io.Writer) error {
	fs := flag.NewFlagSet("route-reconcile", flag.ContinueOnError)
	// Flag/parser errors may echo input. Never print them or their arguments.
	fs.SetOutput(io.Discard)
	var device, version string
	var generation uint64
	var apply bool
	fs.StringVar(&device, "device", "", "Target StableID")
	fs.StringVar(&version, "expect-version", "", "Expected control snapshot version")
	fs.Uint64Var(&generation, "expect-generation", 0, "Expected local snapshot generation")
	fs.BoolVar(&apply, "apply", false, "Unsupported without verified server CAS")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		return errors.New("invalid_arguments")
	}
	if apply {
		return errors.New("apply_disabled_no_verified_server_cas")
	}
	hasGeneration := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "expect-generation" {
			hasGeneration = true
		}
	})
	if !hasGeneration {
		return errors.New("expected_generation_required")
	}
	data, err := io.ReadAll(io.LimitReader(in, (4<<20)+1))
	if err != nil || len(data) > 4<<20 {
		return errors.New("invalid_snapshot")
	}
	if err := uniqueJSON(json.NewDecoder(bytes.NewReader(data)), 0); err != nil {
		return errors.New("invalid_snapshot")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	var s snapshot
	if err := d.Decode(&s); err != nil {
		return errors.New("invalid_snapshot")
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return errors.New("invalid_snapshot")
	}
	p, err := reconcile(s, device, generation, version)
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(p)
}
func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// Duplicate fields make externally assembled snapshots ambiguous; reject them.
func uniqueJSON(d *json.Decoder, depth int) error {
	if depth > 32 {
		return errors.New("depth")
	}
	tok, err := d.Token()
	if err != nil {
		return err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			k, err := d.Token()
			if err != nil {
				return err
			}
			key, ok := k.(string)
			if !ok || seen[key] {
				return errors.New("duplicate")
			}
			seen[key] = true
			if err := uniqueJSON(d, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for d.More() {
			if err := uniqueJSON(d, depth+1); err != nil {
				return err
			}
		}
	default:
		return errors.New("delimiter")
	}
	_, err = d.Token()
	return err
}
