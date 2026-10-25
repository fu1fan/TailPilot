// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/client/local"
)

// These wire types mirror the adoption JSON contract without importing the
// daemon's appc implementation (and its packet-processing dependencies).
// Keep field names and types compatible with appc.ControlProofManifest and
// appc.LegacyDNSReference; TestAppcRouteManifestAndActions checks the payload.
type appcRouteReference struct {
	AssignedRoot string
	Domain       string
	IP           netip.Addr
}

type appcRouteProofManifest struct {
	SchemaVersion  int
	ProfileID      string
	LegacySourceID uint64
	Source         string
	Entries        []appcRouteProofEntry
}

type appcRouteProofEntry struct {
	Reference      appcRouteReference
	Reviewed       bool
	ReviewedBy     string
	Evidence       string
	EvidenceSHA256 string
}

func appcRouteCmd(kind string) *ffcli.Command {
	return appcRouteCmdWithClient(kind, &localClient)
}

func appcRouteCmdWithClient(kind string, client *local.Client) *ffcli.Command {
	var source, hash, claimsFile, manifestFile string
	var generation, sourceID uint64
	var execute, rollback bool
	fs := newFlagSet(kind)
	fs.StringVar(&source, "source", "", "Audit source (required in preview and execution)")
	fs.StringVar(&hash, "expect-sha256", "", "Exact preview hash")
	fs.Uint64Var(&generation, "expect-generation", 0, "Preview generation")
	fs.Uint64Var(&sourceID, "expect-source-id", 0, "Preview Connector source lifetime")
	fs.BoolVar(&execute, "execute", false, "Execute the reviewed preview (default: preview)")
	if kind == "appc-route-reset" {
		fs.BoolVar(&rollback, "rollback", false, "CAS rollback of the last reset; requires a fresh preview")
	}
	if kind == "appc-route-adopt" {
		fs.StringVar(&manifestFile, "manifest", "", "Reviewed external control proof JSON; supply identical manifest in preview and execute")
		fs.StringVar(&claimsFile, "claims", "", "JSON array of explicitly reviewed domain/IP references (no adopt-all)")
	}
	return &ffcli.Command{Name: kind, ShortUsage: "tailscale debug " + kind + " [flags]", ShortHelp: "Preview or execute Connector learning lifecycle action", FlagSet: fs, Exec: func(ctx context.Context, args []string) error {
		if len(args) != 0 || source == "" {
			return errors.New("--source is required; no positional arguments")
		}
		if rollback && execute {
			return errors.New("choose --execute or --rollback")
		}
		if execute || rollback {
			raw, e := hex.DecodeString(hash)
			if e != nil || len(raw) != 32 || sourceID == 0 {
				return errors.New("execution requires preview hash, generation and source ID")
			}
		}
		req := struct {
			Source     string                  `json:"source"`
			Hash       string                  `json:"expect_sha256,omitempty"`
			Generation uint64                  `json:"expect_generation"`
			SourceID   uint64                  `json:"expect_source_id,omitempty"`
			Manifest   *appcRouteProofManifest `json:"manifest,omitempty"`
			Claims     []appcRouteReference    `json:"claims,omitempty"`
		}{Source: source, Hash: hash, Generation: generation, SourceID: sourceID}
		if claimsFile != "" {
			f, e := os.Open(claimsFile)
			if e != nil {
				return e
			}
			defer f.Close()
			data, e := io.ReadAll(io.LimitReader(f, 1<<20+1))
			if e != nil {
				return e
			}
			if len(data) > 1<<20 {
				return errors.New("claims too large")
			}
			if e = json.Unmarshal(data, &req.Claims); e != nil {
				return e
			}
		}
		if manifestFile != "" {
			f, e := os.Open(manifestFile)
			if e != nil {
				return e
			}
			defer f.Close()
			data, e := io.ReadAll(io.LimitReader(f, (1<<20)+1))
			if e != nil {
				return e
			}
			if len(data) > 1<<20 {
				return errors.New("manifest too large")
			}
			d := json.NewDecoder(bytes.NewReader(data))
			d.DisallowUnknownFields()
			if e = d.Decode(&req.Manifest); e != nil {
				return e
			}
			if req.Manifest == nil {
				return errors.New("manifest must be an object")
			}
			if e = d.Decode(new(any)); e != io.EOF {
				return errors.New("trailing manifest JSON")
			}
		}

		action := kind + "-preview"
		if execute {
			action = kind
		}
		if rollback {
			action = kind + "-rollback"
		}
		out, e := client.DebugActionJSON(ctx, action, req)
		if e != nil {
			return e
		}
		_, e = fmt.Fprintln(Stdout, string(out))
		return e
	}}
}
