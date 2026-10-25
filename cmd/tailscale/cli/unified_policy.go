// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/featurepolicy"
)

func unifiedPolicyCmd() *ffcli.Command {
	root := &ffcli.Command{Name: "unified-policy", ShortUsage: "tailscale debug unified-policy <validate|preview|reload|status> [flags]", ShortHelp: "Inspect unified policy (unstable local debug interface)", Exec: func(context.Context, []string) error {
		return errors.New("expected validate, preview, reload, or status")
	}}
	for _, command := range []struct{ verb, help string }{
		{"validate", "Validate unified policy from a local file"},
		{"preview", "Preview unified policy readiness and changes"},
		{"reload", "Reload unified policy using the reviewed binding"},
		{"status", "Show unified policy status"},
	} {
		verb := command.verb
		var file, sha string
		var generation uint64
		var offline, jsonOutput bool
		fs := newFlagSet(verb)
		fs.StringVar(&file, "file", "", "Policy file (preview/validate only)")
		fs.BoolVar(&offline, "offline", false, "Validate without contacting daemon")
		fs.BoolVar(&jsonOutput, "json", false, "JSON output (always enabled)")
		fs.Uint64Var(&generation, "expect-generation", 0, "Expected current generation")
		fs.StringVar(&sha, "expect-sha256", "", "Expected SHA256 of requested file bytes")
		root.Subcommands = append(root.Subcommands, &ffcli.Command{Name: verb, ShortUsage: "tailscale debug unified-policy " + verb + " [flags]", ShortHelp: command.help, FlagSet: fs, Exec: func(ctx context.Context, args []string) error {
			if len(args) != 0 {
				return errors.New("unexpected positional arguments")
			}
			if (verb == "reload" || verb == "status") && (file != "" || offline) {
				return errors.New("file/offline not valid for this command")
			}
			if verb != "reload" && (sha != "" || generation != 0) {
				return errors.New("CAS flags require reload")
			}
			if verb == "reload" {
				raw, err := hex.DecodeString(sha)
				if err != nil || len(raw) != 32 {
					return errors.New("reload requires --expect-sha256 (64 hexadecimal characters)")
				}
				supplied := false
				fs.Visit(func(f *flag.Flag) {
					if f.Name == "expect-generation" {
						supplied = true
					}
				})
				if !supplied {
					return errors.New("reload requires --expect-generation")
				}
			}
			if verb == "validate" || offline {
				if file == "" {
					return errors.New("offline inspection requires --file")
				}
				data, err := readOfflinePolicy(file)
				if err != nil {
					return err
				}
				out := featurepolicy.Inspect(data, nil, nil)
				if err := json.NewEncoder(Stdout).Encode(out); err != nil {
					return err
				}
				if !out.SchemaValid {
					return errors.New("invalid_configuration")
				}
				return nil
			}
			request := struct {
				File       string `json:"file,omitempty"`
				Generation uint64 `json:"expect_generation"`
				SHA        string `json:"expect_sha256,omitempty"`
			}{file, generation, sha}
			out, err := localClient.DebugActionJSON(ctx, "unified-policy-"+verb, request)
			if err != nil {
				return err
			}
			if _, err := fmt.Fprintln(Stdout, string(out)); err != nil {
				return err
			}
			if verb == "preview" {
				var v featurepolicy.Inspection
				if err := json.Unmarshal(out, &v); err != nil {
					return err
				}
				if !v.SchemaValid || !v.RuntimeReady || v.Error != "" {
					return errors.New("policy preview failed")
				}
			}
			return nil
		}})
	}
	return root
}

// Offline inspection checks schema only, not daemon root ownership/trust.
func readOfflinePolicy(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("policy must be a regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("cannot open policy file")
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		return nil, errors.New("policy must be a regular file")
	}
	data, err := io.ReadAll(io.LimitReader(f, featurepolicy.MaxConfigBytes+1))
	if err != nil || len(data) > featurepolicy.MaxConfigBytes {
		return nil, errors.New("policy file unreadable or too large")
	}
	return data, nil
}
