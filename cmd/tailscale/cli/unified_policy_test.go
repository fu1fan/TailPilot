// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package cli

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestUnifiedPolicyOffline(t *testing.T) {
	p := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(p, []byte(`{"schema_version":1}`), 0600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"validate", "--file", p}, {"preview", "--offline", "--file", p}} {
		if err := unifiedPolicyCmd().ParseAndRun(context.Background(), args); err != nil {
			t.Fatal(err)
		}
	}
}
func TestUnifiedPolicyArguments(t *testing.T) {
	for _, args := range [][]string{{"status", "--offline"}, {"reload"}, {"validate"}, {"preview", "--offline"}, {"status", "extra"}, {"reload", "--file=x"}, {"reload", "--expect-sha256=abcd"}} {
		if err := unifiedPolicyCmd().ParseAndRun(context.Background(), args); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
}
