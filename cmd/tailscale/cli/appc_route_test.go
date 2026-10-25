package cli

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"tailscale.com/client/local"
)

type appcRouteTransport func(*http.Request) (*http.Response, error)

func (f appcRouteTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestAppcRouteManifestAndActions(t *testing.T) {
	dir := t.TempDir()
	manifest := filepath.Join(dir, "proof.json")
	claims := filepath.Join(dir, "claims.json")
	raw := `{"SchemaVersion":1,"ProfileID":"p","LegacySourceID":7,"Source":"archive","Entries":[{"Reference":{"AssignedRoot":"*.example.test","Domain":"a.example.test","IP":"192.0.2.1"},"Reviewed":true,"ReviewedBy":"reviewer","Evidence":"offline record","EvidenceSHA256":"` + strings.Repeat("a", 64) + `"}]}`
	if e := os.WriteFile(manifest, []byte(raw), 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(claims, []byte(`[{"AssignedRoot":"*.example.test","Domain":"a.example.test","IP":"192.0.2.1"}]`), 0600); e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct{ kind, flag, action string }{
		{"appc-route-adopt", "", "appc-route-adopt-preview"},
		{"appc-route-adopt", "--execute", "appc-route-adopt"},
		{"appc-route-reset", "", "appc-route-reset-preview"},
		{"appc-route-reset", "--execute", "appc-route-reset"},
		{"appc-route-reset", "--rollback", "appc-route-reset-rollback"},
	} {
		t.Run(tc.action, func(t *testing.T) {
			called := false
			c := &local.Client{OmitAuth: true, Transport: appcRouteTransport(func(r *http.Request) (*http.Response, error) {
				called = true
				if r.Method != "POST" || r.URL.Query().Get("action") != tc.action {
					t.Fatal("wrong action", r.URL)
				}
				var body map[string]json.RawMessage
				if e := json.NewDecoder(r.Body).Decode(&body); e != nil {
					t.Fatal(e)
				}
				if tc.kind == "appc-route-adopt" && (string(body["manifest"]) != raw || len(body["claims"]) == 0) {
					t.Fatalf("proof/claims lost: %s", body)
				}
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{}`))}, nil
			})}
			args := []string{"--source", "review"}
			if tc.kind == "appc-route-adopt" {
				args = append(args, "--manifest", manifest, "--claims", claims)
			}
			if tc.flag != "" {
				args = append(args, tc.flag, "--expect-sha256", strings.Repeat("b", 64), "--expect-generation", "1", "--expect-source-id", "8")
			}
			if e := appcRouteCmdWithClient(tc.kind, c).ParseAndRun(t.Context(), args); e != nil {
				t.Fatal(e)
			}
			if !called {
				t.Fatal("request not sent")
			}
		})
	}
	for _, bad := range []string{`null`, `{} {}`, `{"adopt_all":true}`, `{"Entries":[{"Reference":{"Prefix":"192.0.2.1/32"}}]}`} {
		if e := os.WriteFile(manifest, []byte(bad), 0600); e != nil {
			t.Fatal(e)
		}
		if e := appcRouteCmdWithClient("appc-route-adopt", &local.Client{}).ParseAndRun(t.Context(), []string{"--source", "review", "--manifest", manifest}); e == nil {
			t.Fatal("invalid proof accepted")
		}
	}
}
