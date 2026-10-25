// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
//go:build !ts_omit_debug

package localapi

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestUnifiedDebugAuthorization(t *testing.T) {
	for _, action := range []string{"unified-policy-status", "unified-policy-preview", "unified-policy-reload", "unified-time-confirm", "unified-auto-clear-preview", "unified-auto-clear", "appc-route-reset-preview", "appc-route-reset", "appc-route-reset-rollback", "appc-route-adopt-preview", "appc-route-adopt"} {
		for _, tc := range []struct {
			write  bool
			method string
			status int
		}{{false, "POST", 403}, {true, "GET", 405}} {
			h := handlerForTest(t, &Handler{PermitRead: true, PermitWrite: tc.write})
			w := httptest.NewRecorder()
			r := httptest.NewRequest(tc.method, "http://local-tailscaled.sock/localapi/v0/debug?action="+action, strings.NewReader(`{}`))
			h.serveDebug(w, r)
			if w.Code != tc.status {
				t.Fatalf("%s %s: %d %s", action, tc.method, w.Code, w.Body.String())
			}
		}
	}
}
func TestUnifiedDebugStatusAndInput(t *testing.T) {
	h := handlerForTest(t, &Handler{PermitWrite: true})
	for _, tc := range []struct {
		action, body string
		status       int
	}{{"unified-policy-status", "", 200}, {"unified-policy-preview", `{"unknown":"SENTINEL"}`, 400}, {"unified-policy-preview", `{} {}`, 400}, {"unified-policy-reload", `{}`, 400},
		{"appc-route-adopt-preview", `{"manifest":{"adopt_all":true}}`, 400},
		{"appc-route-adopt-preview", `{"manifest":{"Entries":[{"Reference":{"Prefix":"192.0.2.1/32"}}]}}`, 400}} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "http://local-tailscaled.sock/localapi/v0/debug", strings.NewReader(tc.body))
		r.Header.Set("Debug-Action", tc.action)
		h.serveDebug(w, r)
		if w.Code != tc.status || strings.Contains(w.Body.String(), "SENTINEL") {
			t.Fatalf("%s: %d %s", tc.action, w.Code, w.Body.String())
		}
	}
}
