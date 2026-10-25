// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_debug

package localapi

import (
	"encoding/json"
	"io"
	"net/http"
	"tailscale.com/appc"
	"tailscale.com/ipn/ipnlocal"
)

// Called only after serveDebug's POST and PermitWrite checks.
func (h *Handler) serveUnifiedPolicyDebug(w http.ResponseWriter, r *http.Request, action string) {
	w.Header().Set("Content-Type", "application/json")
	if action == "unified-policy-status" {
		json.NewEncoder(w).Encode(h.b.UnifiedPolicyDebugStatus())
		return
	}
	var input struct {
		ExpectSourceID   uint64                     `json:"expect_source_id,omitempty"`
		Manifest         *appc.ControlProofManifest `json:"manifest,omitempty"`
		Claims           []appc.LegacyDNSReference  `json:"claims,omitempty"`
		ConfirmTime      bool                       `json:"confirm_time,omitempty"`
		Source           string                     `json:"source,omitempty"`
		File             string                     `json:"file,omitempty"`
		ExpectGeneration *uint64                    `json:"expect_generation"`
		ExpectSHA256     string                     `json:"expect_sha256,omitempty"`
	}
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	d.DisallowUnknownFields()
	if err := d.Decode(&input); err != nil {
		http.Error(w, "invalid debug request", http.StatusBadRequest)
		return
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		http.Error(w, "invalid debug request", http.StatusBadRequest)
		return
	}
	if (action == "unified-policy-reload" || action == "unified-time-confirm") && input.ExpectGeneration == nil {
		http.Error(w, "expected_generation_required", http.StatusBadRequest)
		return
	}
	req := ipnlocal.UnifiedDebugRequest{ExpectSourceID: input.ExpectSourceID, Claims: input.Claims, Manifest: input.Manifest, File: input.File, ExpectSHA256: input.ExpectSHA256, ConfirmTime: input.ConfirmTime, Source: input.Source}
	if input.ExpectGeneration != nil {
		req.ExpectGeneration = *input.ExpectGeneration
	}
	out, err := h.b.UnifiedPolicyInspect(r.Context(), action, req)
	if err != nil {
		code := http.StatusBadRequest
		if err.Error() == "policy_cas_conflict" || err.Error() == "policy_inputs_changed_retry" {
			code = http.StatusConflict
		}
		out.Error = err.Error()
		w.WriteHeader(code)
	}
	json.NewEncoder(w).Encode(out)
}
