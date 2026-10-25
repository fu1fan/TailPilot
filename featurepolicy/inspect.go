// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package featurepolicy

import "encoding/json"

// Inspection is a redacted, unstable debug result. Offline inspection cannot
// establish runtime readiness. Preview never stages, persists, or publishes.
type Inspection struct {
	Migration          string          `json:"migration,omitempty"`
	ClearPreview       json.RawMessage `json:"clear_preview,omitempty"`
	AcceptedGeneration uint64          `json:"accepted_generation"`
	AppliedGeneration  uint64          `json:"applied_generation"`
	PendingSideEffects bool            `json:"pending_side_effects"`
	SchemaValid        bool            `json:"schemaValid"`
	RuntimeReady       bool            `json:"runtimeReady"`
	Accepted           bool            `json:"accepted"`
	Applied            bool            `json:"applied"`
	Offline            bool            `json:"offline"`
	RequestedSHA256    string          `json:"requested_sha256"`
	CanonicalSHA256    string          `json:"canonical_sha256,omitempty"`
	Changed            bool            `json:"changed"`
	ChangedModules     []string        `json:"changedModules,omitempty"`
	PendingRules       int             `json:"pendingRules"`
	Error              string          `json:"error,omitempty"`
}

// Inspect validates syntax and optionally compiles against trusted inputs.
// Error codes deliberately exclude user-controlled configuration fragments.
func Inspect(data []byte, in *Inputs, current *PolicySnapshot) Inspection {
	out := Inspection{RequestedSHA256: hash(data), Offline: in == nil}
	c, err := Parse(data)
	if err != nil {
		out.Error = "invalid_configuration"
		return out
	}
	out.SchemaValid = true
	var version struct {
		SchemaVersion int `json:"schema_version"`
	}
	_ = json.Unmarshal(data, &version)
	if version.SchemaVersion == 1 {
		out.Migration = "migrated-from-v1"
	}
	out.CanonicalSHA256 = hash(c.JSON())
	if current != nil {
		old := current.Config()
		out.Changed = hash(old.JSON()) != out.CanonicalSHA256
		// Compare each module without exposing targets or selectors.
		if old.Enabled != c.Enabled {
			out.ChangedModules = append(out.ChangedModules, "root")
		}
		if old.Machine != c.Machine {
			out.ChangedModules = append(out.ChangedModules, "metadata")
		}
		a, b := old, c
		if !equalJSON(a.Lease, b.Lease) {
			out.ChangedModules = append(out.ChangedModules, "lease")
		}
		if !equalJSON(a.AutoIPv6, b.AutoIPv6) {
			out.ChangedModules = append(out.ChangedModules, "auto_ipv6")
		}
		if !equalJSON(a.DNSIPv4Only, b.DNSIPv4Only) {
			out.ChangedModules = append(out.ChangedModules, "dns_ipv4_only")
		}
		if a.ReloadSeconds != b.ReloadSeconds {
			out.ChangedModules = append(out.ChangedModules, "reload")
		}
		if !equalJSON(a.Observability, b.Observability) {
			out.ChangedModules = append(out.ChangedModules, "observability")
		}
		if !equalJSON(a.PathPolicy, b.PathPolicy) {
			out.ChangedModules = append(out.ChangedModules, "path_policy")
		}
	}
	if in == nil {
		return out
	}
	s, err := compile(c, *in, 0)
	if err != nil {
		out.Error = "runtime_not_ready"
		return out
	}
	out.PendingRules = len(s.PendingRules())
	out.RuntimeReady = out.PendingRules == 0
	return out
}

// SourceHash returns the hash of the last accepted source bytes, not canonical JSON.
func (m *Manager) SourceHash() string { m.mu.Lock(); defer m.mu.Unlock(); return m.sourceHash }

func equalJSON(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}

// Durable reports whether enabled configurations can be persisted. It neither
// calls stages nor writes anything; preview must never invoke mutating stages.
func (m *Manager) Durable() bool { m.mu.Lock(); defer m.mu.Unlock(); return m.store != nil }
