// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package appc

// ControlProofManifest is an operator-reviewed assertion, not authenticated
// control-plane data. Import requires exact local historical provenance and CAS.
// No URL is fetched and no prefix is inferred to be learning from its length.
type ControlProofManifest struct {
	SchemaVersion  int
	ProfileID      string
	LegacySourceID uint64
	Source         string
	Entries        []ControlProofEntry
}

type ControlProofEntry struct {
	Reference      LegacyDNSReference
	Reviewed       bool
	ReviewedBy     string
	Evidence       string
	EvidenceSHA256 string
}
