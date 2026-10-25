// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"tailscale.com/appc"
	"tailscale.com/featurepolicy"
	"tailscale.com/types/appctype"
)

// Preserve all accepted receipts within a bounded journal. Repeated identical
// manifests are deduplicated; a full journal fails closed without dropping proof.
func appendControlProof(existing []*appc.ControlProofManifest, m *appc.ControlProofManifest) ([]*appc.ControlProofManifest, error) {
	raw, _ := json.Marshal(m)
	for _, old := range existing {
		b, _ := json.Marshal(old)
		if string(b) == string(raw) {
			return existing, nil
		}
	}
	result := append(slices.Clone(existing), m)
	data, _ := json.Marshal(result)
	if len(data) > 4<<20 {
		return nil, fmt.Errorf("appc TTL: proof journal capacity exceeded")
	}
	return result, nil
}

// controlProofEntries validates the envelope and explains each reference. Even
// reviewed evidence never grants authority over current static or foreign owners.
func controlProofEntries(v connectorIntent, l *RouteLedger, current []netip.Prefix, m *appc.ControlProofManifest) ([]ConnectorProvenance, error) {
	if m == nil {
		return nil, nil
	}
	if m.SchemaVersion != 1 || m.ProfileID != v.Transition.After.Fence.ProfileID || m.LegacySourceID != v.Unclaimed.SourceID || strings.TrimSpace(m.Source) == "" || len(m.Source) > 200 || len(m.Entries) == 0 || len(m.Entries) > 2000 {
		return nil, fmt.Errorf("appc TTL: invalid proof manifest binding")
	}
	if _, err := appendControlProof(v.ImportProofs, m); err != nil {
		return nil, err
	}
	seen := map[appc.LegacyDNSReference]bool{}
	var out []ConnectorProvenance
	for _, entry := range m.Entries {
		ref := entry.Reference
		digest, err := hex.DecodeString(entry.EvidenceSHA256)
		if !entry.Reviewed || strings.TrimSpace(entry.ReviewedBy) == "" || len(entry.ReviewedBy) > 200 || strings.TrimSpace(entry.Evidence) == "" || len(entry.Evidence) > 1000 || err != nil || len(digest) != 32 || seen[ref] {
			return nil, fmt.Errorf("appc TTL: explicit reviewed evidence required; duplicate reference forbidden")
		}
		seen[ref] = true
		p := netip.PrefixFrom(ref.IP, ref.IP.BitLen())
		e := ConnectorProvenance{Reference: ref, Prefix: p, Eligible: false, Reason: "external proof: no matching historical control provenance", Proof: &entry}
		domain, err := featurepolicy.NormalizeDomain(ref.Domain)
		o := l.state.Owners[p]
		switch {
		case err != nil || domain != ref.Domain || ref.IP.Is4In6() || !allowedAutoRoute(p) || ref.AssignedRoot == "" || !slices.Contains(v.Transition.After.Roots, ref.AssignedRoot) || rootForDomain([]string{ref.AssignedRoot}, ref.Domain) == "":
			e.Reason = "external proof: unassigned or invalid reference"
		case slices.Contains(v.Transition.After.Control, p):
			e.Reason = "external proof: current static control retained"
		case o.Manual || o.ExitDefault:
			e.Reason = "external proof: manual/default owner retained"
		case !slices.Contains(current, p) || !slices.Contains(v.Unclaimed.Control, p):
			// Unknown-only and arbitrary host prefixes are not importable.
		default:
			e.Eligible = true
			e.Reason = "reviewed external control provenance; explicit claim required; other owners retained"
		}
		out = append(out, e)
	}
	return out, nil
}

// Add all eligible reviewed references to the provenance projection before
// removing selected claims. Unselected shared references continue protecting it.
func withControlProof(v connectorIntent, entries []ConnectorProvenance) connectorIntent {
	raw, _ := json.Marshal(v.Unclaimed)
	v.Unclaimed = appctype.RouteInfo{}
	_ = json.Unmarshal(raw, &v.Unclaimed)
	if v.Unclaimed.Domains == nil {
		v.Unclaimed.Domains = map[string][]netip.Addr{}
	}
	for _, e := range entries {
		if e.Eligible && !slices.Contains(v.Unclaimed.Domains[e.Reference.Domain], e.Reference.IP) {
			v.Unclaimed.Domains[e.Reference.Domain] = append(v.Unclaimed.Domains[e.Reference.Domain], e.Reference.IP)
		}
	}
	return v
}

func planConnectorImport(v connectorIntent, l *RouteLedger, current []netip.Prefix, source string, m *appc.ControlProofManifest) (ConnectorRoutePlan, error) {
	p := planConnector(v, l, current, source, true)
	entries, err := controlProofEntries(v, l, current, m)
	if err != nil || m == nil {
		return p, err
	}
	p.Entries = append(p.Entries, entries...)
	raw, _ := json.Marshal(m)
	p.ManifestSource = m.Source
	p.ManifestSHA256 = fmt.Sprintf("%x", sha256.Sum256(raw))
	p.EvidenceSource = "persisted RouteInfo.Domains + reviewed external control proof"
	raw, _ = json.Marshal(p)
	p.SnapshotHash = fmt.Sprintf("%x", sha256.Sum256(raw))
	return p, nil
}

func prepareConnectorImport(v connectorIntent, l *RouteLedger, current []netip.Prefix, t appc.ConnectorTTLTransition, claims []appc.LegacyDNSReference, approvalHash string, f featurepolicy.Fence, manifest *appc.ControlProofManifest) (*connectorIntent, error) {
	beforeUnclaimed := v.Unclaimed
	if manifest != nil {
		entries, err := controlProofEntries(v, l, current, manifest)
		if err != nil {
			return nil, err
		}
		v = withControlProof(v, entries)
	}
	next, err := prepareConnectorTransition(v, l, current, t, claims, approvalHash, f)
	if err == nil && manifest != nil {
		next.BeforeUnclaimed = beforeUnclaimed
		next.ImportProofs, err = appendControlProof(v.ImportProofs, manifest)
	}
	return next, err
}
