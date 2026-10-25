package ipnlocal

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"tailscale.com/appc"
)

func controlImportFixture(t *testing.T, n int) (*takeoverHarness, *appc.ControlProofManifest) {
	h := newTakeoverHarness(t, n)
	v, e := readConnectorIntent(h.st, h.key)
	mustTakeover(t, e)
	m := &appc.ControlProofManifest{SchemaVersion: 1, ProfileID: "p", LegacySourceID: v.Unclaimed.SourceID, Source: "offline-reviewed-archive"}
	for i := 0; i < n; i++ {
		d := fmt.Sprintf("d%d.example.test", i)
		ip := v.Unclaimed.Domains[d][0]
		p := netip.PrefixFrom(ip, 32)
		v.Unclaimed.Control = append(v.Unclaimed.Control, p)
		delete(v.Unclaimed.Domains, d)
		o := v.Ledger.Owners[p]
		o.Control = map[string]bool{"appc-legacy-control": true}
		v.Ledger.Owners[p] = o
		m.Entries = append(m.Entries, appc.ControlProofEntry{Reference: appc.LegacyDNSReference{AssignedRoot: "*.example.test", Domain: d, IP: ip}, Reviewed: true, ReviewedBy: "test-reviewer", Evidence: "offline archive line", EvidenceSHA256: strings.Repeat("a", 64)})
	}
	mustTakeover(t, h.adapter.Save(checksumJSON(v.Ledger)))
	mustTakeover(t, writeConnectorIntent(h.st, h.key, v))
	return h, m
}
func importPlan(t *testing.T, h *takeoverHarness, m *appc.ControlProofManifest) (ConnectorRoutePlan, error) {
	t.Helper()
	v, e := readConnectorIntent(h.st, h.key)
	mustTakeover(t, e)
	l, e := NewRouteLedger(h.f, h.adapter)
	mustTakeover(t, e)
	cur, e := h.adapter.Current()
	mustTakeover(t, e)
	return planConnectorImport(v, l, cur, "review", m)
}
func TestConnectorImport810ResetRelearn(t *testing.T) {
	h, m := controlImportFixture(t, 810)
	if len(h.plan(true).Entries) != 0 {
		t.Fatal("invented domain proof")
	}
	p, e := importPlan(t, h, m)
	mustTakeover(t, e)
	if len(p.Entries) != 810 || p.ManifestSHA256 == "" || p.ManifestSource != m.Source {
		t.Fatal("incomplete proof preview")
	}
	for _, entry := range p.Entries {
		if !entry.Eligible {
			t.Fatal(entry)
		}
		h.claims = append(h.claims, entry.Reference)
	}
	h.manifest = m
	mustTakeover(t, h.ac.AdoptTTL(p.ConnectorHash, "review", h.claims))
	h.claims = nil
	h.manifest = nil
	v, e := readConnectorIntent(h.st, h.key)
	mustTakeover(t, e)
	if len(v.ImportProofs) != 1 || len(v.ImportProofs[0].Entries) != 810 || len(v.BeforeUnclaimed.Domains) != 0 {
		t.Fatal("lost original/import evidence")
	}
	p = h.plan(false)
	if len(p.Withdraw) != 810 || len(p.Retain) != 4 {
		t.Fatalf("withdraw=%d retain=%d", len(p.Withdraw), len(p.Retain))
	}
	mustTakeover(t, h.ac.ResetTTL(p.ConnectorHash, h.f.Generation, "reset"))
	mustTakeover(t, h.ac.ObserveDNSResponse(takeoverWire(t, "d0.example.test", [4]byte{192, 0, 1, 1})))
	cur, e := h.adapter.Current()
	mustTakeover(t, e)
	if len(cur) != 5 {
		t.Fatal(cur)
	}
}
func TestConnectorImportProtectionAndBinding(t *testing.T) {
	h, m := controlImportFixture(t, 2)
	baseline, e := importPlan(t, h, m)
	mustTakeover(t, e)
	m.Entries[0].Evidence = "different evidence"
	changed, e := importPlan(t, h, m)
	mustTakeover(t, e)
	if changed.SnapshotHash == baseline.SnapshotHash {
		t.Fatal("proof not bound")
	}
	for _, mutate := range []func(*appc.ControlProofManifest){
		func(m *appc.ControlProofManifest) { m.ProfileID = "foreign" },
		func(m *appc.ControlProofManifest) { m.LegacySourceID++ },
		func(m *appc.ControlProofManifest) { m.SchemaVersion = 2 },
		func(m *appc.ControlProofManifest) { m.Entries[0].Reviewed = false },
		func(m *appc.ControlProofManifest) { m.Entries[0].EvidenceSHA256 = "" },
		func(m *appc.ControlProofManifest) { m.Entries = append(m.Entries, m.Entries[0]) },
	} {
		copy := *m
		copy.Entries = slices.Clone(m.Entries)
		mutate(&copy)
		if _, e := importPlan(t, h, &copy); e == nil {
			t.Fatal("invalid proof accepted")
		}
	}
	for _, kind := range []string{"manual", "static", "unknown", "unassigned", "not-advertised"} {
		t.Run(kind, func(t *testing.T) {
			h, m := controlImportFixture(t, 1)
			v, e := readConnectorIntent(h.st, h.key)
			mustTakeover(t, e)
			p := netip.PrefixFrom(m.Entries[0].Reference.IP, 32)
			o := v.Ledger.Owners[p]
			switch kind {
			case "manual":
				o.Manual = true
			case "static":
				v.Transition.After.Control = append(v.Transition.After.Control, p)
			case "unknown":
				delete(o.Control, "appc-legacy-control")
				v.Unclaimed.Control = nil
			case "unassigned":
				m.Entries[0].Reference.AssignedRoot = "other.test"
			case "not-advertised":
				m.Entries[0].Reference.IP = netip.MustParseAddr("192.0.2.199")
			}
			v.Ledger.Owners[p] = o
			mustTakeover(t, h.adapter.Save(checksumJSON(v.Ledger)))
			mustTakeover(t, writeConnectorIntent(h.st, h.key, v))
			plan, e := importPlan(t, h, m)
			mustTakeover(t, e)
			if plan.Entries[0].Eligible {
				t.Fatal("protected reference eligible", plan)
			}
		})
	}
}
func TestConnectorImportSharedUnselectedRetained(t *testing.T) {
	h, m := controlImportFixture(t, 1)
	second := m.Entries[0]
	second.Reference.Domain = "shared.example.test"
	m.Entries = append(m.Entries, second)
	p, e := importPlan(t, h, m)
	mustTakeover(t, e)
	h.manifest = m
	h.claims = []appc.LegacyDNSReference{m.Entries[0].Reference}
	mustTakeover(t, h.ac.AdoptTTL(p.ConnectorHash, "review", h.claims))
	h.manifest = nil
	h.claims = nil
	if p = h.plan(false); len(p.Withdraw) != 0 {
		t.Fatal("unselected shared proof lost protection")
	}
	v, e := readConnectorIntent(h.st, h.key)
	mustTakeover(t, e)
	if len(v.Unclaimed.Domains[second.Reference.Domain]) != 1 {
		t.Fatal("shared proof not durable")
	}
}

func TestConnectorImportPowerCuts(t *testing.T) {
	// Adoption keeps prefs unchanged; Apply skips the prefs write (five writes).
	for n := 1; n <= 5; n++ {
		for _, after := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d-after-%t", n, after), func(t *testing.T) {
				h, m := controlImportFixture(t, 2)
				p, e := importPlan(t, h, m)
				mustTakeover(t, e)
				h.manifest = m
				for _, entry := range p.Entries {
					h.claims = append(h.claims, entry.Reference)
				}
				h.st.calls = 0
				h.st.nth = n
				h.st.after = after
				if e = h.ac.AdoptTTL(p.ConnectorHash, "review", h.claims); e == nil {
					t.Fatal("failed import acknowledged")
				}
				if _, e = h.ac.PreviewTTLReset(); e == nil {
					t.Fatal("failed import not quarantined")
				}
				h.st.nth = 0
				h.manifest = nil
				h.claims = nil
				v, e := readConnectorIntent(h.st, h.key)
				mustTakeover(t, e)
				mustTakeover(t, applyConnectorIntent(h.st, h.key, v, h.adapter))
				v, e = readConnectorIntent(h.st, h.key)
				mustTakeover(t, e)
				want := 2
				if n == 1 && !after {
					want = 0
				}
				if len(v.Transition.After.Legacy) != want {
					t.Fatal("partial adoption recovery")
				}
				if want == 2 && (len(v.ImportProofs) != 1 || len(v.ImportProofs[0].Entries) != 2) {
					t.Fatal("proof not recovered")
				}
				current, e := h.adapter.Current()
				mustTakeover(t, e)
				if len(current) != 6 {
					t.Fatal("import changed advertisements")
				}
				h.install(&v)
				if p = h.plan(false); len(p.Withdraw) != want {
					t.Fatal("restart ownership incorrect", p)
				}
			})
		}
	}
}

func TestConnectorImportControlWithoutLedgerMarker(t *testing.T) {
	h, m := controlImportFixture(t, 1)
	v, e := readConnectorIntent(h.st, h.key)
	mustTakeover(t, e)
	p := netip.PrefixFrom(m.Entries[0].Reference.IP, 32)
	o := v.Ledger.Owners[p]
	o.Control = nil
	v.Ledger.Owners[p] = o
	mustTakeover(t, h.adapter.Save(checksumJSON(v.Ledger)))
	mustTakeover(t, writeConnectorIntent(h.st, h.key, v))
	plan, e := importPlan(t, h, m)
	mustTakeover(t, e)
	if !plan.Entries[0].Eligible {
		t.Fatal("upstream Control evidence incorrectly requires old unified ledger")
	}
	h.manifest = m
	h.claims = []appc.LegacyDNSReference{m.Entries[0].Reference}
	mustTakeover(t, h.ac.AdoptTTL(plan.ConnectorHash, "review", h.claims))
	h.manifest = nil
	h.claims = nil
	if len(h.plan(false).Withdraw) != 1 {
		t.Fatal("reviewed control route remains unclaimable")
	}
}
