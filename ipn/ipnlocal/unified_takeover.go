// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"tailscale.com/appc"
	"tailscale.com/featurepolicy"
	"tailscale.com/ipn"
	"tailscale.com/types/appctype"
	"tailscale.com/util/jsonchecksum"
)

// One write-ahead record owns all projections. Complete is the only applied
// acknowledgement. Failed writes leave a recoverable intent and quarantine DNS.
// No identity-bearing prefs snapshot is copied into this diagnostic sidecar.
type connectorIntent struct {
	ImportProofs        []*appc.ControlProofManifest `json:",omitempty"`
	BeforeLedger        routeLedgerState
	BeforeUnclaimed     appctype.RouteInfo
	Claims              []appc.LegacyDNSReference
	ObservedPrefsSHA256 string `json:"-"`
	BeforePrefsSHA256   string
	AfterPrefsSHA256    string
	ResetPrefsSHA256    string
	Schema              int
	Complete            bool
	Transition          appc.ConnectorTTLTransition
	Before, Desired     []netip.Prefix
	Ledger              routeLedgerState
	Unclaimed           appctype.RouteInfo
	Reset               *appc.ConnectorTTLTransition
	ResetLedgerHash     string
	Handoff             bool
	ApprovalHash        string
}

func connectorKey(k ipn.StateKey) ipn.StateKey { return k + "||_appConnectorTTLV2" }
func checksumJSON(v any) []byte {
	b, _ := jsonchecksum.Marshal(v)
	return b
}
func readConnectorIntent(st ipn.StateStore, k ipn.StateKey) (v connectorIntent, err error) {
	b, err := st.ReadState(connectorKey(k))
	if errors.Is(err, ipn.ErrStateNotExist) {
		return v, nil
	}
	if err != nil {
		return v, err
	}
	var env ledgerEnvelope
	if json.Unmarshal(b, &env) != nil || sha256.Sum256(env.Payload) != env.SHA256 || json.Unmarshal(env.Payload, &v) != nil || v.Schema != 2 || v.Ledger.Owners == nil || v.Transition.After.Fence.ProfileID == "" {
		return v, fmt.Errorf("appc TTL: corrupt journal")
	}
	return v, nil
}
func writeConnectorIntent(st ipn.StateStore, k ipn.StateKey, v connectorIntent) error {
	// Completed DNS/expiry transactions need only their after-image for restart.
	// Explicit reset undo lives in v.Reset and is retained independently. Keep
	// full before-images for unfinished recovery and operator-reviewed actions.
	if v.Complete && (v.Transition.Action == "dns" || v.Transition.Action == "sweep" || v.Transition.Action == "refresh" || v.Transition.Action == "dns-refresh") {
		v.BeforeLedger = routeLedgerState{}
		v.BeforeUnclaimed = appctype.RouteInfo{}
		v.Transition.Before = appc.ConnectorTTLState{}
		v.Transition.BeforeLeaseState = nil
	}
	return ipn.WriteState(st, connectorKey(k), checksumJSON(v))
}

func connectorCompatibility(v connectorIntent) appctype.RouteInfo {
	ri := v.Transition.After.RouteInfo()
	// Unclaimed learning is retained as compatibility evidence, never imported
	// into the TTL book or silently granted deletion authority.
	for d, ips := range v.Unclaimed.Domains {
		ri.Domains[d] = append(ri.Domains[d], ips...)
		slices.SortFunc(ri.Domains[d], func(a, b netip.Addr) int { return a.Compare(b) })
		ri.Domains[d] = slices.Compact(ri.Domains[d])
	}
	return ri
}

// applyConnectorIntent is restart-idempotent. Unexpected external route changes
// block replay instead of overwriting them. All callers exclude other writers.
func applyConnectorIntent(st ipn.StateStore, k ipn.StateKey, v connectorIntent, a UnifiedLedgerStore) error {
	if v.Schema == 0 || v.Complete {
		return nil
	}
	current, err := a.Current()
	if err != nil {
		return err
	}
	if !slices.Equal(sortedRoutes(current), v.Before) && !slices.Equal(sortedRoutes(current), v.Desired) {
		return fmt.Errorf("appc TTL: recovery prefs CAS conflict")
	}
	if err = (UnifiedLeaseStore{st, k}).Save(v.Transition.AfterLeaseState); err != nil {
		return err
	}
	ri, _ := json.Marshal(connectorCompatibility(v))
	if err = ipn.WriteState(st, k+"||_routeInfo", ri); err != nil {
		return err
	}
	if err = a.Save(checksumJSON(v.Ledger)); err != nil {
		return err
	}
	if err = a.Apply(sortedRoutes(current), v.Desired); err != nil {
		return err
	}
	v.Complete = true
	return writeConnectorIntent(st, k, v)
}

type connectorIntentCache struct {
	raw   []byte
	value connectorIntent
}

type connectorBackend struct {
	dnsCache connectorIntentCache
	store    ipn.StateStore
	key      ipn.StateKey
	detached bool
	b        *LocalBackend
	ac       *appc.AppConnector
	expected string // approval CAS, scoped to the lifecycle worker's current call
	approval string
	manifest *appc.ControlProofManifest
	claims   []appc.LegacyDNSReference
}

// connectorCommitError classifies how far a connector transaction got before
// it failed. Stage is a fixed vocabulary safe for logs and status projections;
// Started is true when persistence may have begun and therefore requires
// durable restart recovery rather than an in-place retry.
type connectorCommitError struct {
	Stage   string
	Started bool
	Err     error
}

func (e *connectorCommitError) Error() string {
	return fmt.Sprintf("appc TTL: %s: %v", e.Stage, e.Err)
}
func (e *connectorCommitError) Unwrap() error { return e.Err }

func connectorCommitErrorf(stage string, started bool, format string, args ...any) error {
	return &connectorCommitError{Stage: stage, Started: started, Err: fmt.Errorf(format, args...)}
}
func wrapConnectorCommit(stage string, started bool, err error) error {
	if err == nil {
		return nil
	}
	return &connectorCommitError{Stage: stage, Started: started, Err: err}
}

// connectorTransaction owns the existing backend writer barrier. It never
// acquires a Connector lock; callers enter in lifecycle -> backend order.
// A prewrite fence rejection (ErrTTLCommitNotStarted) is retryable and must not
// quarantine the lifecycle; uncertain write failures still do.
func (b *LocalBackend) connectorTransaction(f featurepolicy.Fence, fn func(connectorIntent, *RouteLedger, []netip.Prefix) (*connectorIntent, error), readOnly ...bool) (result connectorIntent, err error) {
	return b.connectorTransactionCached(f, fn, nil, readOnly...)
}

// The DNS callback treats the previous intent as immutable. Reuse its decoded
// representation only while the exact durable bytes still match; manual edits,
// profile changes, recovery and corruption always invalidate the cache.
func (b *LocalBackend) connectorTransactionCached(f featurepolicy.Fence, fn func(connectorIntent, *RouteLedger, []netip.Prefix) (*connectorIntent, error), cache *connectorIntentCache, readOnly ...bool) (result connectorIntent, err error) {
	b.mu.Lock()
	b.waitUnifiedPrefsTransactionLocked()
	s := b.unifiedSnapshot
	if b.unifiedTTLBlocked {
		b.mu.Unlock()
		return result, connectorCommitErrorf("prewrite-blocked", true, "appc TTL: restart recovery required")
	}
	if s == nil || s.Fence() != f || b.unifiedPublishedRevision != b.unifiedRevision || string(b.pm.CurrentProfile().ID()) != f.ProfileID {
		b.mu.Unlock()
		return result, &connectorCommitError{Stage: "prewrite-fence", Started: false, Err: fmt.Errorf("%w: stale backend fence", appc.ErrTTLCommitNotStarted)}
	}
	st, k := b.pm.store, b.pm.CurrentProfile().Key()
	var batch *bufferedConnectorStore
	var atomicWriter atomicStateWriter
	if w, ok := st.(atomicStateWriter); ok {
		atomicWriter = w
		batch = &bufferedConnectorStore{StateStore: st, updates: map[ipn.StateKey][]byte{}}
		st = batch
	}

	next := b.pm.CurrentPrefs().AsStruct()
	current := sortedRoutes(next.AdvertiseRoutes)
	done := make(chan struct{})
	b.unifiedPrefsPending = done
	b.unifiedPrefsPendingSince = time.Now()
	b.mu.Unlock()
	var durable *ipn.Prefs
	writeStarted := false
	stage := "journal-read"
	adapter := UnifiedLedgerStore{Store: st, ProfileKey: k, ReadPrefs: func() ([]netip.Prefix, error) { return slices.Clone(current), nil }, ApplyPrefs: func(before, desired []netip.Prefix) error {
		if !slices.Equal(sortedRoutes(before), current) {
			return fmt.Errorf("appc TTL: prefs CAS")
		}
		candidate := next.Clone()
		candidate.AdvertiseRoutes = slices.Clone(desired)
		b.mu.Lock()
		e := b.checkPrefsLocked(candidate)
		b.mu.Unlock()
		if e != nil {
			return e
		}
		if e = ipn.WriteState(st, k, candidate.ToBytes()); e != nil {
			return e
		}
		current = slices.Clone(desired)
		durable = candidate
		return nil
	}}
	if cache != nil {
		raw, e := st.ReadState(connectorKey(k))
		if e == nil && cache.raw != nil && bytes.Equal(raw, cache.raw) {
			result = cache.value
		} else {
			result, err = readConnectorIntent(st, k)
		}
	} else {
		result, err = readConnectorIntent(st, k)
	}
	if err == nil && result.Schema != 0 && result.Transition.After.Fence.ProfileID != f.ProfileID {
		stage = "journal-foreign"
		err = fmt.Errorf("appc TTL: foreign journal")
	}
	if err == nil && len(readOnly) > 0 && readOnly[0] && result.Schema != 0 && !result.Complete {
		stage = "journal-readonly-recovery"
		err = fmt.Errorf("appc TTL: recovery pending")
	}
	if err == nil && !result.Complete {
		writeStarted = result.Schema != 0
		stage = "journal-replay"
		err = applyConnectorIntent(st, k, result, adapter)
		if err == nil && result.Schema != 0 {
			result.Complete = true
		}
	}
	var ledger *RouteLedger
	if err == nil {
		ledger, err = newRouteLedgerPolicy(f, adapter, s.Config().AutoIPv6.Enabled && !s.Config().AutoIPv6.Publish)
		stage = "ledger-open"
	}
	if err == nil && ledger.state.Pending {
		stage = "ledger-recovery"
		if len(readOnly) > 0 && readOnly[0] {
			err = fmt.Errorf("appc TTL: ledger recovery pending")
		} else {
			err = ledger.Recover()
		}
	}
	if err == nil && fn != nil {
		var v *connectorIntent
		result.ObservedPrefsSHA256 = fmt.Sprintf("%x", sha256.Sum256(next.ToBytes()))
		stage = "prepare"
		v, err = fn(result, ledger, current)
		if err == nil && v != nil {
			writeStarted = true
			v.BeforePrefsSHA256 = result.ObservedPrefsSHA256
			prospective := next.Clone()
			prospective.AdvertiseRoutes = slices.Clone(v.Desired)
			v.AfterPrefsSHA256 = fmt.Sprintf("%x", sha256.Sum256(prospective.ToBytes()))
			if v.Transition.Action == "reset" {
				v.ResetPrefsSHA256 = v.AfterPrefsSHA256
			} else if v.Transition.Action == "install" {
				v.ResetPrefsSHA256 = result.ResetPrefsSHA256
			}
			stage = "journal-write"
			if batch == nil {
				err = writeConnectorIntent(st, k, *v)
			}
			if err == nil {
				stage = "journal-apply"
				err = applyConnectorIntent(st, k, *v, adapter)
			}
			if err == nil {
				result = *v
				result.Complete = true
				ledger.state = v.Ledger
			}
		}
	}

	if err == nil && batch != nil {
		stage = "atomic-state-commit"
		err = atomicWriter.WriteStates(batch.updates)
	}
	if err == nil && cache != nil {
		raw, e := st.ReadState(connectorKey(k))
		if e == nil {
			cache.raw = bytes.Clone(raw)
			cache.value = result
		}
	}
	if err != nil {
		err = wrapConnectorCommit(stage, writeStarted, err)
	}
	b.mu.Lock()
	if err == nil {
		if durable != nil {
			b.installCommittedRoutePrefsLocked(durable)
		}
		b.unifiedOwners = ledger.Owners()
		b.unifiedOwnersProfile = f.ProfileID
		b.clearUnifiedIssueLocked(unifiedCauseOwner, nil)
		b.unifiedStatus.Degraded = b.unifiedDegradedFromHealthLocked()
	} else {
		if writeStarted {
			b.unifiedTTLBlocked = true
		}
		b.noteUnifiedIssueLocked(unifiedCauseOwner, err)
		b.unifiedStatus.Applied = featurepolicy.Fence{}
		b.unifiedStatus.Reconciling = true
		b.unifiedStatus.Degraded = b.unifiedDegradedFromHealthLocked()
	}
	b.unifiedPrefsPending = nil
	b.unifiedPrefsPendingSince = time.Time{}
	close(done)
	b.mu.Unlock()
	return result, err
}

func connectorBackendHash(v connectorIntent, l *RouteLedger, current []netip.Prefix) string {
	b, _ := json.Marshal(struct {
		PrefsHash string
		State     appc.ConnectorTTLState
		Ledger    routeLedgerState
		Prefs     []netip.Prefix
		Unclaimed appctype.RouteInfo
	}{v.ObservedPrefsSHA256, v.Transition.After, l.state, sortedRoutes(current), v.Unclaimed})
	return fmt.Sprintf("%x", sha256.Sum256(b))
}
func (a *connectorBackend) commit(t appc.ConnectorTTLTransition) error {
	if a.detached {
		return a.commitDetachedHandoff(t)
	}
	// Handoff is performed under the newly disabled policy fence, while the
	// retiring Connector still carries its previous fence.
	f := t.After.Fence
	if t.Action == "handoff" {
		a.b.mu.Lock()
		f = a.b.unifiedSnapshot.Fence()
		a.b.mu.Unlock()
	}
	var cache *connectorIntentCache
	if t.Action == "dns" {
		cache = &a.dnsCache
	}
	_, err := a.b.connectorTransactionCached(f, func(v connectorIntent, l *RouteLedger, current []netip.Prefix) (*connectorIntent, error) {
		if a.expected != "" && a.expected != connectorBackendHash(v, l, current) {
			return nil, fmt.Errorf("appc TTL: backend approval CAS conflict")
		}
		if t.Action == "install" && (v.Schema == 0 || v.Handoff) {
			raw, e := a.b.pm.store.ReadState(a.b.pm.CurrentProfile().Key() + "||_routeInfo")
			if e == nil {
				if json.Unmarshal(raw, &v.Unclaimed) != nil {
					return nil, fmt.Errorf("appc TTL: invalid legacy RouteInfo")
				}
			} else if !errors.Is(e, ipn.ErrStateNotExist) {
				return nil, e
			}
		}
		return prepareConnectorImport(v, l, current, t, a.claims, a.approval, f, a.manifest)
	}, cache)
	return err
}

// ConnectorRoutePlan includes exact route effects and per-reference provenance.
// Hash binds both authorities, prefs, source lifetime and the selected claims.
type ConnectorRoutePlan struct {
	ManifestSHA256   string `json:",omitempty"`
	ManifestSource   string `json:",omitempty"`
	LegacySourceID   uint64
	EvidenceSource   string
	Fence            featurepolicy.Fence
	SourceID         uint64
	Revision         uint64
	SnapshotHash     string
	ConnectorHash    string
	Source           string
	Domains          map[string][]netip.Addr
	Roots            []string
	Control          []netip.Prefix
	Withdraw, Retain []netip.Prefix
	Entries          []ConnectorProvenance
	RetainReasons    map[netip.Prefix][]string
}
type ConnectorProvenance struct {
	Proof     *appc.ControlProofEntry `json:",omitempty"`
	Reference appc.LegacyDNSReference
	Prefix    netip.Prefix
	Eligible  bool
	Reason    string
}

func rootForDomain(roots []string, d string) string {
	for _, r := range roots {
		if d == r || strings.HasPrefix(r, "*.") && strings.HasSuffix(d, r[1:]) && d != r[2:] {
			return r
		}
	}
	return ""
}
func planConnector(v connectorIntent, l *RouteLedger, current []netip.Prefix, source string, adopt bool) ConnectorRoutePlan {
	s := v.Transition.After
	p := ConnectorRoutePlan{LegacySourceID: v.Unclaimed.SourceID, EvidenceSource: "persisted RouteInfo.Domains", Fence: s.Fence, SourceID: s.SourceID, Revision: s.Revision, Source: source, ConnectorHash: s.Hash(), Domains: s.RouteInfo().Domains, Roots: s.Roots, Control: s.Control}
	state := cloneLedger(l.state)
	if adopt {
		domains := make([]string, 0, len(v.Unclaimed.Domains))
		for d := range v.Unclaimed.Domains {
			domains = append(domains, d)
		}
		slices.Sort(domains)
		for _, d := range domains {
			ips := slices.Clone(v.Unclaimed.Domains[d])
			slices.SortFunc(ips, func(a, b netip.Addr) int { return a.Compare(b) })
			for _, ip := range slices.Compact(ips) {
				r := rootForDomain(s.Roots, d)
				prefix := netip.PrefixFrom(ip, ip.BitLen())
				o := state.Owners[prefix]
				e := ConnectorProvenance{Reference: appc.LegacyDNSReference{AssignedRoot: r, Domain: d, IP: ip}, Prefix: prefix, Eligible: true, Reason: "persisted RouteInfo.Domains; unknown TTL; explicit claim required"}
				if r == "" || !allowedAutoRoute(prefix) {
					e.Eligible = false
					e.Reason = "unassigned or invalid address"
				} else if slices.Contains(s.Control, prefix) {
					e.Eligible = false
					e.Reason = "current static control"
				} else if o.Manual || o.ExitDefault {
					e.Reason = "learning may be adopted; manual/Exit Node advertisement retained"
				} else if len(o.Control) > 0 || len(o.Auto) > 1 {
					e.Reason = "learning may be adopted; shared owners retained"
				}
				p.Entries = append(p.Entries, e)
			}
		}
	} else {
		for prefix, o := range state.Owners {
			delete(o.Auto, "appc-ttl")
			state.Owners[prefix] = o
		}
		desired := desiredRoutes(state, current)
		for _, prefix := range current {
			if slices.Contains(desired, prefix) {
				p.Retain = append(p.Retain, prefix)
			} else {
				p.Withdraw = append(p.Withdraw, prefix)
			}
		}
	}
	if adopt {
		p.Retain = sortedRoutes(current)
	}
	p.Withdraw, p.Retain = sortedRoutes(p.Withdraw), sortedRoutes(p.Retain)
	p.RetainReasons = map[netip.Prefix][]string{}
	for _, prefix := range p.Retain {
		o := l.state.Owners[prefix]
		var reasons []string
		if o.Manual {
			reasons = append(reasons, "manual")
		}
		if o.ExitDefault || prefix.Bits() == 0 {
			reasons = append(reasons, "Exit Node")
		}
		if len(o.Control) > 0 {
			reasons = append(reasons, "static/control owner")
		}
		if o.LegacyUnknown || !o.CreatedByModule {
			reasons = append(reasons, "unknown or unclaimed")
		}
		for id := range o.Auto {
			if id != "appc-ttl" {
				reasons = append(reasons, "shared automatic owner: "+id)
			}
		}
		slices.Sort(reasons)
		if len(reasons) == 0 {
			reasons = []string{"retained by preview action"}
		}
		p.RetainReasons[prefix] = reasons
	}
	// Hash includes audit source: execute must use the source reviewed in preview.
	raw, _ := json.Marshal(struct {
		Backend string
		Plan    ConnectorRoutePlan
	}{connectorBackendHash(v, l, current), p})
	p.SnapshotHash = fmt.Sprintf("%x", sha256.Sum256(raw))
	return p
}

func (b *LocalBackend) connectorAction(r *unifiedPolicyRuntime, action string, req UnifiedDebugRequest) (ConnectorRoutePlan, error) {
	var plan ConnectorRoutePlan
	s := r.manager.Current()
	if r.connector == nil || r.connectorAdapter == nil || r.ownerSnapshot != s {
		return plan, fmt.Errorf("appc TTL: consumer unavailable")
	}
	if strings.TrimSpace(req.Source) == "" || len(req.Source) > 200 {
		return plan, fmt.Errorf("appc TTL: audit source required for preview and execute")
	}
	adopt := strings.HasPrefix(action, "appc-route-adopt")
	preview := strings.HasSuffix(action, "-preview")
	if req.Manifest != nil && !adopt {
		return plan, fmt.Errorf("appc TTL: manifest requires adoption")
	}
	var saved connectorIntent
	var backendHash string
	var ownershipHash string
	_, err := b.connectorTransaction(s.Fence(), func(v connectorIntent, l *RouteLedger, current []netip.Prefix) (*connectorIntent, error) {
		saved = v
		ownershipHash = connectorOwnershipHash(l.state)
		plan = planConnector(v, l, current, req.Source, adopt)
		if adopt {
			var e error
			plan, e = planConnectorImport(v, l, current, req.Source, req.Manifest)
			if e != nil {
				return nil, e
			}
		}
		backendHash = connectorBackendHash(v, l, current)
		if !preview && (req.ExpectSHA256 != plan.SnapshotHash || req.ExpectGeneration != plan.Fence.Generation || req.ExpectSourceID != plan.SourceID) {
			return nil, fmt.Errorf("appc TTL: preview CAS conflict")
		}
		return nil, nil
	}, true)
	if err != nil || preview {
		return plan, err
	}
	a := r.connectorAdapter
	a.expected = backendHash
	a.manifest = req.Manifest
	a.approval = req.ExpectSHA256
	defer func() { a.expected = ""; a.claims = nil; a.manifest = nil; a.approval = "" }()
	switch action {
	case "appc-route-reset":
		err = r.connector.ResetTTL(plan.ConnectorHash, plan.Fence.Generation, req.Source)
	case "appc-route-reset-rollback":
		if saved.Reset == nil || saved.ResetLedgerHash != ownershipHash || saved.ResetPrefsSHA256 != saved.ObservedPrefsSHA256 {
			return plan, fmt.Errorf("appc TTL: rollback checkpoint invalidated")
		}
		err = r.connector.RestoreTTLReset(plan.ConnectorHash, req.Source, saved.Reset.Before, saved.Reset.BeforeLeaseState)
	case "appc-route-adopt":
		if len(req.Claims) == 0 {
			return plan, fmt.Errorf("appc TTL: explicit reference claims required")
		}
		for _, claim := range req.Claims {
			found := false
			for _, entry := range plan.Entries {
				if entry.Eligible && entry.Reference == claim {
					found = true
					break
				}
			}
			if !found || slices.Contains(a.claims, claim) {
				return plan, fmt.Errorf("appc TTL: invalid provenance claim")
			}
			a.claims = append(a.claims, claim)
		}
		err = r.connector.AdoptTTL(plan.ConnectorHash, req.Source, a.claims)
	default:
		return plan, fmt.Errorf("appc TTL: unknown action")
	}
	return plan, err
}

func connectorOwnershipHash(s routeLedgerState) string {
	raw, _ := json.Marshal(struct {
		Owners  map[netip.Prefix]PrefixOwners
		Desired []netip.Prefix
	}{s.Owners, s.Desired})
	return fmt.Sprintf("%x", sha256.Sum256(raw))
}

// finishConnectorHandoff also handles a restart after accepting all-off but
// before the retiring Connector could perform its final durable transition.
func (b *LocalBackend) finishConnectorHandoff(f featurepolicy.Fence) error {
	b.mu.Lock()
	b.waitUnifiedPrefsTransactionLocked()
	needed := b.unifiedOwnership
	b.mu.Unlock()
	if !needed {
		return nil
	}
	_, err := b.connectorTransaction(f, func(v connectorIntent, l *RouteLedger, current []netip.Prefix) (*connectorIntent, error) {
		if v.Schema == 0 || v.Handoff {
			return nil, nil
		}
		v.Complete = false
		v.Handoff = true
		v.Before = sortedRoutes(current)
		v.Desired = sortedRoutes(current)
		v.Ledger = cloneLedger(l.state)
		v.Ledger.Desired = v.Desired
		v.Transition.Before = v.Transition.After
		v.Transition.BeforeLeaseState = v.Transition.AfterLeaseState
		v.Transition.After.Revision++
		v.Transition.Action = "handoff"
		v.Transition.Source = "disabled-policy-recovery"
		v.Reset = nil
		v.ResetLedgerHash = ""
		return &v, nil
	})
	return err
}

// prepareConnectorTransition is shared by the daemon adapter and crash matrix.
// It is pure with respect to durable state; only applyConnectorIntent writes.
func prepareConnectorTransition(v connectorIntent, l *RouteLedger, current []netip.Prefix, t appc.ConnectorTTLTransition, claims []appc.LegacyDNSReference, approvalHash string, f featurepolicy.Fence) (*connectorIntent, error) {
	if t.Action != "install" && !v.Transition.After.Equal(t.Before) {
		return nil, fmt.Errorf("appc TTL: state CAS conflict")
	}
	if t.Action == "install" && v.Schema != 0 && !v.Handoff && t.Before.Revision != v.Transition.After.Revision {
		return nil, fmt.Errorf("appc TTL: restore revision conflict")
	}
	beforeRaw, _ := json.Marshal(v.Unclaimed)
	var beforeUnclaimed appctype.RouteInfo
	_ = json.Unmarshal(beforeRaw, &beforeUnclaimed)
	state := cloneLedger(l.state)
	// After a completed handoff, prefs are authoritative again. An operator
	// may clear routes while ownership is disabled. Stale protected owners
	// must not resurrect those withdrawn prefixes on the next installation.
	if t.Action == "install" && v.Handoff {
		present := make(map[netip.Prefix]bool, len(current))
		for _, p := range current {
			present[p] = true
		}
		for p := range state.Owners {
			if !present[p] {
				delete(state.Owners, p)
			}
		}
		// Legacy RouteInfo persistence is best-effort. It can still contain a
		// cleared address after prefs have durably withdrawn it. Drop that
		// provenance too; otherwise a later genuine DNS observation inherits
		// LegacyUnknown again on the following transaction and never expires.
		retained := make(map[string][]netip.Addr)
		for domain, ips := range v.Unclaimed.Domains {
			for _, ip := range ips {
				if present[netip.PrefixFrom(ip, ip.BitLen())] {
					retained[domain] = append(retained[domain], ip)
				}
			}
		}
		v.Unclaimed.Domains = retained
	}
	protectExternal(&state, current)

	for p, o := range state.Owners {
		// The previous independent producer is retired, never run in parallel.
		if t.Action == "install" && (v.Schema == 0 || v.Handoff) && len(o.Auto) > 0 {
			found := false
			for _, ips := range t.After.RouteInfo().Domains {
				if slices.Contains(ips, p.Addr()) {
					found = true
				}
			}
			if !found {
				o.LegacyUnknown = true
			}
		}
		delete(o.Auto, "leases")
		delete(o.Auto, "appc-ttl")
		for id := range o.Auto {
			if strings.HasPrefix(id, "dns/") {
				delete(o.Auto, id)
			}
		}
		if o.Control["appc-control"] && !slices.Contains(t.After.Control, p) && t.Action == "install" {
			o.Control["appc-legacy-control"] = true
		}
		delete(o.Control, "appc-control")
		state.Owners[p] = o
	}
	if t.Action == "adopt" {
		for _, ref := range claims {
			p := netip.PrefixFrom(ref.IP, ref.IP.BitLen())
			o := state.Owners[p]
			if !slices.Contains(v.Unclaimed.Domains[ref.Domain], ref.IP) || slices.Contains(t.After.Control, p) {
				return nil, fmt.Errorf("appc TTL: provenance changed")
			}
			// Explicit preview-bound claim removes only legacy ambiguity, never a
			// manual/default/static/other owner's contribution.
			o.LegacyUnknown = false
			delete(o.Control, "appc-legacy-control")
			o.CreatedByModule = true
			state.Owners[p] = o
			v.Unclaimed.Domains[ref.Domain] = slices.DeleteFunc(v.Unclaimed.Domains[ref.Domain], func(ip netip.Addr) bool { return ip == ref.IP })
		}
	}
	for _, ips := range v.Unclaimed.Domains {
		for _, ip := range ips {
			p := netip.PrefixFrom(ip, ip.BitLen())
			if slices.Contains(current, p) {
				o := state.Owners[p]
				o.LegacyUnknown = true
				state.Owners[p] = o
			}
		}
	}
	for _, p := range t.After.Control {
		o := state.Owners[p]
		if o.Control == nil {
			o.Control = map[string]bool{}
		}
		o.Control["appc-control"] = true
		state.Owners[p] = o
	}
	ri := t.After.RouteInfo()
	for _, ips := range ri.Domains {
		for _, ip := range ips {
			p := netip.PrefixFrom(ip, ip.BitLen())
			if !allowedAutoRoute(p) {
				continue
			}
			o := state.Owners[p]
			if o.Auto == nil {
				o.Auto = map[string]bool{}
			}
			o.Auto["appc-ttl"] = true
			state.Owners[p] = o
		}
	}
	state.Sequence++
	state.Fence = f
	state.Before = sortedRoutes(current)
	l.filterAutomatic(&state)
	state.Desired = desiredRoutes(state, current)
	for _, p := range state.Desired {
		if !slices.Contains(current, p) {
			o := state.Owners[p]
			o.CreatedByModule = true
			state.Owners[p] = o
		}
	}
	state.Applied = state.Sequence
	state.Pending = false
	if t.Action == "handoff" || t.Action == "adopt" {
		state.Desired = sortedRoutes(current)
	}
	out := connectorIntent{ImportProofs: v.ImportProofs, BeforeLedger: cloneLedger(l.state), BeforeUnclaimed: beforeUnclaimed, Claims: slices.Clone(claims), Schema: 2, Transition: t, Before: sortedRoutes(current), Desired: state.Desired, Ledger: state, Unclaimed: v.Unclaimed, Reset: v.Reset, ResetLedgerHash: v.ResetLedgerHash, Handoff: t.Action == "handoff", ApprovalHash: approvalHash}
	if t.Action == "reset" {
		copy := t
		out.Reset = &copy
		out.ResetLedgerHash = connectorOwnershipHash(state)
	} else if t.Action != "install" {
		out.Reset = nil
		out.ResetLedgerHash = ""
	}
	return &out, nil
}

// A profile switch has already moved pm. Retire the old lifecycle using only
// its captured store namespace; never use the new profile's prefs or identity.
func (a *connectorBackend) commitDetachedHandoff(t appc.ConnectorTTLTransition) error {
	if t.Action != "handoff" || a.store == nil || a.key == "" {
		return fmt.Errorf("appc TTL: detached source")
	}
	b := a.b
	b.mu.Lock()
	b.waitUnifiedPrefsTransactionLocked()
	done := make(chan struct{})
	b.unifiedPrefsPending = done
	b.unifiedPrefsPendingSince = time.Now()
	b.mu.Unlock()
	defer func() {
		b.mu.Lock()
		b.unifiedPrefsPending = nil
		b.unifiedPrefsPendingSince = time.Time{}
		close(done)
		b.mu.Unlock()
	}()
	v, err := readConnectorIntent(a.store, a.key)
	if err != nil {
		return err
	}
	if !v.Complete || !v.Transition.After.Equal(t.Before) {
		return fmt.Errorf("appc TTL: detached handoff recovery required")
	}
	raw, err := a.store.ReadState(a.key)
	if err != nil {
		return err
	}
	prefs := ipn.NewPrefs()
	if err = ipn.PrefsFromBytes(raw, prefs); err != nil {
		return err
	}
	current := sortedRoutes(prefs.AdvertiseRoutes)
	adapter := UnifiedLedgerStore{Store: a.store, ProfileKey: a.key, ReadPrefs: func() ([]netip.Prefix, error) { return current, nil }, ApplyPrefs: func(before, desired []netip.Prefix) error {
		if !slices.Equal(current, desired) {
			return fmt.Errorf("appc TTL: detached handoff changed routes")
		}
		return nil
	}}
	l, err := NewRouteLedger(t.After.Fence, adapter)
	if err != nil {
		return err
	}
	if l.state.Pending {
		return fmt.Errorf("appc TTL: detached ledger pending")
	}
	v.Complete = false
	v.Handoff = true
	v.Transition = t
	v.Before = current
	v.Desired = current
	v.Ledger = cloneLedger(l.state)
	v.Ledger.Desired = current
	v.Reset = nil
	v.ResetLedgerHash = ""
	if err = writeConnectorIntent(a.store, a.key, v); err != nil {
		return err
	}
	return applyConnectorIntent(a.store, a.key, v, adapter)
}
