// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package appc

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"tailscale.com/featurepolicy"
	"tailscale.com/types/appctype"
	"tailscale.com/util/clientmetric"
)

// LegacyDNSReference is reviewed Connector learning with no observed TTL.
// Import is not authority to remove an unknown/manual backend owner.
type LegacyDNSReference struct {
	AssignedRoot string
	Domain       string
	IP           netip.Addr
}

// ConnectorTTLState is the complete learning authority, not a route publisher.
// Static control routes and assigned roots are configuration, never TTL leases.
type ConnectorTTLState struct {
	Fence    featurepolicy.Fence
	SourceID uint64
	Revision uint64
	Roots    []string
	Control  []netip.Prefix
	Legacy   []LegacyDNSReference
	Leases   []Lease
}

// ConnectorTTLTransition must be committed by the backend's single writer.
// Commit must durably journal the after-image before changing prefs; explicit
// administrative transitions also carry the before-book for reset undo. It must
// preserve all non-Connector owners, and check the complete backend CAS. A
// returned error quarantines the lifecycle, even if no write actually occurred.
// Implementations must not call back into this lifecycle or hold AppConnector.mu.
type ConnectorTTLTransition struct {
	Before           ConnectorTTLState
	After            ConnectorTTLState
	BeforeLeaseState []byte
	AfterLeaseState  []byte
	Action           string
	Source           string
}

// ErrTTLCommitNotStarted may only be returned by a backend that rejected the
// fence before starting any persistence. It permits replacement of a failed
// initial installation and retry with a newer fence; all uncertain/partial
// writes still require recovery. Callers must not treat it as a permanent
// lifecycle failure: a later ConfigureTTL with a fresh fence may converge.
var ErrTTLCommitNotStarted = errors.New("appc TTL: commit not started")

// ErrTTLStaleObservation reports an observer whose captured fence or lease epoch
// no longer matches the installed consumer. Nothing was written; the request is
// expected to fail and the caller retries with a fresh capture.
var ErrTTLStaleObservation = errors.New("appc TTL: stale observation fence")

// metricTTLObserveSkipped counts observations that only refreshed an already
// healthy lease and therefore did not rewrite the durable ownership
// transaction. The remaining TTL is still at least half the observed TTL.
var metricTTLObserveSkipped = clientmetric.NewCounter("appc_ttl_observe_skipped_refresh")
var metricTTLRefreshDeferred = clientmetric.NewCounter("appc_ttl_refresh_deferred")
var metricTTLRefreshFlushed = clientmetric.NewCounter("appc_ttl_refresh_flushed")

// ttlRefreshInterval bounds how long a repeat-observer lease refresh can be
// deferred. The durable expiry is extended well before it can run out.
const ttlRefreshInterval = 5 * time.Second

// TTLCommitPhase classifies where a rejected durable transition stopped.
// prewrite means no persistence started (safe to retry with a new fence);
// uncertain means write may have started and the lifecycle stays quarantined.
type TTLCommitPhase string

const (
	TTLCommitPrewrite  TTLCommitPhase = "prewrite"
	TTLCommitUncertain TTLCommitPhase = "uncertain"
)

// TTLTransitionError carries the lifecycle identity of a rejected transition so
// logs and status can report a cause, action, fence, revision, lease epoch and
// write phase instead of only a generation number.
type TTLTransitionError struct {
	Phase    TTLCommitPhase
	Action   string
	Source   string
	Fence    featurepolicy.Fence
	Revision uint64
	Epoch    uint64
	Err      error
}

func (e *TTLTransitionError) Error() string {
	if e.Phase == TTLCommitPrewrite {
		return fmt.Sprintf("appc TTL: prewrite reject action=%s: %v", e.Action, e.Err)
	}
	return fmt.Sprintf("appc TTL: commit uncertain action=%s: %v", e.Action, e.Err)
}

func (e *TTLTransitionError) Unwrap() error { return e.Err }

type ConnectorTTLCommit func(ConnectorTTLTransition) error

// ConnectorTTLConfig is internal integration input. Legacy must come from a
// reviewed source manifest, not arbitrary AdvertiseRoutes or RouteInfo.Control.
// Restore bytes use the existing lease checksum/time-uncertainty rules.
type ConnectorTTLConfig struct {
	Fence    featurepolicy.Fence
	Revision uint64
	Roots    []string
	Control  []netip.Prefix
	Legacy   []LegacyDNSReference
	Options  LeaseOptions
	Now      func() time.Time
	Restore  []byte
	Commit   ConnectorTTLCommit
}

type connectorTTL struct {
	installIncomplete bool
	epoch             uint64
	mu                sync.Mutex
	state             ConnectorTTLState
	book              *LeaseBook
	commit            ConnectorTTLCommit
	project           func(ConnectorTTLState)
	blocked           error
	resetBefore       *ConnectorTTLState
	resetBook         *LeaseBook
	resetAfterHash    string

	// Observability only. Guarded by mu; never used to make lifecycle decisions
	// except blocked/cause classification. The atomic flag is a lock-free mirror
	// for status projections that run under an unrelated lock.
	blockedFlag     *atomic.Bool
	blockedPhase    TTLCommitPhase
	blockedAction   string
	blockedFence    featurepolicy.Fence
	blockedRev      uint64
	blockedEpoch    uint64
	prewriteRejects uint64
	lastPrewrite    *TTLTransitionError
	lastSuccess     *TTLTransitionError

	// pending holds refresh-only observations (existing lease still healthy at
	// enqueue time). A background refresher merges them into one durable
	// transaction so DNS replies never wait behind the whole-state rewrite.
	refreshStop chan struct{}
	refreshDone chan struct{}
	pending     map[LeaseKey]time.Duration
}

func ttlRootMatches(root, name string) bool {
	if strings.HasPrefix(root, "*.") {
		return strings.HasSuffix(name, root[1:]) && name != root[2:]
	}
	return root == name
}

func newConnectorTTL(id uint64, c ConnectorTTLConfig, project func(ConnectorTTLState), blockedFlag *atomic.Bool) (*connectorTTL, error) {
	if id == 0 || c.Fence.ProfileID == "" || c.Commit == nil {
		return nil, fmt.Errorf("appc TTL: missing source, profile or transaction adapter")
	}
	b := NewLeaseBook(c.Fence, c.Options, c.Now)
	if len(c.Restore) != 0 {
		var err error
		b, err = RestoreLeaseBook(c.Restore, c.Fence, c.Options, c.Now)
		if err != nil {
			return nil, err
		}
	}
	s := ConnectorTTLState{Revision: c.Revision, Fence: c.Fence, SourceID: id, Roots: slices.Clone(c.Roots), Control: slices.Clone(c.Control), Legacy: slices.Clone(c.Legacy), Leases: b.Snapshot()}
	for _, root := range s.Roots {
		canonical, err := featurepolicy.NormalizeDomain(root)
		if err != nil || canonical != root {
			return nil, fmt.Errorf("appc TTL: noncanonical root")
		}
	}
	slices.Sort(s.Roots)
	s.Roots = slices.Compact(s.Roots)
	slices.SortFunc(s.Control, func(a, b netip.Prefix) int { return a.Compare(b) })
	s.Control = slices.Compact(s.Control)
	for _, p := range s.Control {
		if !p.IsValid() || p != p.Masked() || p.Addr().Is4In6() {
			return nil, fmt.Errorf("appc TTL: invalid control prefix")
		}
	}
	for _, r := range s.Legacy {
		canonical, err := featurepolicy.NormalizeDomain(r.Domain)
		if err != nil || canonical != r.Domain || strings.HasPrefix(r.Domain, "*.") {
			return nil, fmt.Errorf("appc TTL: invalid legacy domain")
		}
		if !r.IP.IsValid() || r.IP.Is4In6() || !slices.Contains(s.Roots, r.AssignedRoot) || !ttlRootMatches(r.AssignedRoot, r.Domain) {
			return nil, fmt.Errorf("appc TTL: invalid legacy reference")
		}
	}
	if len(s.Legacy)+len(s.Leases) > c.Options.MaxEntries {
		return nil, fmt.Errorf("appc TTL: import capacity")
	}
	slices.SortFunc(s.Legacy, func(a, b LegacyDNSReference) int {
		if n := strings.Compare(a.AssignedRoot, b.AssignedRoot); n != 0 {
			return n
		}
		if n := strings.Compare(a.Domain, b.Domain); n != 0 {
			return n
		}
		return a.IP.Compare(b.IP)
	})
	s.Legacy = slices.Compact(s.Legacy)
	for _, l := range s.Leases {
		if !slices.Contains(s.Roots, l.Key.AssignedRoot) {
			return nil, fmt.Errorf("appc TTL: restored lease outside assignment")
		}
	}
	return &connectorTTL{state: s, book: b, commit: c.Commit, project: project, blockedFlag: blockedFlag}, nil
}

func cloneTTLState(s ConnectorTTLState) ConnectorTTLState {
	s.Roots = slices.Clone(s.Roots)
	s.Control = slices.Clone(s.Control)
	s.Legacy = slices.Clone(s.Legacy)
	s.Leases = slices.Clone(s.Leases)
	return s
}

// Equal compares complete durable state without serializing and hashing the
// large lease table twice. Monotonic timestamps are process-local and are not
// part of JSON persistence. All other fields remain part of this CAS.
func (s ConnectorTTLState) Equal(other ConnectorTTLState) bool {
	if s.Fence != other.Fence || s.SourceID != other.SourceID || s.Revision != other.Revision || !slices.Equal(s.Roots, other.Roots) || !slices.Equal(s.Control, other.Control) || !slices.Equal(s.Legacy, other.Legacy) {
		return false
	}
	wall := func(l Lease) Lease {
		l.LastObserved = l.LastObserved.UTC().Round(0)
		l.Expires = l.Expires.UTC().Round(0)
		l.GraceUntil = l.GraceUntil.UTC().Round(0)
		l.AbsoluteRetainUntil = l.AbsoluteRetainUntil.UTC().Round(0)
		l.FirstAdvertised = l.FirstAdvertised.UTC().Round(0)
		return l
	}
	return slices.EqualFunc(s.Leases, other.Leases, func(a, b Lease) bool { return wall(a) == wall(b) })
}

func (s ConnectorTTLState) Hash() string {
	b, _ := json.Marshal(s)
	return fmt.Sprintf("%x", sha256.Sum256(b))
}

// RouteInfo is a derived compatibility view, including configuration so a
// reset never leaves the Connector permanently unable to learn again.
func (s ConnectorTTLState) RouteInfo() appctype.RouteInfo {
	ri := appctype.RouteInfo{SourceID: s.SourceID, Control: slices.Clone(s.Control), Domains: map[string][]netip.Addr{}}
	for _, r := range s.Roots {
		if strings.HasPrefix(r, "*.") {
			ri.Wildcards = append(ri.Wildcards, r[2:])
		} else {
			ri.Domains[r] = nil
		}
	}
	for _, r := range s.Legacy {
		ri.Domains[r.Domain] = append(ri.Domains[r.Domain], r.IP)
	}
	for _, l := range s.Leases {
		ri.Domains[l.Key.QName] = append(ri.Domains[l.Key.QName], l.Key.IP)
	}
	for d, ips := range ri.Domains {
		slices.SortFunc(ips, compareAddr)
		ri.Domains[d] = slices.Compact(ips)
	}
	return ri
}

func (t *connectorTTL) apply(next ConnectorTTLState, book *LeaseBook, action, source string) error {
	if t.blocked != nil {
		return t.blocked
	}
	transition := TTLTransitionError{Phase: TTLCommitUncertain, Action: action, Source: source, Fence: t.state.Fence, Revision: t.state.Revision, Epoch: t.epoch}
	var beforeBytes []byte
	var err error
	// DNS/expiry changes replay their after-image on recovery. Only explicit
	// lifecycle/administrative changes need the serialized before-book (reset
	// undo in particular). The before state itself remains for the CAS check.
	if action != "dns" && action != "sweep" && action != "refresh" && action != "dns-refresh" {
		beforeBytes, err = t.book.MarshalState()
	}
	if err != nil {
		transition.Phase = TTLCommitPrewrite
		transition.Err = err
		return &transition
	}
	afterBytes, err := book.MarshalState()
	if err != nil {
		transition.Phase = TTLCommitPrewrite
		transition.Err = err
		return &transition
	}
	next.Revision = t.state.Revision + 1
	next.Leases = book.Snapshot()
	err = t.commit(ConnectorTTLTransition{cloneTTLState(t.state), cloneTTLState(next), beforeBytes, afterBytes, action, source})
	if err != nil {
		transition.Err = err
		if errors.Is(err, ErrTTLCommitNotStarted) {
			// The backend rejected the fence before any persistence. This is a
			// retryable condition, not a permanent quarantine: the committed
			// state/book stay untouched and a later ConfigureTTL with a fresh
			// fence may converge. Only errors that may have written are fatal.
			transition.Phase = TTLCommitPrewrite
			t.prewriteRejects++
			t.lastPrewrite = &transition
			return &transition
		}
		t.blocked = fmt.Errorf("appc TTL: recovery required: %w", err)
		t.blockedPhase, t.blockedAction = TTLCommitUncertain, action
		t.blockedFence, t.blockedRev, t.blockedEpoch = transition.Fence, transition.Revision, transition.Epoch
		t.setBlockedFlag(true)
		return t.blocked
	}
	t.state, t.book = next, book
	t.lastSuccess = &transition
	t.setBlockedFlag(false)
	t.project(cloneTTLState(next))
	return nil
}

func (t *connectorTTL) setBlockedFlag(v bool) {
	if t.blockedFlag != nil {
		t.blockedFlag.Store(v)
	}
}

// startRefresher runs one bounded background loop that merges deferred refresh
// observations into a single transaction. It never delays a DNS reply and is
// stopped before the lifecycle is replaced or handed off.
func (t *connectorTTL) startRefresher() {
	if t.refreshStop != nil {
		return
	}
	t.refreshStop = make(chan struct{})
	t.refreshDone = make(chan struct{})
	go func() {
		defer close(t.refreshDone)
		ticker := time.NewTicker(ttlRefreshInterval)
		defer ticker.Stop()
		for {
			select {
			case <-t.refreshStop:
				return
			case <-ticker.C:
				t.flushRefresh()
			}
		}
	}()
}

func (t *connectorTTL) stopRefresher() {
	if t.refreshStop == nil {
		return
	}
	close(t.refreshStop)
	<-t.refreshDone
	t.refreshStop, t.refreshDone = nil, nil
}

// flushRefresh commits merged refresh-only observations. It drops entries for
// roots/fences that no longer apply and never retries after an uncertain error
// (the observation will be re-queued by the next matching DNS answer).
func (t *connectorTTL) flushRefresh() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.blocked != nil || len(t.pending) == 0 {
		return
	}
	pending := t.pending
	t.pending = nil
	next, book := cloneTTLState(t.state), t.book.clone()
	now := book.now()
	for k, ttl := range pending {
		if !slices.Contains(next.Roots, k.AssignedRoot) || !ttlRootMatches(k.AssignedRoot, k.QName) {
			continue
		}
		if err := book.Observe(t.state.Fence, k, now, ttl); err != nil {
			continue
		}
	}
	if err := t.apply(next, book, "dns-refresh", "peerapi-dns-deferred"); err != nil {
		return
	}
	metricTTLRefreshFlushed.Add(1)
}

func (t *connectorTTL) observe(f featurepolicy.Fence, epoch uint64, obs []DNSLeaseObservation) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if f != t.state.Fence || epoch != t.epoch {
		return fmt.Errorf("%w: captured generation=%d assigned=%d identity=%d epoch=%d current generation=%d assigned=%d identity=%d epoch=%d", ErrTTLStaleObservation, f.Generation, f.AssignedDomainsEpoch, f.PeerIdentityEpoch, epoch, t.state.Fence.Generation, t.state.Fence.AssignedDomainsEpoch, t.state.Fence.PeerIdentityEpoch, t.epoch)
	}
	if len(obs) == 0 {
		// No lease evidence: never bump the revision or rewrite durable state.
		metricTTLObserveSkipped.Add(1)
		return nil
	}
	next, book := cloneTTLState(t.state), t.book.clone()
	now := book.now()
	legacyChanged := false
	keys := make([]LeaseKey, 0, len(obs))
	ttls := make([]time.Duration, 0, len(obs))
	for _, o := range obs {
		if !slices.Contains(next.Roots, o.AssignedRoot) || !ttlRootMatches(o.AssignedRoot, o.QName) {
			return fmt.Errorf("appc TTL: unassigned observation")
		}
		source := o.Source
		if source == "" {
			source = "peerapi-dns"
		}
		k := LeaseKey{ProfileID: f.ProfileID, AssignedRoot: o.AssignedRoot, QName: o.QName, Chain: o.Chain, IP: o.IP, Source: source}
		keys = append(keys, k)
		ttls = append(ttls, o.TTL)
		if err := book.Observe(f, k, now, o.TTL); err != nil {
			return err
		}
		before := len(next.Legacy)
		next.Legacy = slices.DeleteFunc(next.Legacy, func(r LegacyDNSReference) bool {
			return r.AssignedRoot == o.AssignedRoot && r.Domain == o.QName && r.IP == o.IP
		})
		if len(next.Legacy) != before {
			legacyChanged = true
		}
	}
	// A repeat answer for existing leases only extends expiry; it need not
	// block the DNS reply behind a whole-state rewrite. New leases, capacity
	// changes and legacy-to-lease transitions always commit inline below. The
	// refresher extends expiry every 5s, well inside the persistence grace
	// window, so a deferred refresh cannot let a live reference be removed.
	if !legacyChanged && t.book.HasLeases(keys) {
		// Reply now; extend the durable expiry from the background refresher.
		if t.pending == nil {
			t.pending = map[LeaseKey]time.Duration{}
		}
		for i, k := range keys {
			t.pending[k] = ttls[i]
		}
		metricTTLObserveSkipped.Add(1)
		metricTTLRefreshDeferred.Add(1)
		return nil
	}
	if len(next.Legacy)+len(book.leases) > book.opts.MaxEntries {
		return fmt.Errorf("appc TTL: capacity")
	}
	return t.apply(next, book, "dns", "peerapi-dns")
}

// SweepTTL expires Connector references and commits the complete learning view.
func (e *AppConnector) SweepTTL(f featurepolicy.Fence, limit int, activity ActivityProvider) error {
	t := e.ttl.Load()
	if t == nil {
		return fmt.Errorf("appc TTL: not installed")
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.blocked != nil {
		return t.blocked
	}
	if f != t.state.Fence {
		return fmt.Errorf("appc TTL: stale sweep fence")
	}
	book := t.book.clone()
	if removed := book.Sweep(f, limit, activity); len(removed) == 0 {
		// No expiry and no ownership change: a sweep must not rewrite durable
		// state, but it must keep the in-memory clock-jump state. Deferred lease
		// refreshes are committed by the refresher.
		t.book.AdoptSweepState(book)
		return nil
	}
	return t.apply(cloneTTLState(t.state), book, "sweep", "timer")
}

// ConnectorResetPlan describes learning removal only. Backend preview must add
// exact Withdraw/Retain decisions from its manual/static/unknown owner union.
type ConnectorResetPlan struct {
	SnapshotHash    string
	Fence           featurepolicy.Fence
	SourceID        uint64
	Revision        uint64
	Domains         map[string][]netip.Addr
	PreserveControl []netip.Prefix
	PreserveRoots   []string
}

func (t *connectorTTL) preview() ConnectorResetPlan {
	ri := t.state.RouteInfo()
	return ConnectorResetPlan{t.state.Hash(), t.state.Fence, t.state.SourceID, t.state.Revision, ri.Domains, slices.Clone(t.state.Control), slices.Clone(t.state.Roots)}
}

func (e *AppConnector) PreviewTTLReset() (ConnectorResetPlan, error) {
	t := e.ttl.Load()
	if t == nil {
		return ConnectorResetPlan{}, fmt.Errorf("appc TTL: not installed")
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.blocked != nil {
		return ConnectorResetPlan{}, t.blocked
	}
	return t.preview(), nil
}

func (e *AppConnector) ResetTTL(hash string, generation uint64, source string) error {
	t := e.ttl.Load()
	if t == nil {
		return fmt.Errorf("appc TTL: not installed")
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if hash != t.state.Hash() || generation != t.state.Fence.Generation || strings.TrimSpace(source) == "" || len(source) > 200 {
		return fmt.Errorf("appc TTL reset: CAS conflict or missing source")
	}
	before, oldBook := cloneTTLState(t.state), t.book.clone()
	next, book := cloneTTLState(t.state), t.book.clone()
	next.Legacy = nil
	book.leases = map[LeaseKey]Lease{}
	if err := t.apply(next, book, "reset", source); err != nil {
		return err
	}
	t.resetBefore, t.resetBook, t.resetAfterHash = &before, oldBook, t.state.Hash()
	// A captured pre-reset DNS response must not immediately resurrect learning.
	e.installTTLObserver(t)
	return nil
}

// RollbackTTLReset is a live CAS rollback. Durable restart recovery belongs to
// the backend journal; a caller cannot inject an arbitrary rollback snapshot.
func (e *AppConnector) RollbackTTLReset(hash string, generation uint64, source string) error {
	t := e.ttl.Load()
	if t == nil {
		return fmt.Errorf("appc TTL: not installed")
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.resetBefore == nil || hash != t.resetAfterHash || hash != t.state.Hash() || generation != t.state.Fence.Generation || strings.TrimSpace(source) == "" || len(source) > 200 {
		return fmt.Errorf("appc TTL rollback: CAS conflict")
	}
	if err := t.apply(cloneTTLState(*t.resetBefore), t.resetBook.clone(), "rollback", source); err != nil {
		return err
	}
	t.resetBefore = nil
	t.resetBook = nil
	t.resetAfterHash = ""
	e.installTTLObserver(t)
	return nil
}

// InstallTTLTakeover installs the Connector-owned lifecycle. The backend must
// quiesce legacy producers and validate its import manifest before calling it.
// No production backend adapter is installed by this API alone. The initial
// transition is durable before any DNS callback can acknowledge learning.
func (e *AppConnector) InstallTTLTakeover(c ConnectorTTLConfig) error {
	previous := e.ttl.Load()
	if previous != nil {
		previous.mu.Lock()
		// Only an installation that never became durable is replaceable. A
		// prewrite rejection leaves blocked unset (nothing was written); an
		// uncertain write still carries a non-nil blocked error.
		retry := previous.installIncomplete && (previous.blocked == nil || errors.Is(previous.blocked, ErrTTLCommitNotStarted))
		previous.mu.Unlock()
		if !retry {
			return fmt.Errorf("appc TTL: already installed")
		}
		previous.stopRefresher()
	}
	t, err := newConnectorTTL(e.sourceID, c, func(s ConnectorTTLState) {
		ri := s.RouteInfo()
		e.mu.Lock()
		defer e.mu.Unlock()
		e.domains, e.controlRoutes, e.wildcards = ri.Domains, ri.Control, ri.Wildcards
	}, &e.ttlBlocked)
	if err != nil {
		return err
	}
	t.installIncomplete = true
	// A rejected installation stays published as a quarantine until a fresh
	// backend replay/check supplies its replacement. Never reopen legacy DNS.
	// Lifecycle installation is serialized by the caller's transition barrier.
	// Publish a rejecting sink first; a failed import must not resume legacy DNS.
	t.mu.Lock()
	defer t.mu.Unlock()
	e.mu.Lock()
	if !e.ttl.CompareAndSwap(previous, t) {
		e.mu.Unlock()
		return fmt.Errorf("appc TTL: already installed")
	}
	e.leaseEpoch.Add(1)
	e.leaseSink.Store(&dnsLeaseSink{roots: slices.Clone(c.Roots), observe: func([]DNSLeaseObservation) error { return fmt.Errorf("appc TTL: installation incomplete") }})
	e.mu.Unlock()
	if err = t.apply(cloneTTLState(t.state), t.book.clone(), "install", "reviewed-import"); err != nil {
		return err
	}
	t.installIncomplete = false
	t.startRefresher()
	e.installTTLObserver(t)
	return nil
}

// installTTLObserver is called with the lifecycle writer excluded. Its epoch is
// checked again under that writer lock, closing the parse/reset/observe race.
func (e *AppConnector) installTTLObserver(t *connectorTTL) {
	e.mu.Lock()
	defer e.mu.Unlock()
	epoch := e.leaseEpoch.Add(1)
	t.epoch = epoch
	f := t.state.Fence
	e.leaseSink.Store(&dnsLeaseSink{roots: slices.Clone(t.state.Roots), observe: func(obs []DNSLeaseObservation) error { return t.observe(f, epoch, obs) }})
}

// ConfigureTTL replaces current assignment and static routes in the same
// transaction as learned state. The backend must fence its writer to f first.
func (e *AppConnector) ConfigureTTL(f featurepolicy.Fence, roots []string, control []netip.Prefix, options ...LeaseOptions) error {
	t := e.ttl.Load()
	if t == nil {
		return fmt.Errorf("appc TTL: not installed")
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	next, book := cloneTTLState(t.state), t.book.clone()
	for _, p := range control {
		if !p.IsValid() || p != p.Masked() || p.Addr().Is4In6() {
			return fmt.Errorf("appc TTL: invalid control prefix")
		}
	}
	for _, root := range roots {
		canonical, err := featurepolicy.NormalizeDomain(root)
		if err != nil || canonical != root {
			return fmt.Errorf("appc TTL: noncanonical root")
		}
	}
	if len(options) > 0 {
		book.opts = options[0]
	}
	next.Roots = slices.Clone(roots)
	slices.Sort(next.Roots)
	next.Roots = slices.Compact(next.Roots)
	next.Control = slices.Clone(control)
	slices.SortFunc(next.Control, func(a, b netip.Prefix) int { return a.Compare(b) })
	next.Control = slices.Compact(next.Control)
	if err := book.AdvanceFence(f, func(root string) bool { return slices.Contains(next.Roots, root) }); err != nil {
		return err
	}
	next.Fence = f
	next.Legacy = slices.DeleteFunc(next.Legacy, func(r LegacyDNSReference) bool { return !slices.Contains(next.Roots, r.AssignedRoot) })
	if err := t.apply(next, book, "configure", "netmap"); err != nil {
		return err
	}
	e.installTTLObserver(t)
	return nil
}

// ConfirmTTLTime records explicit trusted-time recovery in the same transaction.
// The administrative caller must authenticate source; wall time alone is not
// proof. No automatic restart path calls this method.
func (e *AppConnector) ConfirmTTLTime(f featurepolicy.Fence, source string) error {
	t := e.ttl.Load()
	if t == nil {
		return fmt.Errorf("appc TTL: not installed")
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if f != t.state.Fence || strings.TrimSpace(source) == "" || len(source) > 200 {
		return fmt.Errorf("appc TTL: invalid time confirmation")
	}
	book := t.book.clone()
	book.ConfirmTime()
	book.timeConfirmation = TimeConfirmation{source, book.now(), f}
	return t.apply(cloneTTLState(t.state), book, "confirm-time", source)
}

// TTLState returns a defensive committed snapshot. It never sweeps.
func (e *AppConnector) TTLState() (ConnectorTTLState, error) {
	t := e.ttl.Load()
	if t == nil {
		return ConnectorTTLState{}, fmt.Errorf("appc TTL: not installed")
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.blocked != nil {
		return ConnectorTTLState{}, t.blocked
	}
	return cloneTTLState(t.state), nil
}

// AdoptTTL imports only references approved by the backend's bound provenance
// preview. The commit adapter must validate ownership again under its barrier.
func (e *AppConnector) AdoptTTL(hash, source string, refs []LegacyDNSReference) error {
	t := e.ttl.Load()
	if t == nil {
		return fmt.Errorf("appc TTL: not installed")
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if hash != t.state.Hash() || strings.TrimSpace(source) == "" {
		return fmt.Errorf("appc TTL: adoption CAS")
	}
	next := cloneTTLState(t.state)
	for _, r := range refs {
		n, err := featurepolicy.NormalizeDomain(r.Domain)
		if err != nil || n != r.Domain || !r.IP.IsValid() || r.IP.Is4In6() || !slices.Contains(next.Roots, r.AssignedRoot) || !ttlRootMatches(r.AssignedRoot, r.Domain) {
			return fmt.Errorf("appc TTL: invalid adoption")
		}
		if !slices.Contains(next.Legacy, r) {
			next.Legacy = append(next.Legacy, r)
		}
	}
	if len(next.Legacy)+len(next.Leases) > t.book.opts.MaxEntries {
		return fmt.Errorf("appc TTL: capacity")
	}
	return t.apply(next, t.book.clone(), "adopt", source)
}

// RestoreTTLReset restores a backend-validated durable reset checkpoint. The
// adapter must CAS the current complete backend state, including manual prefs.
func (e *AppConnector) RestoreTTLReset(hash, source string, before ConnectorTTLState, data []byte) error {
	t := e.ttl.Load()
	if t == nil {
		return fmt.Errorf("appc TTL: not installed")
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if hash != t.state.Hash() || before.Fence.ProfileID != t.state.Fence.ProfileID || strings.TrimSpace(source) == "" || !slices.Equal(before.Roots, t.state.Roots) || !slices.Equal(before.Control, t.state.Control) {
		return fmt.Errorf("appc TTL: rollback CAS")
	}
	book, err := RestoreLeaseBook(data, t.state.Fence, t.book.opts, t.book.now)
	if err != nil {
		return err
	}
	before.Fence, before.SourceID = t.state.Fence, t.state.SourceID
	if err := t.apply(before, book, "rollback", source); err != nil {
		return err
	}
	e.installTTLObserver(t)
	return nil
}

// HandoffTTL commits before detaching the authority. In-flight observers are
// rejected by the retired lifecycle, including callbacks already past parsing.
func (e *AppConnector) HandoffTTL(source string) error {
	t := e.ttl.Load()
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := t.apply(cloneTTLState(t.state), t.book.clone(), "handoff", source); err != nil {
		return err
	}
	t.blocked = fmt.Errorf("appc TTL: handed off")
	t.mu.Unlock()
	t.stopRefresher()
	t.mu.Lock()
	e.mu.Lock()
	e.leaseEpoch.Add(1)
	e.leaseSink.Store(nil)
	e.ttl.Store(nil)
	e.mu.Unlock()
	return nil
}

func (e *AppConnector) TTLDebugSummary(now time.Time) (count int, uncertain bool, age float64) {
	t := e.ttl.Load()
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, l := range t.state.Leases {
		age = max(age, now.Sub(l.Expires).Seconds())
	}
	return len(t.state.Leases) + len(t.state.Legacy), t.book.TimeUncertain(), age
}

// TTLBlocked reports whether the installed lifecycle is quarantined because a
// write may have started. It is lock-free so status projections may call it
// under an unrelated lock. A prewrite rejection does not set it.
func (e *AppConnector) TTLBlocked() bool {
	return e.ttl.Load() != nil && e.ttlBlocked.Load()
}

// TTLDiagnostics is a fixed-vocabulary snapshot for logs and status. It never
// contains domains, addresses, keys or free-form backend text.
type TTLDiagnostics struct {
	Installed         bool
	InstallIncomplete bool
	Blocked           bool
	BlockedCause      string
	BlockedAction     string
	BlockedFence      featurepolicy.Fence
	BlockedRevision   uint64
	BlockedEpoch      uint64
	PrewriteRejects   uint64
	LastPrewrite      *TTLTransitionError
	LastSuccess       *TTLTransitionError
	CommittedFence    featurepolicy.Fence
	CommittedRevision uint64
	LeaseEpoch        uint64
}

// TTLDiagnostics returns lifecycle identity and commit-phase diagnostics. It
// takes the lifecycle lock and must not be called from a transition callback.
func (e *AppConnector) TTLDiagnostics() TTLDiagnostics {
	var d TTLDiagnostics
	t := e.ttl.Load()
	if t == nil {
		return d
	}
	d.Installed = true
	t.mu.Lock()
	defer t.mu.Unlock()
	d.InstallIncomplete = t.installIncomplete
	d.Blocked = t.blocked != nil
	if d.Blocked && t.blockedPhase != "" {
		d.BlockedCause = string(t.blockedPhase)
		d.BlockedAction = t.blockedAction
		d.BlockedFence = t.blockedFence
		d.BlockedRevision = t.blockedRev
		d.BlockedEpoch = t.blockedEpoch
	}
	d.PrewriteRejects = t.prewriteRejects
	d.LastPrewrite = cloneTransitionError(t.lastPrewrite)
	d.LastSuccess = cloneTransitionError(t.lastSuccess)
	d.CommittedFence = t.state.Fence
	d.CommittedRevision = t.state.Revision
	d.LeaseEpoch = t.epoch
	return d
}

func cloneTransitionError(e *TTLTransitionError) *TTLTransitionError {
	if e == nil {
		return nil
	}
	c := *e
	return &c
}
