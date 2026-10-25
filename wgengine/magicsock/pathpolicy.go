// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"context"
	"encoding/binary"
	"errors"
	"math/rand/v2"
	"net/netip"
	"reflect"
	"slices"
	"sync/atomic"
	"time"

	"github.com/tailscale/wireguard-go/conn"
	"github.com/tailscale/wireguard-go/device"
	"go4.org/mem"
	"tailscale.com/disco"
	"tailscale.com/featurepolicy"
	"tailscale.com/tailcfg"
	"tailscale.com/tstime/mono"
	"tailscale.com/types/key"
)

var errPolicyNoPath = errors.New("POLICY_NO_PATH")

// All map members and rule values are immutable after publication. The only
// mutable members are atomic status, relay bindings and evidence counters. The WG predicate reads
// no endpoint/Conn locks and does not record health (it precedes replay checks).
type pathRelayBinding struct {
	source  epAddr
	server  key.DiscoPublic
	session uint64
}

type pathPeerPolicy struct {
	relay      atomic.Pointer[pathRelayBinding]
	node       tailcfg.NodeView
	identity   featurepolicy.Identity
	rule       featurepolicy.Rule
	generation uint64
	status     atomic.Pointer[featurepolicy.PathStatus]
}
type pathKnownPeer struct {
	stableID tailcfg.StableNodeID
	disco    key.DiscoPublic
	epoch    uint64
}

type pathPolicyTable struct {
	evidence      pathEvidenceCounters
	profile       string
	settings      featurepolicy.PathConfig
	generation    uint64
	enabled       bool
	peers         map[key.NodePublic]*pathPeerPolicy
	known         map[key.NodePublic]pathKnownPeer
	pending       []string
	observability featurepolicy.ObservabilityConfig
}

func pathOf(a epAddr) featurepolicy.Path {
	if a.ap.Addr() == tailcfg.DerpMagicIPAddr {
		return featurepolicy.DERP
	}
	if a.vni.IsSet() {
		return featurepolicy.PeerRelay
	}
	return featurepolicy.Direct
}
func (c *Conn) pathGeneration() uint64 {
	if c == nil {
		return 0
	}
	if s := c.pathPolicy.Load(); s != nil {
		return s.generation
	}
	return 0
}
func (c *Conn) pathPeer(k key.NodePublic) *pathPeerPolicy {
	if c == nil {
		return nil
	}
	if s := c.pathPolicy.Load(); s != nil && s.enabled {
		return s.peers[k]
	}
	return nil
}

// decidePath is the shared pure final predicate. Each peer stores the oldest
// still-valid global ingress generation. Unrelated peer updates do not cancel
// its work; a changed rule or identity advances that lower bound.
// Generation zero is an actual
// ingress epoch (not a wildcard). Unmatched current peers retain upstream logic.
func (c *Conn) decidePath(k key.NodePublic, p featurepolicy.Path, purpose featurepolicy.PathPurpose, g uint64) bool {
	if c == nil {
		return true
	}
	return c.pathPolicy.Load().decidePath(k, p, purpose, g)
}

func (s *pathPolicyTable) decidePath(k key.NodePublic, p featurepolicy.Path, purpose featurepolicy.PathPurpose, g uint64) bool {
	if s == nil || !s.enabled {
		return true
	}
	identity, known := s.known[k]
	if !known || g < identity.epoch || g > s.generation {
		return false
	}
	peer := s.peers[k]
	if peer == nil {
		return true
	}
	if g < peer.generation || g > s.generation || !peer.rule.Allow.Allows(p) {
		return false
	}
	if purpose == featurepolicy.PathProbe {
		return true
	}
	if purpose == featurepolicy.PathReceive {
		return peer.rule.Fallback != "strict" || len(peer.rule.Prefer) > 0 && featurepolicy.Path(peer.rule.Prefer[0]) == p
	}
	st := peer.status.Load()
	return st != nil && st.Active == p
}

func (c *Conn) allowPolicyAuthenticated(k [32]byte, kind conn.PacketKind, ctx conn.TransportContext) bool {
	return c.pathPolicy.Load().allowPolicyAuthenticated(k, kind, ctx)
}

func (s *pathPolicyTable) allowPolicyAuthenticated(k [32]byte, kind conn.PacketKind, ctx conn.TransportContext) bool {
	p := featurepolicy.Direct
	switch ctx.Kind {
	case conn.TransportDirect:
	case conn.TransportDERP:
		p = featurepolicy.DERP
	case conn.TransportRelay:
		p = featurepolicy.PeerRelay

		pub := key.NodePublicFromRaw32(mem.B(k[:]))
		if peer := s.pathPeer(pub); peer != nil {
			if !ctx.RelayVerified {
				return false
			}
			binding := peer.relay.Load()
			if binding == nil || binding.session != ctx.RelaySession || binding.server.Raw32() != ctx.RelayServer || binding.source.ap != ctx.Endpoint || !binding.source.vni.IsSet() || binding.source.vni.Get() != ctx.RelayVNI {
				return false
			}
		}
	default:
		return false
	}
	purpose := featurepolicy.PathReceive
	if kind == conn.PacketInitiation || kind == conn.PacketResponse {
		purpose = featurepolicy.PathProbe
	}
	return s.decidePath(key.NodePublicFromRaw32(mem.B(k[:])), p, purpose, ctx.Generation)
}

// SetPathPolicy installs already validated LKG configuration. Identity always
// comes from magicsock's current control netmap, not from an async caller's old
// snapshot. Callers serialize revisions; this is not a public configuration API.
func (c *Conn) SetPathPolicy(s *featurepolicy.PolicySnapshot) error {
	if s == nil {
		return nil
	}
	cfg := s.Config()
	if cfg.Enabled && cfg.PathPolicy.Enabled {
		gate := c.authenticatedPathGate.Load()
		if gate == nil || !gate.livePolicy {
			return errors.New("path policy: permanent authenticated gate not installed")
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if reflect.DeepEqual(c.pathConfig, cfg) && c.pathSourceFence == s.Fence() {
		return nil
	}
	preserve := c.pathSourceFence.ProfileID == s.Fence().ProfileID
	c.pathSourceFence = s.Fence()
	c.pathConfig = cfg
	c.pathProbeSeconds.Store(int64(cfg.PathPolicy.ProbeSeconds))
	c.pathTimeoutSeconds.Store(int64(cfg.PathPolicy.ProbeTimeoutSeconds))
	c.rebuildPathPolicyLocked(preserve)
	return nil
}

// refreshPathPolicyLocked also runs at netmap membership/key/disco boundaries.
// Publication revokes old work before clearing endpoint caches. It never stops
// shared relay/STUN/DERP services. Lock order is Conn -> endpoint, never reversed.
func (c *Conn) refreshPathPolicyLocked(force ...tailcfg.NodeID) {
	c.rebuildPathPolicyLocked(false, force...)
}

func (c *Conn) rebuildPathPolicyLocked(preserve bool, force ...tailcfg.NodeID) {
	cfg := c.pathConfig
	old := c.pathPolicy.Load()
	enabled := cfg.Enabled && cfg.PathPolicy.Enabled
	if !enabled && (old == nil || !old.enabled) {
		return
	}
	generation := uint64(1)
	if old != nil {
		generation = old.generation + 1
	}
	next := &pathPolicyTable{generation: generation, enabled: enabled, observability: cfg.Observability, peers: map[key.NodePublic]*pathPeerPolicy{}, known: map[key.NodePublic]pathKnownPeer{}}
	next.profile = c.pathSourceFence.ProfileID
	next.settings = cfg.PathPolicy
	next.settings.Rules = nil
	seen := map[string]bool{}
	identities := map[tailcfg.StableNodeID]int{}
	nodes := map[key.NodePublic]int{}
	for _, n := range c.peersByID {
		if n.Valid() {
			identities[n.StableID()]++
			nodes[n.Key()]++
		}
	}
	for _, n := range c.peersByID {
		if !n.Valid() || n.Key().IsZero() || n.StableID() == "" || identities[n.StableID()] != 1 || nodes[n.Key()] != 1 {
			continue
		}
		identity := pathKnownPeer{stableID: n.StableID(), disco: n.DiscoKey(), epoch: generation}
		if old == nil {
			identity.epoch = 0
		} else if previous, ok := old.known[n.Key()]; ok && old.profile == next.profile && previous.stableID == identity.stableID && previous.disco == identity.disco {
			identity.epoch = previous.epoch
		}
		next.known[n.Key()] = identity
		seen[string(n.StableID())] = true
		if !enabled {
			continue
		}
		for _, r := range cfg.PathPolicy.Rules {
			if !slices.Contains(r.StableIDs, string(n.StableID())) {
				continue
			}
			next.peers[n.Key()] = &pathPeerPolicy{node: n, identity: featurepolicy.Identity{StableID: n.StableID(), RuleID: r.ID, Node: n.Key(), Disco: n.DiscoKey()}, rule: r, generation: generation}
			if old != nil && old.profile == next.profile && reflect.DeepEqual(old.settings, next.settings) && !slices.Contains(force, n.ID()) {
				previous := old.peers[n.Key()]
				if previous != nil && previous.identity.StableID == n.StableID() && previous.identity.Disco == n.DiscoKey() && reflect.DeepEqual(previous.rule, r) && previous.node.HomeDERP() == n.HomeDERP() && slices.Equal(previous.node.Endpoints().AsSlice(), n.Endpoints().AsSlice()) {
					next.peers[n.Key()] = previous
				}
			}
			break
		}
	}
	for _, r := range cfg.PathPolicy.Rules {
		for _, id := range r.StableIDs {
			if !seen[id] {
				next.pending = append(next.pending, r.ID+":"+id)
			}
		}
	}
	// Empty statuses deny business until endpoint machines are rebound below.
	c.pathPolicy.Store(next)
	c.peerMap.forEachEndpoint(func(ep *endpoint) {
		before := (*pathPeerPolicy)(nil)
		if old != nil {
			before = old.peers[ep.publicKey]
		}
		after := next.peers[ep.publicKey]
		if before == after {
			return
		}
		ep.mu.Lock()
		defer ep.mu.Unlock()
		savedBest, savedTrust := ep.bestAddr, ep.trustBestAddrUntil
		if savedBest.vni.IsSet() && savedBest.policyTrustUntil != 0 {
			savedTrust = savedBest.policyTrustUntil
		}
		savedCandidates := ep.policyCandidates
		machine := ep.pathMachine
		atomic.AddInt64(&ep.numStopAndResetAtomic, 1)
		ep.resetLocked()
		ep.policyCandidates = nil
		ep.policyPingIDs = nil
		ep.policyProbeSuccess = nil
		ep.policyProbeFailure = nil
		delete(c.onEndpointRefreshed, ep)
		if ep.policyWGTimer != nil {
			ep.policyWGTimer.Stop()
			ep.policyWGTimer = nil
		}
		ep.policyWGAttempt = 0
		ep.policyWGLastSuccess = 0
		ep.policyLastProbe = 0
		ep.policyNextProbe = 0
		if after == nil {
			ep.pathMachine = nil
			return
		}
		f := featurepolicy.Fence{Generation: generation, PeerIdentityEpoch: generation}
		// Preserve the rule across key rotation, never unauthenticated health.
		ep.pathMachine = featurepolicy.NewPathMachine(after.rule, cfg.PathPolicy, f)
		// A verified, still-trusted pre-policy relay grant can bootstrap relay-only
		// without forbidden DERP coordination. Retain it only as a probe candidate;
		// old queued packets/work remain fenced and a new Pong activates business.
		if before == nil && savedBest.ap.IsValid() && mono.Now().Before(savedTrust) && after.rule.Allow.Allows(pathOf(savedBest.epAddr)) && (!savedBest.vni.IsSet() || savedBest.relaySession != 0) {
			savedBest.policyGeneration = generation
			savedBest.policyTrustUntil = savedTrust
			ep.policyCandidates = map[featurepolicy.Path]addrQuality{pathOf(savedBest.epAddr): savedBest}
		}
		if preserve && machine != nil && before != nil && before.identity.StableID == after.identity.StableID && before.identity.Disco == after.identity.Disco {
			machine.Reconfigure(after.rule, cfg.PathPolicy, f, time.Now())
			ep.pathMachine = machine
			for p, a := range savedCandidates {
				if !after.rule.Allow.Allows(p) {
					continue
				}
				if ep.policyCandidates == nil {
					ep.policyCandidates = map[featurepolicy.Path]addrQuality{}
				}
				a.policyGeneration = generation
				ep.policyCandidates[p] = a
			}
		}
		publishRelayBinding(after, ep.policyCandidates[featurepolicy.PeerRelay])
		ep.publishPathStatusLocked(after)
	})
}

func (ep *endpoint) publishPathStatusLocked(p *pathPeerPolicy) {
	if ep.pathMachine == nil {
		return
	}
	st := ep.pathMachine.Status()
	if st.Fence.Generation != p.generation {
		return
	}
	previous := p.status.Swap(&st)
	if previous != nil && previous.State == st.State && previous.Active == st.Active {
		return
	}
	// Change-only logs, bounded by the configured global per-minute budget.
	// No addresses, keys, or rule IDs as metric labels.
	now := time.Now()
	ep.c.pathLogMu.Lock()
	defer ep.c.pathLogMu.Unlock()
	if now.Sub(ep.c.pathLogStart) >= time.Minute {
		ep.c.pathLogStart = now
		ep.c.pathLogCount = 0
	}
	table := ep.c.pathPolicy.Load()
	if table == nil || ep.c.pathLogCount >= table.observability.LogRatePerMinute || !table.observability.LogDecisions {
		return
	}
	ep.c.pathLogCount++
	ep.c.logf("unified: path_decision generation=%d state=%s path=%s reason=%s stableID=%q matched=true allow=%+v homeDERP=%d derpAddr=%v bestAddr=%v candidates={direct:%t peer_relay:%t derp:%t} lastProbe=%v nextProbe=%v",
		p.generation, st.State, st.Active, st.Reason, p.identity.StableID, p.rule.Allow,
		p.node.HomeDERP(), ep.derpAddr, ep.bestAddr.epAddr, ep.policyCandidates[featurepolicy.Direct].ap.IsValid(), ep.policyCandidates[featurepolicy.PeerRelay].ap.IsValid(),
		ep.derpAddr.IsValid() && !ep.isWireguardOnly, ep.policyLastProbe, ep.policyNextProbe)
}

// PathPolicyState is internal-only; Patch08 may build a separately reviewed API.
func (c *Conn) PathPolicyState() (uint64, map[tailcfg.StableNodeID]featurepolicy.PathStatus, []string) {
	out := map[tailcfg.StableNodeID]featurepolicy.PathStatus{}
	s := c.pathPolicy.Load()
	if s == nil {
		return 0, out, nil
	}
	for _, p := range s.peers {
		if st := p.status.Load(); st != nil {
			out[p.identity.StableID] = *st
		}
	}
	return s.generation, out, slices.Clone(s.pending)
}

func (ep *endpoint) observePathLocked(a epAddr, success bool, g uint64) {
	p := ep.c.pathPeer(ep.publicKey)
	if p == nil || !ep.c.decidePath(ep.publicKey, pathOf(a), featurepolicy.PathProbe, g) || ep.pathMachine == nil {
		return
	}
	if success {
		ep.c.pathPolicy.Load().countConfirmation(ep.publicKey, pathOf(a), evidenceHealth)
	}
	ep.pathMachine.Observe(pathOf(a), success, time.Now(), featurepolicy.Fence{Generation: p.generation, PeerIdentityEpoch: p.generation})
	ep.publishPathStatusLocked(p)
}

func (ep *endpoint) policyAddrLocked() (epAddr, netip.AddrPort) {
	p := ep.c.pathPeer(ep.publicKey)
	if p == nil {
		return epAddr{}, netip.AddrPort{}
	}
	st := p.status.Load()
	if st == nil {
		return epAddr{}, netip.AddrPort{}
	}
	if st.Active == featurepolicy.DERP && !ep.isWireguardOnly {
		return epAddr{}, ep.derpAddr
	}
	a := ep.policyCandidates[st.Active]
	if !a.ap.IsValid() {
		return epAddr{}, netip.AddrPort{}
	}
	return a.epAddr, netip.AddrPort{}
}

// policyProbeLocked ensures DERP is tested independently of bestAddr. A DERP
// socket is never counted as peer reachability. Existing heartbeat schedules
// drive this method; background timers are owned by sentPing.
func (ep *endpoint) policyProbeLocked(now mono.Time) {
	p := ep.c.pathPeer(ep.publicKey)
	if p == nil {
		return
	}
	if ep.policyNextProbe != 0 && now.Before(ep.policyNextProbe) {
		return
	}
	ep.policyLastProbe = now
	interval := time.Duration(ep.c.pathProbeSeconds.Load()) * time.Second
	ep.policyNextProbe = now.Add(interval * time.Duration(800+rand.IntN(401)) / 1000)
	for addr := range ep.endpointState {
		ep.startDiscoPingLocked(epAddr{ap: addr}, now, pingDiscovery, 0, nil)
	}
	if relay := ep.policyCandidates[featurepolicy.PeerRelay]; relay.ap.IsValid() {
		ep.startDiscoPingLocked(relay.epAddr, now, pingHeartbeat, 0, nil)
	}
	if ep.wantUDPRelayPathDiscoveryLocked(now) {
		ep.discoverUDPRelayPathsLocked(now)
	}
	if ep.derpAddr.IsValid() && !ep.isWireguardOnly {
		ep.startDiscoPingLocked(epAddr{ap: ep.derpAddr}, now, pingDiscovery, 0, nil)
	}
	if p.rule.Allow.Direct && p.rule.Allow.Derp && ep.derpAddr.IsValid() && !ep.isWireguardOnly {
		go ep.c.enqueueCallMeMaybePolicy(ep.derpAddr, ep, ep.c.newPathSend(ep.publicKey, featurepolicy.PathProbe))
	}
}

// pathSendContext belongs to the terminal peer even for relay-server traffic.
// It travels with queued sends; a server's own direct rule is irrelevant to work
// performed for a different terminal peer.
type pathSendContext struct {
	workContext  context.Context
	relaySession uint64
	peer         key.NodePublic
	generation   uint64
	purpose      featurepolicy.PathPurpose
	relayWork    bool
}

func (c *Conn) newPathSend(k key.NodePublic, purpose featurepolicy.PathPurpose) pathSendContext {
	return pathSendContext{peer: k, generation: c.pathGeneration(), purpose: purpose}
}
func (c *Conn) allowPathSend(x pathSendContext, p featurepolicy.Path) bool {
	s := c.pathPolicy.Load()
	allowed := s.allowPathSendUncounted(x, p)
	direction := 0
	if x.purpose == featurepolicy.PathProbe {
		direction = 1
	}
	s.countDecision(x.peer, p, direction, allowed)
	if !allowed {
		kind := 0
		if x.purpose == featurepolicy.PathProbe {
			kind = 1
		}
		c.countPathDeny(kind, p)
	}
	return allowed
}

func (c *Conn) allowPathSendUncounted(x pathSendContext, p featurepolicy.Path) bool {
	return c.pathPolicy.Load().allowPathSendUncounted(x, p)
}

func (s *pathPolicyTable) allowPathSendUncounted(x pathSendContext, p featurepolicy.Path) bool {
	if x.workContext != nil && s.pathPeer(x.peer) != nil && x.workContext.Err() != nil {
		return false
	}
	if x.relaySession != 0 {
		if peer := s.pathPeer(x.peer); peer != nil {
			binding := peer.relay.Load()
			if binding == nil || binding.session != x.relaySession {
				return false
			}
		}
	}
	if x.relayWork {
		if !s.decidePath(x.peer, featurepolicy.PeerRelay, featurepolicy.PathProbe, x.generation) {
			return false
		}
		if p != featurepolicy.DERP {
			return true
		}
	}
	return s.decidePath(x.peer, p, x.purpose, x.generation)
}

func (c *Conn) pathEnabled() bool { s := c.pathPolicy.Load(); return s != nil && s.enabled }

// Called only after sharedKey.Open and Parse, under Conn.mu. NodeKey in a Ping
// is accepted only through the existing control-map/DiscoKey binding resolver.
func (c *Conn) policyPingLocked(dm *disco.Ping, src epAddr, di *discoInfo, derp key.NodePublic) (node key.NodePublic, allowed bool) {
	s := c.pathPolicy.Load()
	defer func() { s.countDecision(node, pathOf(src), 2, allowed) }()
	nk, ok := c.unambiguousNodeKeyOfPingLocked(dm, di.discoKey, derp)
	if !c.pathEnabled() {
		return nk, true
	}
	if !ok || pathOf(src) == featurepolicy.DERP && (derp.IsZero() || derp != nk) || !c.decidePath(nk, pathOf(src), featurepolicy.PathProbe, c.pathGeneration()) {
		return nk, false
	}
	ep, ok := c.peerMap.endpointForNodeKey(nk)
	if !ok {
		return nk, false
	}
	ep.mu.Lock()
	defer ep.mu.Unlock()
	for _, id := range ep.policyPingIDs {
		if id == dm.TxID {
			return nk, false
		}
	}
	ep.policyPingIDs = append(ep.policyPingIDs, dm.TxID)
	if len(ep.policyPingIDs) > 64 {
		ep.policyPingIDs = ep.policyPingIDs[1:]
	}
	if pathOf(src) == featurepolicy.Direct {
		s.countConfirmation(nk, pathOf(src), evidenceLastRecv)
		ep.lastRecvUDPAny.StoreAtomic(mono.Now())
	}
	return nk, true
}

// Multiple addresses probed in one sweep are one health sample for a transport
// class. A successful address prevents failed sibling addresses from declaring
// that transport down. Replayed/duplicate TxIDs were consumed before this call.
func (ep *endpoint) observeProbeLocked(sp sentPing, success bool) {
	p := pathOf(sp.to)
	if success {
		if ep.policyProbeSuccess[p] >= sp.at || ep.policyProbeFailure[p] > sp.at {
			return
		}
		if ep.policyProbeSuccess == nil {
			ep.policyProbeSuccess = map[featurepolicy.Path]mono.Time{}
		}
		ep.policyProbeSuccess[p] = sp.at
	} else {
		if ep.policyProbeSuccess[p] >= sp.at || ep.policyProbeFailure[p] >= sp.at {
			return
		}
		if ep.policyProbeFailure == nil {
			ep.policyProbeFailure = map[featurepolicy.Path]mono.Time{}
		}
		ep.policyProbeFailure[p] = sp.at
	}
	ep.observePathLocked(sp.to, success, sp.policyGeneration)
}

// WireGuard-only peers cannot use Disco. Permit their locally generated Noise
// handshake as a direct probe, but never promote an ICMP response to path health.
// Payload transport still requires an authenticated successful path observation.
func (ep *endpoint) policyWGHandshakeLocked(buffs [][]byte, offset int, now mono.Time, policy *pathSendContext) (epAddr, bool) {
	if !ep.isWireguardOnly || ep.c.pathPeer(ep.publicKey) == nil || len(buffs) == 0 {
		return epAddr{}, false
	}
	for _, b := range buffs {
		if offset < 0 || len(b) < offset+4 {
			return epAddr{}, false
		}
		b = b[offset:]
		typ := binary.LittleEndian.Uint32(b)
		if !(typ == device.MessageInitiationType && len(b) == device.MessageInitiationSize || typ == device.MessageResponseType && len(b) == device.MessageResponseSize) {
			return epAddr{}, false
		}
	}
	if !ep.c.decidePath(ep.publicKey, featurepolicy.Direct, featurepolicy.PathProbe, policy.generation) {
		return epAddr{}, false
	}
	a, _ := ep.addrForWireGuardSendLocked(now)
	if !a.ap.IsValid() {
		return epAddr{}, false
	}
	policy.purpose = featurepolicy.PathProbe
	if ep.policyWGTimer == nil {
		generation := policy.generation
		ep.policyWGAttempt = now
		ep.policyWGTimer = time.AfterFunc(time.Duration(ep.c.pathTimeoutSeconds.Load())*time.Second, func() {
			ep.mu.Lock()
			defer ep.mu.Unlock()
			if ep.policyWGAttempt != now {
				return
			}
			ep.policyWGTimer = nil
			ep.observePathLocked(a, false, generation)
		})
	}
	return a, true
}

// Called after WG authentication AND replay acceptance under Conn.mu, outside
// WireGuard locks. A stream of payload packets cannot accelerate recovery: at
// most one successful observation is counted per configured probe interval.
func (ep *endpoint) policyWGAccepted(src epAddr, generation uint64) {
	if !ep.isWireguardOnly || ep.c.pathPeer(ep.publicKey) == nil {
		return
	}
	ep.mu.Lock()
	defer ep.mu.Unlock()
	if !ep.c.decidePath(ep.publicKey, pathOf(src), featurepolicy.PathProbe, generation) {
		return
	}
	if ep.policyWGTimer != nil {
		ep.policyWGTimer.Stop()
		ep.policyWGTimer = nil
	}
	ep.policyWGAttempt = 0
	now := mono.Now()
	if ep.policyWGLastSuccess != 0 && now.Sub(ep.policyWGLastSuccess) < time.Duration(ep.c.pathProbeSeconds.Load())*time.Second {
		return
	}
	ep.policyWGLastSuccess = now
	if ep.policyCandidates == nil {
		ep.policyCandidates = map[featurepolicy.Path]addrQuality{}
	}
	ep.policyCandidates[featurepolicy.Direct] = addrQuality{epAddr: src, policyGeneration: generation}
	ep.observePathLocked(src, true, generation)
}

// A replacement session invalidates queued provenance even when policy itself
// did not change. The WG predicate reads this value without acquiring locks.
func publishRelayBinding(peer *pathPeerPolicy, candidate addrQuality) {
	if peer == nil {
		return
	}
	if !candidate.vni.IsSet() || candidate.relaySession == 0 {
		peer.relay.Store(nil)
		return
	}
	peer.relay.Store(&pathRelayBinding{source: candidate.epAddr, server: candidate.relayServerDisco, session: candidate.relaySession})
}

func (ep *endpoint) validPolicyPing(sp sentPing) bool {
	if !ep.c.decidePath(ep.publicKey, pathOf(sp.to), featurepolicy.PathProbe, sp.policyGeneration) {
		return false
	}
	if peer := ep.c.pathPeer(ep.publicKey); peer != nil && sp.to.vni.IsSet() {
		binding := peer.relay.Load()
		return binding != nil && binding.source == sp.to && binding.session == sp.policyRelaySession
	}
	return true
}
