// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package featurepolicy

import (
	"slices"
	"time"
)

// Path is a transport class, not an address or a claim of peer identity.
type Path string

const (
	Direct    Path = "direct"
	PeerRelay Path = "peer_relay"
	DERP      Path = "derp"
)

// PathPurpose separates business selection from allowed recovery probes.
type PathPurpose uint8

const (
	PathSend PathPurpose = iota
	PathProbe
	PathReceive
	PathPromote
)

// PathState is an internal diagnostic, not a promise of remote convergence.
type PathState string

const (
	Unresolved PathState = "UNRESOLVED"
	Probing    PathState = "PROBING"
	Active     PathState = "ACTIVE"
	Suspect    PathState = "SUSPECT"
	Fallback   PathState = "FALLBACK"
	NoPath     PathState = "NO_PATH"
	Recovering PathState = "RECOVERING"
)

type pathHealth struct {
	failed              bool
	available           bool
	failures, successes int
	healthySince        time.Time
}

// PathMachine is owned by one endpoint lock. Time is supplied by the caller so
// tests exercise boundaries without sleeping. Observations must be authenticated,
// unique probe outcomes, fenced against both policy revision and identity epoch.
// Socket readiness alone is not a successful observation. R8 enforces a
// minimum 15-second recovery hold even for older schema-valid shorter values.
type PathMachine struct {
	rule     Rule
	config   PathConfig
	fence    Fence
	state    PathState
	active   Path
	switched time.Time
	health   map[Path]pathHealth
}

type PathStatus struct {
	RuleID string
	State  PathState
	Active Path
	Reason string
	Fence  Fence
}

// NewPathMachine starts with no proven paths. NoPath is immediate for blackholes.
func NewPathMachine(r Rule, c PathConfig, f Fence) *PathMachine {
	r.Prefer = slices.Clone(r.Prefer)
	m := &PathMachine{rule: r, config: c, fence: f, state: Unresolved, health: make(map[Path]pathHealth)}
	m.state = Probing
	if len(r.Prefer) == 0 {
		m.state = NoPath
	}
	return m
}

func (a Allow) Allows(p Path) bool {
	switch p {
	case Direct:
		return a.Direct
	case PeerRelay:
		return a.PeerRelay
	case DERP:
		return a.Derp
	}
	return false
}

func (m *PathMachine) Status() PathStatus {
	reason := string(m.state)
	if m.active == "" {
		reason = "POLICY_NO_PATH"
	}
	return PathStatus{RuleID: m.rule.ID, State: m.state, Active: m.active, Reason: reason, Fence: m.fence}
}

// Decide never substitutes another path and never permits a stale generation.
func (m *PathMachine) Decide(p Path, purpose PathPurpose, f Fence) bool {
	if f != m.fence || !m.rule.Allow.Allows(p) {
		return false
	}
	if purpose == PathProbe {
		return true
	}
	if purpose == PathReceive {
		return m.rule.Fallback != "strict" || len(m.rule.Prefer) > 0 && Path(m.rule.Prefer[0]) == p
	}
	return p == m.active && p != ""
}

// Observe applies exactly one completed probe, not one packet or MTU replica.
// False is a send failure or an elapsed probe timeout; callers own timeout timers.
func (m *PathMachine) Observe(p Path, success bool, now time.Time, f Fence) {
	if f != m.fence || !m.rule.Allow.Allows(p) {
		return
	}
	h := m.health[p]
	if success {
		if h.successes == 0 {
			h.healthySince = now
		}
		h.successes++
		h.failures = 0
		h.available = true
	} else {
		h.successes = 0
		h.healthySince = time.Time{}
		h.failures++
		if h.failures >= max(1, m.config.FailureThreshold) {
			h.available = false
			h.failed = true
		}
	}
	m.health[p] = h
	m.selectPath(now)
}

func (m *PathMachine) selectPath(now time.Time) {
	order := m.rule.Prefer
	if m.rule.Fallback == "strict" && len(order) > 1 {
		order = order[:1]
	}
	var candidate Path
	for _, s := range order {
		p := Path(s)
		if m.rule.Allow.Allows(p) && m.health[p].available {
			candidate = p
			break
		}
	}
	if m.active != "" && !m.health[m.active].available {
		m.active = ""
	}
	if candidate == "" {
		m.state = NoPath
		return
	}
	if m.active == "" {
		recovered := func(p Path) bool {
			h := m.health[p]
			return !h.failed || h.successes >= max(1, m.config.RecoverySuccesses) && now.Sub(h.healthySince) >= time.Duration(max(15, m.config.RecoveryHoldSeconds))*time.Second && now.Sub(m.switched) >= time.Duration(m.config.CooldownSeconds)*time.Second
		}
		if !recovered(candidate) {
			candidate = ""
			for _, s := range order {
				p := Path(s)
				if m.rule.Allow.Allows(p) && m.health[p].available && recovered(p) {
					candidate = p
					break
				}
			}
			if candidate == "" {
				m.state = Recovering
				return
			}
		}
		h := m.health[candidate]
		h.failed = false
		m.health[candidate] = h
		m.active = candidate
		m.switched = now
		m.state = Active
		if len(order) > 0 && candidate != Path(order[0]) {
			m.state = Fallback
		}
		return
	}
	if candidate != m.active {
		h := m.health[candidate]
		m.state = Recovering
		if h.successes < max(1, m.config.RecoverySuccesses) || now.Sub(h.healthySince) < time.Duration(max(15, m.config.RecoveryHoldSeconds))*time.Second || now.Sub(m.switched) < time.Duration(m.config.CooldownSeconds)*time.Second {
			return
		}
		m.active = candidate
		m.switched = now
		h.failed = false
		m.health[candidate] = h
	}
	m.state = Active
	if len(order) > 0 && m.active != Path(order[0]) {
		m.state = Fallback
	}
	if m.health[m.active].failures > 0 {
		m.state = Suspect
	}
}

// Reconfigure invalidates all old observations and removes hard-denied paths
// immediately, irrespective of hold/cooldown. Callers must reset on identity
// replacement (including deletion followed by registration).
func (m *PathMachine) Reconfigure(r Rule, c PathConfig, f Fence, now time.Time) {
	r.Prefer = slices.Clone(r.Prefer)
	m.rule = r
	m.config = c
	m.fence = f
	for p := range m.health {
		if !r.Allow.Allows(p) {
			delete(m.health, p)
		}
	}
	if !r.Allow.Allows(m.active) || r.Fallback == "strict" && (len(r.Prefer) == 0 || m.active != Path(r.Prefer[0])) {
		m.active = ""
	}
	m.selectPath(now)
}
