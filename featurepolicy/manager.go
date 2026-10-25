// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package featurepolicy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"sync"
	"sync/atomic"
	"time"
)

// Store persists profile-scoped LKG prepare records atomically. Save must return
// only after durable storage; on error it must leave the previous record intact.
type Store interface {
	Load(profile string) ([]byte, error)
	Save(profile string, record []byte) error
}

// Stage validates consumers without publishing or mutating live state. Consumers
// subsequently read Current; there is only one atomic publication point.
type Stage func(*PolicySnapshot) error

// Manager serializes configuration, control epochs, persistence and publication.
// Disk I/O occurs under its own mutex, never under a backend data-plane lock.
type Manager struct {
	mu         sync.Mutex
	current    atomic.Pointer[PolicySnapshot]
	store      Store
	stage      []Stage
	input      Inputs
	sourceHash string
}

type record struct {
	SchemaVersion int
	Fence         Fence
	Config        json.RawMessage
	Hash          string
	SourceHash    string
}

// NewManager starts disabled. Start must be called before enabling consumers.
func NewManager(store Store, stages ...Stage) *Manager {
	m := &Manager{store: store, stage: slicesCopy(stages)}
	c, _ := Parse([]byte(`{"schema_version":1}`))
	s, _ := compile(c, Inputs{}, 0)
	m.current.Store(s)
	return m
}
func slicesCopy[T any](v []T) []T { return append([]T(nil), v...) }

// Current returns an immutable snapshot safe for concurrent readers.
func (m *Manager) Current() *PolicySnapshot { return m.current.Load() }

// CurrentFence checks a captured asynchronous operation's full fence.
func (m *Manager) CurrentFence(f Fence) bool { return m.Current().Fence() == f }
func hash(b []byte) string                   { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

// Start loads a valid file, falls back to this profile's LKG on file failure,
// or starts disabled only when both file and LKG are absent. The returned
// warning reports fallback; err blocks activation. read must enforce file trust.
func (m *Manager) Start(in Inputs, read func() ([]byte, error)) (warning, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var old record
	var saved []byte
	var se error = fs.ErrNotExist
	if m.store != nil {
		saved, se = m.store.Load(in.ProfileID)
	}
	if se == nil {
		if e := json.Unmarshal(saved, &old); e != nil || old.SchemaVersion != 1 || old.Fence.ProfileID != in.ProfileID || hash(old.Config) != old.Hash {
			return "", fmt.Errorf("invalid LKG")
		}
	} else if !errors.Is(se, fs.ErrNotExist) {
		return "", se
	}
	b, e := read()
	if e == nil {
		var c Config
		c, e = Parse(b)
		if e == nil {
			e = m.publish(c, in, max(m.Current().fence.Generation, old.Fence.Generation)+1, hash(b))
			if e == nil {
				return "", nil
			}
		}
	}
	if se == nil {
		c, ce := Parse(old.Config)
		if ce != nil {
			return "", ce
		}
		if ce = m.publish(c, in, max(m.Current().fence.Generation, old.Fence.Generation)+1, old.SourceHash); ce != nil {
			return "", ce
		}
		if errors.Is(e, fs.ErrNotExist) && old.SourceHash == "" {
			return "", nil
		}
		return warning(fmt.Sprintf("using LKG: %v", e)), nil
	}
	if errors.Is(e, fs.ErrNotExist) {
		c, _ := Parse([]byte(`{"schema_version":1}`))
		return "", m.publish(c, in, m.Current().fence.Generation+1, "")
	}
	return "", e
}

// warning records a recoverable startup failure separately from activation errors.
type warning string

// Reload is the LocalAPI-ready CAS entry point. Invalid input and persistence or
// staging failures retain the previous generation. expectedHash binds raw bytes.
func (m *Manager) Reload(b []byte, expectedGeneration uint64, expectedHash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Current().fence.Generation != expectedGeneration || hash(b) != expectedHash {
		return fmt.Errorf("reload: CAS conflict")
	}
	c, e := Parse(b)
	if e != nil {
		return e
	}
	if hash(b) == m.sourceHash {
		return nil
	}
	return m.publish(c, m.input, expectedGeneration+1, hash(b))
}

// Recompile atomically replaces authenticated domains/identities. Profile changes
// require Start to load the new profile's state instead of reusing old policy.
func (m *Manager) Recompile(in Inputs) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.Current()
	if in.ProfileID != s.fence.ProfileID || in.AssignedDomainsEpoch < s.fence.AssignedDomainsEpoch || in.PeerIdentityEpoch < s.fence.PeerIdentityEpoch {
		return fmt.Errorf("stale or foreign inputs")
	}
	return m.publish(s.config, in, s.fence.Generation+1, m.sourceHash)
}
func (m *Manager) publish(c Config, in Inputs, g uint64, source string) error {
	s, e := compile(c, in, g)
	if e != nil {
		return e
	}
	for _, stage := range m.stage {
		if e = stage(s); e != nil {
			return e
		}
	}
	if m.store == nil && s.Enabled() {
		return fmt.Errorf("enabled policy requires durable LKG store")
	}
	if m.store != nil {
		r := record{1, s.fence, c.JSON(), hash(c.JSON()), source}
		b, _ := json.Marshal(r)
		if e = m.store.Save(in.ProfileID, b); e != nil {
			return e
		}
	}
	// All fallible work precedes publication. A crash here recovers this prepared
	// record; no external side effects have been performed by policy compilation.
	in.AssignedDomains = slicesCopy(in.AssignedDomains)
	in.Peers = slicesCopy(in.Peers)
	m.input = in
	m.sourceHash = source
	m.current.Store(s)
	return nil
}

// Poll hashes actual contents on each interval (mtime/size are not a cache key).
// read and report must not call back into Manager while holding unrelated locks.
func (m *Manager) Poll(ctx context.Context, read func() ([]byte, error), report func(error)) {
	for {
		t := time.NewTimer(time.Duration(m.Current().config.ReloadSeconds) * time.Second)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
		b, e := read()
		if e == nil {
			e = m.Reload(b, m.Current().fence.Generation, hash(b))
		}
		if e != nil && report != nil {
			report(e)
		}
	}
}

// CheckStartup validates the trusted file or profile LKG before the daemon
// starts. Compilation waits for authenticated control inputs; this check does
// not confuse a missing initial netmap with a malformed configuration file.
func CheckStartup(store Store, profile string, read func() ([]byte, error)) error {
	data, readErr := read()
	if readErr == nil {
		_, readErr = Parse(data)
		if readErr == nil {
			return nil
		}
	}
	if store != nil {
		data, err := store.Load(profile)
		if err == nil {
			var r record
			if json.Unmarshal(data, &r) != nil || r.SchemaVersion != 1 || r.Fence.ProfileID != profile || hash(r.Config) != r.Hash {
				return fmt.Errorf("invalid LKG")
			}
			_, err = Parse(r.Config)
			return err
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	if errors.Is(readErr, fs.ErrNotExist) {
		return nil
	}
	return readErr
}
