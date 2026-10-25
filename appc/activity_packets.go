// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package appc

import (
	"net/netip"
	"sync"
	"time"

	"tailscale.com/net/packet"
	"tailscale.com/types/ipproto"
)

// PacketActivity keeps only managed destination metadata. Observation must be
// called after authentication and ACL acceptance. It is supplementary evidence:
// silence cannot prove that an unseen kernel TCP/NAT flow is idle.
type PacketActivity struct {
	mu      sync.Mutex
	profile string
	max     int
	idle    time.Duration
	now     func() time.Time
	managed map[netip.Addr]bool
	recent  map[netip.Addr]time.Time
}

func NewPacketActivity(profile string, maxEntries int, idle time.Duration, now func() time.Time) *PacketActivity {
	if now == nil {
		now = time.Now
	}
	return &PacketActivity{profile: profile, max: maxEntries, idle: idle, now: now, managed: map[netip.Addr]bool{}, recent: map[netip.Addr]time.Time{}}
}
func (p *PacketActivity) SetManaged(ips []netip.Addr) {
	p.mu.Lock()
	defer p.mu.Unlock()
	next := map[netip.Addr]bool{}
	for _, ip := range ips {
		if len(next) >= p.max {
			break
		}
		next[ip] = true
	}
	p.managed = next
	for ip := range p.recent {
		if !next[ip] {
			delete(p.recent, ip)
		}
	}
}
func (p *PacketActivity) Observe(pkt *packet.Parsed, inbound bool) {
	if pkt.IPProto != ipproto.UDP && pkt.IPProto != ipproto.TCP {
		return
	}
	ip := pkt.Src.Addr()
	if inbound {
		ip = pkt.Dst.Addr()
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.managed[ip] {
		p.recent[ip] = p.now()
	}
}
func (p *PacketActivity) Activity(profile string, ip netip.Addr) ActivityState {
	p.mu.Lock()
	defer p.mu.Unlock()
	if profile != p.profile || !p.managed[ip] {
		return ActivityUnknown
	}
	if at, ok := p.recent[ip]; ok {
		age := p.now().Sub(at)
		if age >= 0 && age < p.idle {
			return ActivityActive
		}
	}
	return ActivityUnknown
}

type CombinedActivity struct{ Kernel, Packets ActivityProvider }

func (p CombinedActivity) Activity(profile string, ip netip.Addr) ActivityState {
	for _, provider := range []ActivityProvider{p.Kernel, p.Packets} {
		if provider != nil && provider.Activity(profile, ip) == ActivityActive {
			return ActivityActive
		}
	}
	return ActivityUnknown
}

func (p *PacketActivity) Configure(maxEntries int, idle time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.max = maxEntries
	p.idle = idle
}
