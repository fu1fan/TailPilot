// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package appc

import (
	"bufio"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ConntrackActivity refreshes a bounded read-only conntrack snapshot off the
// lease path. Activity never performs I/O or waits on a kernel dump. A missing,
// truncated, malformed or stale source is Unknown, not proof of inactivity.
//
// UNVERIFIED: procfs visibility across forwarding namespaces/NAT must be checked
// in Linux lab tests. Absence is therefore Unknown, even after a complete scan.
// UDP timeout values are not packet timestamps. UDP rows alone never establish
// recent activity; the authenticated packet observer supplies UDP idle evidence.
type ConntrackActivity struct {
	refreshMu sync.Mutex
	mu        sync.Mutex
	profile   string
	managed   map[netip.Addr]bool
	maxRows   int
	cacheTTL  time.Duration
	now       func() time.Time
	read      func() (io.ReadCloser, error)
	updated   time.Time
	active    map[netip.Addr]bool
	valid     bool
}

func NewConntrackActivity(profile string, managed []netip.Addr, maxRows int, cacheTTL time.Duration, now func() time.Time, read func() (io.ReadCloser, error)) *ConntrackActivity {
	if now == nil {
		now = time.Now
	}
	p := &ConntrackActivity{profile: profile, managed: map[netip.Addr]bool{}, maxRows: maxRows, cacheTTL: cacheTTL, now: now, read: read}
	// Bound destination state as well as the streamed flow table.
	if len(managed) > maxRows {
		p.maxRows = 0
		return p
	}
	for _, ip := range managed {
		if ip.IsValid() {
			p.managed[ip.Unmap()] = true
		}
	}
	return p
}

func (p *ConntrackActivity) Refresh() error {
	p.refreshMu.Lock()
	defer p.refreshMu.Unlock()
	p.mu.Lock()
	p.valid = false
	p.mu.Unlock()
	if p.read == nil || p.maxRows <= 0 {
		return fmt.Errorf("conntrack: unavailable or invalid budget")
	}
	r, err := p.read()
	if err != nil {
		return err
	}
	defer r.Close()
	scan := bufio.NewScanner(r)
	scan.Buffer(make([]byte, 4096), 64*1024)
	active := map[netip.Addr]bool{}
	rows := 0
	for scan.Scan() {
		rows++
		if rows > p.maxRows {
			return fmt.Errorf("conntrack: row budget exceeded")
		}
		fields := strings.Fields(scan.Text())
		// nf_conntrack has family, family-number, protocol, protocol-number, timeout.
		if len(fields) < 5 {
			return fmt.Errorf("conntrack: malformed row")
		}
		timeout, err := strconv.ParseUint(fields[4], 10, 32)
		if err != nil {
			return fmt.Errorf("conntrack: invalid timeout")
		}
		proto := fields[2]
		// Other valid protocols cannot establish TCP/UDP activity.
		if proto != "tcp" && proto != "udp" {
			continue
		}
		var src, dst []netip.Addr
		established := false
		for _, f := range fields[5:] {
			if f == "ESTABLISHED" {
				established = true
			}
			if strings.HasPrefix(f, "src=") || strings.HasPrefix(f, "dst=") {
				ip, err := netip.ParseAddr(f[4:])
				if err != nil {
					return fmt.Errorf("conntrack: invalid tuple")
				}
				if f[:3] == "src" {
					src = append(src, ip.Unmap())
				} else {
					dst = append(dst, ip.Unmap())
				}
			}
		}
		if len(src) != 2 || len(dst) != 2 {
			return fmt.Errorf("conntrack: incomplete tuple")
		}
		if timeout == 0 || proto == "udp" || !established {
			continue
		}
		// Original destination and reply source cover common DNAT/SNAT layouts;
		// neither source is used to infer another profile's absence of activity.
		for _, ip := range []netip.Addr{dst[0], src[1]} {
			if p.managed[ip] {
				active[ip] = true
			}
		}
	}
	if err := scan.Err(); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.active = active
	p.updated = p.now()
	p.valid = true
	return nil
}

func (p *ConntrackActivity) Activity(profile string, ip netip.Addr) ActivityState {
	p.mu.Lock()
	defer p.mu.Unlock()
	age := p.now().Sub(p.updated)
	if profile != p.profile || !p.managed[ip] || !p.valid || age < 0 || age > p.cacheTTL {
		return ActivityUnknown
	}
	if p.active[ip] {
		return ActivityActive
	}
	return ActivityUnknown
}
