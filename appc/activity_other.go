// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !linux

package appc

import (
	"fmt"
	"net/netip"
	"time"
)

func NewSystemActivity(profile string, managed []netip.Addr, maxRows int, cacheTTL time.Duration) *ConntrackActivity {
	return NewConntrackActivity(profile, managed, maxRows, cacheTTL, time.Now, nil)
}
func SystemBootID() (string, error) { return "", fmt.Errorf("boot ID unavailable on this platform") }
