// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package appc

import (
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"
	"time"
)

// NewSystemActivity returns a procfs reader. Missing conntrack support or access
// errors are surfaced by Refresh and preserve bounded Unknown protection.
func NewSystemActivity(profile string, managed []netip.Addr, maxRows int, cacheTTL time.Duration) *ConntrackActivity {
	return NewConntrackActivity(profile, managed, maxRows, cacheTTL, time.Now, func() (io.ReadCloser, error) { return os.Open("/proc/net/nf_conntrack") })
}

func SystemBootID() (string, error) {
	data, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "", err
	}
	id := strings.TrimSpace(string(data))
	if len(id) != 36 {
		return "", fmt.Errorf("invalid boot ID")
	}
	return id, nil
}
