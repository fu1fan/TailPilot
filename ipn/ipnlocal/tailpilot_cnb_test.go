// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build tailpilot_cnb_test

package ipnlocal

import "tailscale.com/net/netns"

func init() {
	// Match cmd/tailscaled's --tun=userspace-networking startup. CNB cannot
	// mark sockets or bind them to devices. This file only enters test binaries;
	// the real daemon integration tests exercise the ordinary startup path.
	netns.SetEnabled(false)
}
