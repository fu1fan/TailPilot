// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package resolver

import (
	"net/netip"
	"testing"
)

// systemd-resolved's stub addresses may route tailnet split-DNS names back
// through tailscale0 and re-enter the local Connector PeerAPI. PeerAPI must not
// use them as explicit upstreams; the configured non-loopback upstreams are
// used instead. Other loopback stubs keep the historical behavior.
func TestPeerDNSUpstreamsAvoidLoopbackStub(t *testing.T) {
	for _, tc := range []struct {
		ns      string
		bypass  bool
		wantOne string
	}{
		{"127.0.0.53", true, ""},
		{"127.0.0.54", true, ""},
		{"127.0.0.1", false, "127.0.0.1:53"},
		{"::1", false, "[::1]:53"},
		{"8.8.8.8", false, "8.8.8.8:53"},
		{"192.0.2.53", false, "192.0.2.53:53"},
	} {
		t.Run(tc.ns, func(t *testing.T) {
			resolvers, bypass := peerDNSUpstreams(netip.MustParseAddr(tc.ns))
			if bypass != tc.bypass {
				t.Fatalf("bypass=%v want %v", bypass, tc.bypass)
			}
			if tc.wantOne == "" {
				if len(resolvers) != 0 {
					t.Fatalf("unexpected upstreams: %+v", resolvers)
				}
				return
			}
			if len(resolvers) != 1 || resolvers[0].name.Addr != tc.wantOne {
				t.Fatalf("resolvers=%+v want %s", resolvers, tc.wantOne)
			}
		})
	}
	// The Tailscale service IP and the empty address are handled by the
	// existing no-explicit-upstream path, not as loopback stubs.
	for _, ns := range []string{"100.100.100.100", "fd7a:115c:a1e0::53"} {
		if _, bypass := peerDNSUpstreams(netip.MustParseAddr(ns)); bypass {
			t.Fatalf("%s reported as loopback stub", ns)
		}
	}
}
