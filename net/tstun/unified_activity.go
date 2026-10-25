// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tstun

import "tailscale.com/net/packet"

type activityObserver struct{ observe func(*packet.Parsed, bool) }

// SetActivityObserver composes an observer with existing Conn25 interceptors;
// it never replaces their callbacks or changes their verdicts. Nil is default.
// A callback must not retain Parsed (pooled) or block on I/O/backend locks.
func (t *Wrapper) SetActivityObserver(observe func(*packet.Parsed, bool)) {
	if observe == nil {
		t.activityObserver.Store(nil)
		return
	}
	t.activityObserver.Store(&activityObserver{observe})
}
func (t *Wrapper) observeAcceptedActivity(p *packet.Parsed, inbound bool) {
	if o := t.activityObserver.Load(); o != nil {
		o.observe(p, inbound)
	}
}
