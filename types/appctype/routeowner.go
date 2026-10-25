// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package appctype

import (
	"net/netip"
	"tailscale.com/featurepolicy"
)

// RouteOwnerSource identifies why a route update was requested. A manual full
// list is distinct from automatic learning, control routes, or readvertisement.
type RouteOwnerSource string

const (
	RouteOwnerManual        RouteOwnerSource = "manual"
	RouteOwnerControl       RouteOwnerSource = "control"
	RouteOwnerAuto          RouteOwnerSource = "auto"
	RouteOwnerLegacyUnknown RouteOwnerSource = "legacyUnknown"
	RouteOwnerExitDefault   RouteOwnerSource = "exit-default"
	RouteOwnerReadvertise   RouteOwnerSource = "readvertise"
)

// RouteOwnerEvent is an ordered, fenced replacement for one owner's complete
// desired set. Auto OwnerID is a canonical lease ID, so two domains sharing an
// IP remain independent. Readvertise has no ownership mutation. It never grants
// permission to infer ownership from a legacy RouteInfo or a raw route diff.
type RouteOwnerEvent struct {
	Fence    featurepolicy.Fence
	Sequence uint64
	Source   RouteOwnerSource
	OwnerID  string
	Prefixes []netip.Prefix
}
