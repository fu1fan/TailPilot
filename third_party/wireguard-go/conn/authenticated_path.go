// SPDX-License-Identifier: MIT

package conn

import "net/netip"

// PacketKind identifies an authenticated WireGuard message. Cookies are never
// authenticated peer traffic and do not pass through this interface.
type PacketKind uint8

const (
	PacketInitiation PacketKind = iota + 1
	PacketResponse
	PacketTransport
	PacketKeepalive
)

type TransportKind uint8

const (
	TransportUnknown TransportKind = iota
	TransportDirect
	TransportRelay
	TransportDERP
)

// TransportContext is a value snapshot owned by one received packet. It must
// not contain pointers to mutable endpoint caches or recycled batch storage.
// RelayVerified means an authenticated relay handshake was captured, NOT that
// the Geneve header itself authenticates the path. RelayPeer binds that session
// to its terminal peer; DERPSource is the server's claim, not the Noise identity.
// Generation is the receiver's configuration generation at packet ingress.
type TransportContext struct {
	Kind          TransportKind
	Endpoint      netip.AddrPort
	Generation    uint64
	DERPRegion    int
	DERPSource    [32]byte
	RelayVNI      uint32
	RelayVerified bool
	RelaySession  uint64
	RelayServer   [32]byte
	RelayPeer     [32]byte
}

// AuthenticatedPathEndpoint is optional. Implementations must keep the context
// immutable until all asynchronous processing of the packet is complete (not
// merely until ReceiveFunc returns). AllowAuthenticatedPeer must be a pure,
// bounded predicate: no locks, IO, callbacks into Device, or health updates.
// It can run under handshake locks; transport calls precede replay acceptance
// and therefore may include replayed packets. Identity comes only from Noise
// authentication, never from a sender index or a transport source claim.
// Endpoints without this interface retain the upstream receive behavior.
type AuthenticatedPathEndpoint interface {
	TransportContext() TransportContext
	AllowAuthenticatedPeer(peerPublicKey [32]byte, kind PacketKind, context TransportContext) bool
}

func AllowAuthenticatedPeer(ep Endpoint, key [32]byte, kind PacketKind) bool {
	if ap, ok := ep.(AuthenticatedPathEndpoint); ok {
		return ap.AllowAuthenticatedPeer(key, kind, ap.TransportContext())
	}
	return true
}
