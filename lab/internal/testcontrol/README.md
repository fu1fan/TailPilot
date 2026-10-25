Lab-only fork of `tstest/integration/testcontrol/testcontrol.go` at 6dd785ec7.
Upstream license retained. Production and upstream testcontrol are unchanged.

The upstream helper deliberately launches asynchronous panics on malformed input.
An HTTP recovery wrapper around that original helper cannot contain them. This
copy makes those failures synchronous, catches them at both plaintext and Noise
HTTP boundaries, and replaces the unhandled endpoint with 404. Only key,
connectivity check, Noise upgrade, and the four required machine endpoints are
allowed. TKA, webclient, c2n and other upstream features are intentionally disabled.

Bounds: 1 MiB body, 64 active requests, 32 HTTP/2 streams, two-minute Noise
connection lifetime (clients reconnect). The executable also limits listener
connections, headers, header/read/idle times and binds all TCP/UDP endpoints to
loopback by default. Explicit RFC1918 bridge binding remains for g4 netns runs.
This is unauthenticated test infrastructure, never an Internet-facing service.
Future upstream synchronization must preserve guard placement on BOTH transports.
