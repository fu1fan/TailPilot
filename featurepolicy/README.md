# Unified policy core (Patch 01)

Source contract: astra/03-config-spec.md in the handoff repository. schema.json is
its closed v1 structural vocabulary, copied at implementation time; config.go
implements defaults, duplicate rejection and additional semantic invariants.
config_types.go splits public data types out of config.go for readability.

Manager is independent of LocalBackend: Start, Reload, Recompile and Poll are
lifecycle entry points. Store must be atomic and durable, scoped to ProfileID.
Stage callbacks may only validate/build private state; live consumers read the
single Current pointer. No callbacks mutate live consumers before publication.
A successfully persisted prepare record is the restart LKG; recovery recompiles
it against fresh authenticated inputs before publication. Never reuse a manager
across profile transitions without Start. NodeView inputs must be the complete
trusted netmap (including applied deltas), not packet-derived claims.

Integration boundary: this patch deliberately provides no environment activation
or LocalBackend lifecycle wiring yet. No data-plane consumer reads this package;
therefore the upstream default remains unchanged. Connecting startup, profile
switch, netmap delta epochs and StateStore is still required for daemon use.
LocalAPI debug action belongs to Patch 08. Root-owned file checks fail closed on
platforms without Unix owner metadata. No production activation is claimed.

Baseline mounting points, v1.102.3 53a0d659a:
- ipn/ipnlocal/local.go:541 NewLocalBackend, :1366 shutdown context cancellation.
- local.go:7265 setNetMapLocked (must not do disk I/O under b.mu).
- local.go:5918 configureAppConnector collects actually assigned domains.
- local.go:8580 namespaceKeyForCurrentProfile scopes sidecar storage.

Tests cover parser/defaults, hash reload with same mtime, LKG, staged/persistence
failure, CAS, immutable concurrent readers, trusted identity rotation/removal,
first match and DNS assignment intersection. They are core tests, not daemon
lifecycle or production behavior acceptance.
