# Unified runtime integration status (R2)

This is not a production-ready activation path.

* `NewLocalBackend` checks the trusted policy file/profile LKG before starting.
  The policy worker captures profile, complete current NodeViews and assigned
  domains under `b.mu`, then does compilation/file/state I/O outside that lock.
  A changed input immediately invalidates the backend publication revision.
  Failed recompilation cannot relabel an old snapshot with a new revision.
* `UnifiedPolicyState` is an internal Go accessor. Accepted configuration is not
  evidence of applied route/DNS/path consumers. Selected consumers remain
  reconciling. No new LocalAPI debug or CLI action is present.
* `persistRouteCAS` writes the existing profile's complete current prefs with
  only AdvertiseRoutes changed. It checks the profile and before-set and returns
  storage failures before any in-memory installation. The backend installer
  does not perform a second prefs write. Default-off rejects this entry point.
* **UNVERIFIED / blocker:** durable route apply retains `b.mu` during StateStore
  I/O to exclude existing upstream profile writers. Lock order is coordinator ->
  backend -> store; never call this while holding appc.mu. Moving the write out
  requires a barrier shared by every profile/prefs writer, not an optimistic
  unlock/write/relock. Slow-store latency is not yet acceptable as the final
  architecture. There is no active route coordinator installed in R2.
* The optional AppConnector lease sink bypasses legacy learning only when
  explicitly installed. It parses CNAME/A/AAAA actual returned TTLs, and typed
  lease errors cause PeerAPI SERVFAIL. The default nil sink preserves upstream
  best-effort parsing. DNS TTL capping/IPv6 transformation is not implemented.
* LeaseController serializes observations and sweeps, persists a staged copy,
  then reconciles complete lease references. Reconcile failures retain durable
  evidence and retry on the next sweep. Boot provenance is saved; restoration
  without explicitly trusted time freezes deletion. A timer/clock and jitter
  can be injected. No deadline is freshly granted on restore.
* Linux conntrack procfs scans run outside the Activity call and are bounded.
  Cached established TCP/UDP evidence can protect a lease; absence, malformed
  tables, capacity, permission errors or stale data mean Unknown. NAT/namespace
  coverage, precise UDP idle accounting, kernel packet hooks and production
  resource/latency bounds remain **UNVERIFIED**.

Still required: active typed owner publisher/subscriber and single writer;
manual LocalAPI/EditPrefsAs/MaybeClearAppConnector union semantics with original
actor authorization; control/readvertise/legacy RouteInfo handoff; complete
migration and disable/re-enable barriers; connecting the lease controller and
sweep/activity lifecycle to that owner coordinator. Do not install the lease
sink independently of these barriers.

## R12 recovery and administrative actions

The disabled LKG is accepted only after `_unifiedHandoffV1=pending` is durable.
RouteInfo is written before `complete`; cold connector initialization sees the
marker and gates legacy writers. Failure retains ownership and reconciling state.
The ledger and lease sidecars survive disabling. This relies on StateStore's
single-key atomic/durable contract; fault tests simulate write boundaries, not
physical power-loss certification of every StateStore implementation.

LocalAPI debug actions use the existing POST + PermitWrite authorization. No
normal `set` clears automatic state. No CLI command was added.

* `unified-time-confirm`: JSON `confirm_time:true`, `source` (nonempty, <=200
  bytes, Lead's confirmation/evidence reference), `expect_generation` and
  `expect_sha256` (current policy source hash). The caller explicitly attests
  that Lead verified the clock. PermitWrite authenticates local administration,
  not an organizational Lead role. The action does not inspect NTP or infer
  trust. Source, timestamp and fence persist with leases; every restart requires
  fresh confirmation. Failed persistence never thaws the live book. Clock
  anomalies freeze sweeps again, without granting a new TTL/grace interval.
* `unified-auto-clear-preview`: read-only state preview, returns `clear_preview`
  with exact Withdraw/Retain and `requested_sha256`. Unlike ordinary redacted
  status, this authorized preview includes route prefixes. No request body other
  than `{}` is needed. `unified-auto-clear` consumes that hash in
  `expect_sha256`, the preview generation in `expect_generation`, and a nonempty
  `source` reference. Both live renewals and owner/prefs changes invalidate the
  preview. Only proven exclusive module-created auto prefixes lose their lease
  evidence and auto owners; shared/manual/control/exit/unknown state survives.
  Old recognized exclusive legacy auto owners are included. Unclaimed legacy
  routes remain unknown and cannot be cleared by this operation.

Clear writes a checksum-protected intent containing both authority candidates,
then leases, pending owner journal, prefs, applied journal, and completed audit.
The writer barrier and lease-controller lock exclude normal competing updates.
Any failure is NOT completion: the controller is quarantined and the lifecycle
worker recovers before installing consumers. Repeated recovery is idempotent;
unexplained added prefixes gain unknown ownership. Arbitrary out-of-process
same-prefix manual assertions cannot be distinguished from pre-crash state.
Ordinary profileManager writes cannot address `||_unified*` keys. Upstream
Start/profile writes are still multi-key and are NOT a universal transaction;
sidecar isolation is the tested boundary, not full upstream atomicity.

DNS uses a 64-entry mailbox on the existing lifecycle worker, with no new
per-request goroutine. Nonzero local_route_wait_ms includes queue/persistence/
local commit wait and is capped at 1000ms even if configuration says 2000ms.
It shares the handler's existing 5s context. Zero waits for durable evidence,
then releases the DNS waiter before local route reconciliation; it promises
neither route completion nor first-packet delivery. A later commit error is
reported degraded and retried from persistent evidence on sweep/reconfigure;
it cannot retroactively change an already acknowledged 0ms response. Failures
before acknowledgement, wait timeout, stale fences and cancellation produce
SERVFAIL + no-store for managed queries. Queue-full rejects immediately.
StateStore itself is synchronous and not cancelable: an in-flight write finishes
on the sole worker and shutdown joins it; cancellation does not roll back a
completed durable intent. Upstream legacy writers still perform some I/O under
backend locks, so this does not assert a hard wall-time bound on arbitrary
blocked legacy storage/resolver implementations that ignore context.

Protocol errors are classified before resolution with active DNS policy:
FORMERR for undecodable/multiple-question managed queries, NOTIMP for unsupported
managed opcode/class, SERVFAIL for resolver/transform/route failures. Default-off
and valid unrelated queries retain upstream behavior. Cross-response alias
association remains unsupported. DNSSEC tests assert wire flags/proof removal,
not cryptographic validation of synthesized answers. Handler tests use fake
UDP-complete/TC/TCP-complete outcomes; real UDP-to-TCP transport retry and I-D/E2E
remain outside this evidence.
