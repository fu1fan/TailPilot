# Unified policy debug interfaces (Patch08, unstable)

These are local development interfaces, not a new stable API. No listener,
control-plane token, remote service, approval writer, or clear operation is added.

## LocalAPI and CLI

Existing `/localapi/v0/debug` dispatch and authentication apply. All three actions
require POST **and PermitWrite**, even status/preview which are read-only.
PermitRead alone is insufficient. Existing host/origin/socket access checks remain.
Actions may be supplied as `?action=...` or `Debug-Action` header.
Debug-omitted builds do not expose these actions.

* `unified-policy-status`: no request body required; returns the redacted status.
* `unified-policy-preview`: JSON `{ "file": "/absolute/trusted/policy.json" }`;
  omit `file` to read the daemon's configured file. Reads use the existing
  root-owned 0600, regular, <=1 MiB, trusted-parent, no-symlink policy reader.
* `unified-policy-reload`: JSON `{ "expect_generation": 1,
  "expect_sha256": "<64 lowercase hex digits>" }`. File selection is forbidden.
  CAS compares the current accepted generation and SHA256 of **requested file
  bytes**, not the previous source hash or canonical hash. A conflict is HTTP 409;
  input, trust or persistence errors are HTTP 400 with redacted error codes.
  The LKG is unchanged on failure. Normal independent periodic reload still runs.

Request bodies are limited to 8 KiB; unknown fields and trailing JSON are rejected.
No configuration body, token, or private key is accepted by these actions.
Preview and reload are serialized through the existing lifecycle worker, with
profile/input-epoch checks. Preview does not invoke consumer stages, save LKG,
change generations, reset the poll timer, or trigger reconciliation. A canceled
request is rejected before mutation when observed; cancellation cannot undo a
commit already completed. File/store I/O retains the existing synchronous contract.

```
tailscale debug unified-policy validate --file policy.json [--offline]
tailscale debug unified-policy preview --offline --file policy.json
tailscale debug unified-policy preview [--file /absolute/trusted/policy.json]
tailscale debug unified-policy reload --expect-generation 1 --expect-sha256 HASH
tailscale debug unified-policy status --json
```

All output is JSON (`--json` is accepted for convenience). Validate is always
offline. Offline reads allow user-owned regular files, enforce the size/schema
limits, and do **not** certify daemon file trust. No daemon call occurs offline.
Invalid arguments, validation errors and online failures return a nonzero exit.

## Fields and evidence boundaries

Inspection results:

| Field | Meaning |
|---|---|
| `schemaValid` | Strict parser and semantic validator accepted the bytes. |
| `runtimeReady` | Online trusted-input compilation has no pending selectors; preview additionally checks durable-store and required consumer availability. Offline always false. This is not transport health or lab proof. |
| `accepted` | This reload committed to Manager/LKG. Preview/validate always false. |
| `applied` | Preview/validate/reload responses always false; query status for subsequent consumer completion. |
| `requested_sha256`, `canonical_sha256` | Requested source-byte digest and normalized configuration digest. Never configuration contents. |
| `changed`, `changedModules` | Difference from the currently accepted config; fixed module names only, no selectors/targets. Offline has no baseline and reports no inferred diff. |
| `pendingRules` | Count of unresolved rules, not their IDs. |
| `accepted_generation` | Newly accepted reload generation; zero for an inspection. |
| `applied_generation` | Zero in inspections/acceptance acknowledgement. |
| `pending_side_effects` | True after reload acceptance pending status observation. |
| `offline`, `error` | Explicit context and redacted diagnostic code. |

Status includes `schemaValid`, `runtimeReady`, `accepted`, `applied`,
`acceptedFence`, `appliedFence` (Generation, local ProfileID, AssignedDomainsEpoch,
PeerIdentityEpoch), `source_sha256`, `canonical_sha256`, `reconciling`, `degraded`
(boolean, never the raw internal error), `pendingRules`, `enabledModules`, and
`moduleApplied`. Module application is conservative: all modules are reported
applied only when the complete accepted fence is applied. A changed input epoch
immediately invalidates applied reporting. Disabling a module does not mean old
owner evidence was cleared. A bad disk file can coexist with a valid running LKG.

`ownerPrefixes` counts committed owner entries. `ownerConflicts` counts automatic
entries also held by non-auto owners (protected sharing, not proof of corruption).
`ipv6Shared` and `ipv6Unknown` summarize the existing diagnostic predicates.
`paths` groups statuses by fixed `state/active/reason`, omitting peer and rule IDs.
`dropCounters` is the per-Conn fixed-bucket count described below (null if no Conn).

`leaseCount`, `timeUncertain`, `oldestExpiredLeaseSeconds` are worker-sampled lease
summaries. Null time/age means no controller sample, not false/zero certainty.
Expired age is `max(now - lease.Expires, 0)`; it includes intentionally retained
leases and is **not** DNS queue latency or proof that a route should be removed.
`ownerQueueAgeSeconds` is the age of the current serialized owner/prefs persistence
transaction, zero when idle; it is not the age of every producer waiting upstream.
Status reads the committed view without waiting for that transaction to finish.
There is no newly instrumented DNS queue, and no full domain/IP/peer detail mode.

## Metrics

Existing DNS counters remain. Added clientmetric counters:

* `unified_policy_reload_accepted`, `unified_policy_reload_rejected`: explicit
  debug reload requests processed by the worker, not periodic watcher activity.
* `unified_path_{send|probe|receive}_{direct|peer_relay|derp|unknown}_policy_deny`:
  exactly 12 process-wide buckets. Status uses corresponding per-Conn counters.

Counters describe **denied decisions**, not unique packets. Send checks may occur
at enqueue and final send; receive rejects can include authenticated replay
candidates. Receive accounting is outside the pure policy predicate and only
uses atomic increments; FromPeer's health recheck is not counted again. It does
not alter replay/health acceptance, wire protocol, or the WireGuard dependency.
No peer, domain, IP, rule ID, payload, or unbounded reason becomes a metric label.
Default-off accepted traffic does not increment these counters.

## Offline route-reconcile

`cmd/route-reconcile` reads one JSON snapshot from stdin (<=4 MiB). It has no
network client, credential input, daemon integration, or approval mutation code.
Example invocation with Lead-provided, separately sanitized snapshots:

```
route-reconcile --device DEVICE --expect-generation 7 --expect-version VERSION < snapshot.json
```

Snapshot schema:

```json
{
  "stableID": "DEVICE",
  "generation": 7,
  "advertiseRoutes": ["10.1.0.0/16"],
  "tombstones": [
    {"prefix":"10.0.0.1/32","generation":7,"exclusiveModuleOwned":true}
  ],
  "control": {"stableID":"DEVICE","version":"VERSION","enabledRoutes":["10.0.0.1/32"]}
}
```

Both StableIDs and expected generation/version must agree. This is an **offline
snapshot consistency check**, not evidence of server CAS or snapshot freshness.
Prefixes must be canonical. Unknown/duplicate JSON fields, duplicate tombstones,
future tombstones, malformed inputs and trailing JSON are rejected without echoing
input. Tokens are not part of the schema or command flags.

`removeCandidates` includes only enabled routes with same-generation exclusive
module tombstones, excluding default routes and every prefix overlapping current
advertisements. Older/partial/unknown ownership is retained. `add` is always empty.
Results contain explicit risks and a manual re-read/review/read-back checklist.
Local tombstones alone cannot prove exclusive ownership of remote approvals.

`--apply` always fails **before reading input**, even if input claims CAS support.
No verified server-side CAS adapter exists in this patch, so no apply/retry/rollback
implementation is reachable. Consequently 429, 412 and partial remote writes
cannot occur here; tests prove refusal, not simulated successful remote recovery.
Any future adapter requires a separate reviewed change with authenticated CAS,
pre-write re-read, post-write read-back, and explicit partial-failure handling.
No autoApprovers, new approvals, other devices or production state are modified.

R13 boundary clarifications:

* DNS uses a cooperative 5-second context after HTTP request parsing, shared by
  resolver processing and the bounded route waiter. It is not a hard total HTTP
  budget: request body reading, backend mutex acquisition, legacy synchronous
  observer/StateStore I/O and an uncooperative resolver may block longer. Context
  checks before resolution and after every external processing stage prevent a
  late successful result from being observed or returned as success. Managed
  failures return SERVFAIL/no-store; canceled unrelated requests return an error.
  No goroutine is created to abandon a blocked operation. Queue timeouts do not
  undo a durable write already in progress; lifecycle recovery remains responsible.
* `timeUncertain` deliberately favors retaining routes over enforcing the maximum
  retention deadline. Confirmation never renews TTL/grace/hard deadlines. Restore
  preserves expired wall deadlines and may shorten still-live intervals using
  the minimum of saved remaining time and wall remaining time. An authorized LocalAPI caller's explicit
  `confirm_time`, source and matching generation/hash assert that Lead checked the
  clock; the API does not authenticate a distinct organizational Lead role or
  independently measure trusted elapsed time. The audit record is historical,
  never a reusable trust token. Every backend cold restore freezes again, even when wall
  time is unchanged. Forward/backward clock jumps refreeze after confirmation.
* R13 loopback transport tests use the real Resolver.Query TCP-family forwarder
  (also used by HandlePeerDNSQuery), with explicit test-server routes. They test
  UDP-complete, UDP truncation/TCP retry, and disabled-retry fail-closed behavior.
  They do not cover OS stub selection, remote DNS, client route installation or
  cryptographic DNSSEC validation. Backend clear/restart acceptance remains a
  separate engine/socket test; deterministic store fault tests cover journal
  replay and repeated cold lease restore, not physical power loss.
