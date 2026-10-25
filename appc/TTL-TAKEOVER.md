# Connector TTL takeover: R24 integration and acceptance boundary

R35 update: committed-release upgrade/reverse and durable TTL enable/disable
adapters now have isolated native Linux/systemd acceptance. See
[`deploy/prod/README.md`](../deploy/prod/README.md) and
[`evidence/round35.md`](../evidence/round35.md). The R24 text below is historical;
production rollout still requires separate target/OOB/E2E approval.

**R24 PARTIAL — do not deploy.** The daemon now installs the Connector authority;
its independent LeaseController writer has been removed. Remaining work is
native daemon/profile/concurrency and deployment acceptance, not a second TTL
publisher. The handoff workspace records commands and limitations in
`work/impl-log/round24.md` and `astra/08-appc-ttl-takeover-design.md`.

## Implemented data path

`unified_takeover_runtime.go` installs `InstallTTLTakeover`, restores the journal,
and uses `ConfigureTTL` for assignment/policy updates. Final returned DNS wire
passes through the lifecycle mailbox to the Connector's captured observer.
`SweepTTL`, adoption, reset, rollback, time confirmation and handoff use the same
Connector commit callback. No daemon `NewLeaseController`, `RecordDNSAt`,
`ReconcileAt` or independent `Auto[leases]` publisher remains. The old
`unified_lease.go` is removed; old clear execution is rejected. Historical lease
and clear sidecars are read/recovered only for migration.

`unified_takeover.go` writes one checksummed, profile-scoped V2 intent containing
before/after Connector state and lease bytes, before/after ledger, unclaimed
provenance, route sets, approval hash, claims, full-prefs hashes and reset evidence.
The durable sequence is intent -> lease projection -> compatibility RouteInfo ->
owner ledger -> prefs -> complete marker. Only then are live prefs and Connector
tables installed and DNS acknowledged, including the zero-wait setting.
The backend barrier excludes prefs/netmap/profile writers during persistence.

A multi-key StateStore is not physically atomic: a power cut may leave projections
partly written. No failed operation is acknowledged as applied. The live Connector
is quarantined and backend prefs writes freeze until restart; startup gates legacy
writers and replays the intent before installing a new consumer. Replay refuses
unexpected external route edits rather than overwriting them. A conflicting or
corrupt journal requires investigation; there is no force-replay switch.

## Provenance and ownership

Installation saves old `RouteInfo.Domains` as **unclaimed evidence**, separate from
TTL-managed learning. Existing sidecar lease evidence is restored without a new
publisher. Unclaimed routes remain protected; no /32 inference or adopt-all exists.
A protected adoption preview enumerates each domain/IP, matched current root,
eligibility/reason, current and legacy source IDs, generation and hash. Only
explicit references selected from that current preview can be adopted. The intent
records those claims and their approval hash. Adoption changes ownership without
changing advertisements; later lifecycle operations project the resulting union.

Reviewed legacy references have unknown TTL and do not expire until replaced by
an actual observation of that same root/domain/IP or cleared by reset. Shared
unclaimed domain/IP references continue protecting the advertisement. A claim
removes legacy ambiguity and obsolete `appc-legacy-control` provenance only;
manual, current static control, Exit Node and other owners remain independent.
Control-only history lacking domain/IP evidence stays protected unless an explicit
reviewed manifest matches its persisted historical Control entry. R24 implements
that import through the same adoption transaction; arbitrary unknown-only host
prefixes cannot be imported. A prior unified owner-ledger marker is not required:
upstream Control evidence plus reviewed Reference details is sufficient.

## Local operations (isolated test hosts only)

CLI entries are under `tailscale debug`; no command below was run on production.
Both default to preview and require a nonempty audit source:

```
tailscale debug appc-route-adopt --source review-ticket
tailscale debug appc-route-reset --source review-ticket
```

Responses put the plan in `clear_preview`. Adoption has `Entries` with explicit
`Reference` objects (`AssignedRoot`, `Domain`, `IP`). Write only reviewed eligible
references into a JSON array, then pass it using `--claims reviewed.json`.
Execution also requires `--execute`, `--expect-sha256`, `--expect-generation` and
`--expect-source-id`, copied from the corresponding preview. Keep `--source`
identical: it is part of the binding. No automatic claims selection is provided.

Reset preview lists exact `Withdraw`/`Retain`, reasons for retained prefixes,
domain/IP learning, current roots/wildcards/static control, revision, fence and
hash. Execute removes **all managed learning references**, including shared-route
references, while retaining other owners and current configuration. The same DNS
can relearn immediately. It does not clear identity or require a daemon restart.
Unclaimed history is retained until separately reviewed and adopted.

For rollback, obtain a fresh reset preview after execution and pass its binding
with `appc-route-reset --rollback`. The last reset checkpoint survives restart
installation. Any subsequent DNS/sweep/configuration/adoption transaction or
owner/full-prefs change invalidates it. Old deadlines are restored, never extended;
restored time remains untrusted until explicit time confirmation.

LocalAPI uses the existing authenticated `POST /localapi/v0/debug` actions:
`appc-route-adopt-preview`, `appc-route-adopt`, `appc-route-reset-preview`,
`appc-route-reset`, `appc-route-reset-rollback`. All require `PermitWrite`.
JSON fields are `source`, `expect_sha256`, `expect_generation`, `expect_source_id`
and (adoption only) `claims`. The body is bounded at 1 MiB, sufficient for the
810-reference fixture. The legacy `unified-auto-clear` execution is retired.

## Configuration and handoff

Schema v2 uses `app_connector_ttl` with the existing timing/activity/capacity
parameters. Strict v1 inputs are translated to normalized v2, with inspection
reporting `migration: "migrated-from-v1"`. Mixing `lease` and
`app_connector_ttl` is rejected. v1 never selects an old writer. DNS IPv4-only,
automatic IPv6 gating and path policy continue using the existing shared config.
Release examples and deployment tools now require strict all-off v2, with no
`lease` field. Both schema copies are packaged and the recovery payload pins v2.
Fake-host deployment/rehearsal passes; native VM v2 acceptance remains pending.
For a future upgrade, translate v1 to all-off v2 first, complete the all-off
rehearsal and review migration evidence, then separately enable
`app_connector_ttl`. Never run an old v1 lease writer alongside the new daemon.
Runtime v1 translation supports compatibility; it is not deployment permission.

All-off/TTL-disable commits handoff before detaching the observer. Cold disabled
startup can finish an interrupted handoff. Profile retirement uses the captured
old profile namespace and preserves its advertisements. Handoff keeps compatibility
learning/configuration plus unclaimed evidence, without editing identity. These
paths are implemented, but the full native profile-switch/power-cut matrix is a
remaining deployment gate. Do not downgrade an active V2 journal without completing
handoff and verifying compatibility on an isolated host.

## Evidence limits

Production journal/projection tests cover 810 old references, exact reset/relearn,
shared/manual/static/default/unknown retention, six durable write points with
before/after failures, restart rollback, full preview bindings, handoff and external
CAS conflicts. Existing core tests cover renewal, expiry/grace, bounded activity,
clock uncertainty and concurrent Connector calls. Focused normal/race checks pass.

Lead's supplied R23 Linux package normal/race and `TestConnectorDaemonReset`
evidence is PASS; the earlier Mac sandbox socket failures are not an R23 blocker.
R24 focused normal/race and full portable packages pass locally. New daemon
fixtures cover control-only 810 adoption/reset/rollback/relearn, all-off/TTL-off,
profile namespace handoff, DNS/prefs/netmap concurrency and reset write failures.
They compile for Linux amd64, but their Linux execution is still pending. Mac
execution stops at fake-engine construction (`operation not permitted`).
These fixtures drive real backend consumers/transactions with a fake engine;
they do not yet prove socket CLI-to-LocalAPI-to-daemon E2E or the complete live
worker/profile/power-loss matrix. G4 real network, route propagation, native VM
v2 rehearsal, and production E2E remain unclaimed.

## Reviewed external control proof (R24)

An external manifest is a local operator attestation, not an authenticated control
API result. The daemon does not fetch its Evidence string or verify the referenced
file bytes. Review those bytes independently and retain them with the manifest.
The envelope binds the profile and historical SourceID from the current preview;
zero is allowed only when the historical persisted SourceID is itself zero.
Every entry requires an explicit Reference, Reviewed=true, reviewer, evidence
locator/description and a 64-hex SHA256. Maximum 2,000 references per manifest;
LocalAPI request limit remains 1 MiB, including claims. Example (fictional):

```json
{
  "SchemaVersion": 1,
  "ProfileID": "reviewed-profile",
  "LegacySourceID": 77,
  "Source": "offline-review-ticket",
  "Entries": [{
    "Reference": {
      "AssignedRoot": "*.example.test",
      "Domain": "www.example.test",
      "IP": "192.0.2.1"
    },
    "Reviewed": true,
    "ReviewedBy": "reviewer",
    "Evidence": "offline archive record 42",
    "EvidenceSHA256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  }]
}
```

Preview with `tailscale debug appc-route-adopt --source review-ticket
--manifest reviewed-proof.json`. Entries explain eligibility and retention;
`ManifestSHA256` hashes the typed canonical JSON, while `SnapshotHash` also binds
the backend, full prefs digest, current generation/source lifetime and audit
source. No writes occur in preview. Execute with the same manifest/source, an
explicit `--claims reviewed-refs.json` subset and all three expected bindings.
The LocalAPI JSON field is `manifest`; action names and PermitWrite are unchanged.
Unknown manifest fields, unreviewed/malformed proofs, duplicate references and
stale bindings are rejected. There is no adopt-all flag or /32 heuristic.

A reference must match an advertised exact prefix in persisted historical
Control and a current assigned root/domain. Current static control and manual/
default owners are ineligible for external import; unknown-only prefixes remain
protected. Other static/shared owners are never removed. All eligible manifest
references enter unclaimed provenance together, so selecting only one of several
shared-domain references leaves the others protected. Selected references become
unknown-TTL Legacy learning and can then be reset or replaced by real DNS.

The existing checksummed intent records the exact approved preview hash, selected
claims, original unclaimed state and all accepted import receipts. Receipts survive
later DNS/reset/install transactions, deduplicate identical manifests, and have a
4 MiB aggregate limit; exceeding it fails closed. Import leaves advertisements
unchanged, so its persistence adapter has five actual writes (no prefs delta).
Write-before/write-after recovery tests cover each. Do not mistake the proof hash
for authentication of its author's assertions.

## DNS filtering and IPv6 route learning

`dns_ipv4_only.enabled` filters the target-domain response returned to clients:
AAAA records and HTTPS/SVCB IPv6 hints are removed. Route observation uses a
separate validated view of the same upstream response, retaining both address
families and their chain/TTL limits. Durable route observation completes before
the filtered response is returned; a failed managed commit returns SERVFAIL.
IPv6 hints are recorded as ordinary TTL evidence alongside AAAA addresses.

To retain learned IPv6 routes, leave `auto_ipv6` disabled or configure it with
`enabled: true, publish: true`. An explicit `publish: false` continues to block
automatic IPv6 publication independently of DNS answer filtering. Both servers
use the same executable; assignment and policy remain configuration driven.

This covers addresses observed by the connector. It cannot recover arbitrary
addresses cached only on a client, enumerate all wildcard subdomains, or keep
routes beyond their lease lifecycle merely because a client retained a stale
cache. No proactive AAAA refresh or all-IPv6 catch-all route is introduced.

The isolated native regression is selected with `R6_DUALSTACK=1` through
`lab/appc-e2e/systemd-scale.sh`; it checks 32 concurrent filtered AAAA responses,
IPv6 advertisements and TTL ownership surviving SIGKILL and daemon restart.
