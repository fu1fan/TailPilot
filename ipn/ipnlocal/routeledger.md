# Route ownership core (Patch 02)

This is a tested journal/ownership core, not an installed daemon feature.
No LocalBackend field, LocalAPI handler or appc event subscription activates it.
The unmodified upstream paths therefore remain the default and only live paths.

## Contracts

- RouteOwnerEvent is a complete replacement for one owner's contribution.
  Automatic OwnerID must identify one canonical lease, never only an IP.
  Manual is a full list; a /0 is an exit-default owner. Control uses explicit IDs.
  Readvertise recomputes existing ownership and grants no new ownership.
- Each ledger belongs to one profile/fence. Sequence is contiguous. Stale,
  foreign or reordered updates fail without prefs changes; the coordinator must
  resynchronize complete desired state, not blindly retry old incremental diffs.
- All previously unexplained prefs routes become legacyUnknown, including old
  RouteInfo.Domain matches. MigrationDryRun binds prefs, control/domains and
  fence to a SHA256. ValidateClaims checks a reviewed candidate manifest but
  intentionally has no adoption operation. Control/default/manual owners are
  never surrendered by migration.
- Only automatic host advertisements may be suppressed by a covering non-default
  route. References remain present while covered. /0 does not suppress hosts.
- Store.Save(intent) precedes Apply; Store.Save(applied) follows it. Failure after
  intent blocks further events until Recover. Unexpected external additions are
  protected before replay. A corrupt journal blocks opening. Pending intents from
  another epoch are rejected, not replayed with the new epoch's authority.
- UnifiedLedgerStore and UnifiedPolicyStore use independent profile sidecars
  through ipn.StateStore, independent of AppCStoreRoutes. The actual backend CAS
  and durable prefs callback are still missing. No sensitive prefs bytes are read
  by these adapters.

## Lease model boundary

appc.LeaseBook records actual returned TTL, independent domain/chain references,
renewal, grace, dwell, bounded activity interface, capacity and deterministic
batch sweep with injected time. It never performs a DNS cap on its own.
MarshalState/RestoreLeaseBook preserve remaining deadlines with a checksum;
backward time and observed in-process anomalies freeze deletion. Full boot/time
trust, jitter scheduling, durable sweep delivery and conntrack belong to further
integration. Sweep results must become fenced owner events, durably acknowledged
before any consumer assumes a withdrawal completed. DNS parsing is not present.

## Blocking integration findings (v1.102.3 53a0d659a)

- local.go:726 has unscoped asynchronous RouteUpdate delivery.
- local.go:5139,5161 and localapi/localapi.go:1016,1024 clear appc and treat a
  full-list edit as an ordinary user edit. Source marking is not yet changed.
- local.go:8498,8558 internal advertise/unadvertise use the same EditPrefs path;
  :5982 readvertisement lacks a captured profile/epoch and owner ID.
- local.go:5487 setPrefsLocked mutates runtime state and :5540 logs SetPrefs
  persistence errors instead of returning them. profiles.go:514 changes pm.prefs
  and emits callbacks before :546 attempts persistence. Calling EditPrefs and
  marking the journal applied would therefore falsely acknowledge durable prefs.

Before enabling this core, implement a staged, durable prefs write path that
returns persistence failures, preserves authorization checks and serializes
profile/fence validation with apply. Then connect manual, control, per-domain
appc and readvertise sources, including profile transitions and netmap deltas.
These are remaining R1 requirements, not deferred acceptance disguised as Patch03.

## Test coverage boundary

routeledger_test.go exercises U-L06 through U-L09 with a fake durable prefs store,
plus stale/foreign/concurrent event rejection from U-L10. unified_store_test.go
checks namespace isolation in ipn/store/mem. The fake store's atomic CAS contract
is stronger than today's actual EditPrefs implementation; passing these tests
must not be reported as actual backend integration acceptance.
