# Linux deployment executor — R24 (v2 configuration)

The nine phase scripts default to **dry-run**. `--execute` selects `native.py`;
the local fake-host suite does not establish native systemd/VM acceptance.
Supported scope is deliberately narrow: Linux amd64, apt daemon/CLI paths,
explicit reviewed ExecStart, file-backed state, all four modules OFF, no policy
rules/targets, and no existing unified-policy Environment override. Other layouts
fail closed. Python 3, systemd/systemd-run/systemd-analyze, ip, ss and apt-mark
must already be installed locally. Recovery downloads nothing.

## Public plan and approval

`plan.example.json` is fictional and remains safe for dry-run. For native use add
`native` as illustrated by `native-contract.example.json`. Every source file,
including the effective unit, all systemd-reported drop-ins/EnvironmentFiles,
configuration, state, RouteInfo/ledger and Lead-provided control snapshots must
be covered by `backupFiles` and `expectedBefore`. Nonexistent placeholders are
not acceptable for daemon/CLI/unit/state. Lead must supply complete state paths;
the adapter verifies the explicit live `--state=` and `--socket=` arguments.
Sources must remain stable between preflight and switch; otherwise replan.

All execute calls require the existing deployment-id/host/stable-id/release-sha256/
approved-plan-sha256 bindings, plus `--approval /root/reviewed-approval.json`.
Root-owned private evidence and all parent paths must be non-symlink and not
writable by other users. Approval is a local Lead attestation, not a cryptographic
signature or a replacement for G6. Its required fields are:

```json
{"deploymentID":"dev-fixture-001","host":"isolated-dev",
 "approvedPlanSHA256":"<exact plan digest>","expiresUnix":0,
 "serialWindowExclusive":true,"excludePeers":["management-fixture","codex-fixture"],
 "excludeDomains":["management.example.invalid","codex.example.invalid"]}
```

OOB evidence uses the R10 binding fields plus `host`, `independent:true`,
`rootRecovery:true`, `kind:"oob"`, `passed:true` and an unexpired `expiresUnix`.
No OOB credential is read. The fallback rehearsal file must include
`kind:"state-downgrade-rehearsal"`, `passed:true`, stableID, releaseSHA256 and
oldDaemonSHA256. It must also bind `host`. Produce it using the controlled target-host rehearsal below;
a different VM StableID cannot authorize this host.

A second-host plan requires the digest of a private predecessor evidence file
with `host`, terminal `phase` and `stable:true`. **Host locking is local.** The
exclusive cross-host window is a Lead/coordinator attestation; these scripts do
not implement a distributed lock. Lead must run one host to terminal external
stability before issuing the second approval. Never run the two hosts in parallel.

## Phase contract

1. **preflight:** validates live hostname/StableID/Tailscale IPs, package manifest,
   all-off configuration, OOB, fallback rehearsal, exclusions, complete effective
   unit inventory, live socket/state argv, resource floors, pending jobs, dpkg/apt
   lock availability and original AutoUpdate Check/Apply/apt hold. Pins local
   recovery code, plan, approval, original unit/argv, LKG daemon and CLI. Control
   snapshots are supplied by Lead; no control API is called.
2. **backup:** private readable snapshot (0700 directory, 0600 files), hashes and
   UID/GID/mode restore map; private live prefs and route/rule snapshots are also
   retained. No state contents go to stdout. LKG executable copies are 0700.
3. **stage:** installs a new `/usr/local/lib/tailscale-unified/<release>/`, verifies
   manifest, amd64 ELF, all-off schema using the new CLI, and the composed unit
   with systemd-analyze. Only the daemon executable token changes: `$FLAGS`, port,
   state/socket arguments and inherited EnvironmentFiles stay intact. Apt files
   and original configuration are never overwritten. A private versioned policy
   file is selected by the transaction drop-in.
4. **arm:** fsyncs pending journal and fixed monotonic/wall deadlines first;
   installs a persistent boot oneshot plus a tailscaled Requires/After drop-in;
   starts it harmlessly in the original boot, then creates an independent
   systemd-run monotonic timer with a complete absolute recovery argv. Reads back
   timer/ExecStart/guard activity and records payload hashes/modes. A failed arm
   attempts rollback; no switch is allowed without armed evidence.
5. **switch:** queues an independent `systemd-run --no-block` worker. Under the
   host lock it rechecks deadline, timer, expected-before and stage hashes, disables
   AutoUpdate Apply and holds apt (with readback), stops tailscaled, seals the final
   consistent snapshot, atomically writes its drop-in, reloads and starts. Any
   caught step failure invokes local rollback; process death/timeout leaves the
   independent timer/boot guard responsible for recovery.
6. **verify:** checks active/MainPID, proc executable pinned hash, CLI version,
   Running, StableID, Tailscale IPs, selected prefs, process UDP listener and
   applied all-off policy SHA/fence. This is **local-only**, never external E2E.
7. **commit:** only from verified, same lock as rollback, same boot and before
   both deadlines. Requires fresh external evidence and its digest passed as
   `--acceptance-sha256 SHA`; current approval must also bind `acceptanceSHA256`.
   This avoids trying to precompute a future acceptance file's hash in the plan.
   The proof at `externalEvidence` includes R10 fields (txn/StableID/release/config,
   passed, kind external-e2e, expiry), plus host, `deadlineUnix` copied exactly from
   journal.wallDeadline and generation matching local acceptedFence.Generation.
   The legacy plan externalSHA256 is for R10 offline helpers, not native commit.
   Writes committed durably BEFORE stopping timer. The persistent boot unit is
   harmless after commit and is removed during cleanup; it is not stopped while
   tailscaled still Requires it. A rollback-started journal can never commit.
8. **rollback:** independent, locked and idempotent. Stops new daemon, CAS-removes
   only its exact drop-in, validates unchanged original daemon/CLI/unit/config,
   reloads and starts original service; verifies identity/listener, restores exact
   original update policy and hold. Since this deployment has no enabled modules
   or targets, it owns **no route delta**. Current state/prefs/RouteInfo/ledger and
   manual/control/unknown routes are preserved; route snapshots are never replayed.
   Concurrent original-file changes fail closed and retain evidence for OOB.
9. **cleanup:** terminal only; removes exact own guard/unit, keeps versioned policy
   needed by a committed custom daemon, LKG, snapshots, journal and evidence.
   Custom residency keeps AutoUpdate Apply off and apt held (A7-a). OOB removal
   remains a separate Lead action after independent stability confirmation; the
   executor has no authority or credential to remove an unspecified rescue entry.

## R14 startup readiness

`verify` (including the refresh before commit) and rollback/boot `finish` share a
30-second monotonic readiness budget. They poll `systemctl is-active` and the
selected CLI's `status --json` for Running plus the planned Self.ID and TailscaleIPs.
Backoff starts at 100 ms and caps at 1 second. Each probe has a subprocess timeout
of at most 2 seconds, capped by the remaining budget; probe time counts toward the
budget. Host clock/sleep/commands are injectable in tests, not CLI options.

Timeout diagnostics distinguish `service-unavailable`, `status-unavailable`,
`backend-not-running`, and `identity-mismatch`, without printing identity/state.
A mismatching Running identity is latched for this attempt: a later matching
sample cannot turn it into success. Non-Running startup samples do not establish
identity drift. Patched verification checks the transaction deadline while waiting
and after readiness; it never extends the original arm deadline. Recovery of the
old daemon must still work after expiry/reboot, so it uses its own readiness budget.
This bounds readiness polling, not the entire operation: start and subsequent
hash/prefs/listener/policy/update commands retain their existing timeouts and the
independent worker has its existing 180-second systemd timeout.

Only a failed original start command or a readiness timeout with no active service
observed is eligible for the existing stopped-state fallback. An active service
with unavailable status, persistent non-Running backend, mismatching identity, or
failed hash/prefs/listener/policy validation does **not** trigger state replay.
Such failures require OOB inspection; non-Running alone does not prove incompatible
state. Fallback still refuses changed state and still requires prior rehearsal.
Normal switch-time state updates are preserved. Update settings are restored only
after the old service passes readiness and the remaining local verification.
Failure leaves the journal nonterminal and recovery artifacts retained; the native
entrypoint records rollback-failed for failed rollback/boot/finish.

## Boot and state downgrade limits

On a different boot any nonterminal pending journal restores original service
configuration before the Requires/After guard can succeed. It queues a separate
finish task ordered after the guard; it never synchronously starts the service
that is ordered after itself. Finish starts/verifies original tailscaled and
restores updates. Failed restoration leaves recovery failed and blocks startup.
A reboot is conservative even if wall time moves backwards. Normal timer uses
monotonic time; commit also rejects wall expiry and changed boot ID.

Default rollback keeps the newest identity state. If the old daemon cannot start,
fallback requires both prior rehearsal and byte-identical current state to the
final stopped snapshot. It refuses changed state, because copying a whole old
state could erase new manual/control owners. This is **not a general semantic
state downgrade/owner merge engine**. Changed or corrupt/incompatible state may
require OOB manual diff/restore; no successful unattended downgrade is claimed.
Original files are retained in place and sealed in backup; concurrent changes to
them cause OOB refusal rather than destructive backup replay.

Apt lock probing is point-in-time. Lead must hold the approved maintenance window
against package-manager/manual changes; apt hold alone is not a distributed or
permanent package lock. Crash during preflight/stage can leave a private partial
transaction/version directory; retain and inspect it, then use a fresh transaction
ID/release directory. No automatic broad deletion is provided.

## Tests and handoff

`bash deploy/tests/selftest.sh` runs parser/journal negatives and R14 fake-host
state-machine tests. The latter use real temporary files/fsync/flock and **fake
systemctl/systemd-run**, never native success assertions. `static_test.py` parses
concrete generated units and checks ordering/argv; it is not systemd's validator.
Run actual `systemd-analyze verify` and U-S01/I-B1 on Lead's dev VMs: full self-call
argv, timer expiry, lost SSH, concurrent commit/rollback, failures at each durable
step, disk-full, bad binary, changed state/route, update restore, reboot/power loss.
Native runtime integration, generalized downgrade and cross-host coordination
remain acceptance/implementation limits. No production authorization is implied.

### Lead dev-VM R14 retest (not executed by Astra)

Use a fresh transaction/release directory and reviewed plan/approval in the isolated
VM. Preflight pins a copy of native.py: an old pending transaction will keep its old
recovery payload. Do not overwrite that payload mid-transaction. Preserve the prior
failed transaction as evidence and resolve it through the existing OOB procedure.

1. Verify the R14 script commit/hash, run preflight → backup → stage → arm → switch
   with the existing full identity/approval bindings and `--execute`. Wait for the
   queued worker to reach switched, then run verify. Record active/MainPID/proc hash,
   Running/StableID/IPs, timer/guard state and fixed deadlines privately in the VM.
2. Immediately run rollback with the same reviewed bindings. Expect rolled-back,
   original proc hash and same StableID/IPs, exact update/apt originals, timer stopped,
   and no destructive fallback despite normal state changes. Repeat rollback and
   confirm no extra restart/state rewrite. Run terminal cleanup only after checking
   original service health; verify cleanup does not stop tailscaled.
3. With fresh transactions repeat via timer expiry and power loss while pending.
   Confirm boot restores the original configuration before startup, asynchronous
   finish waits for Running, and no rolled-back result precedes local verification.
4. In disposable VM fault cases, delay startup below/above 30 seconds and inject an
   actual identity mismatch. Retain categorized failure/OOB evidence; verify no
   automatic state rewind for active non-Running or identity failures. For a genuinely
   failed start, test both byte-identical fallback and changed-state OOB refusal.
5. Verify commit near expiry cannot extend deadlines/disarm on failed readiness.
   Retain U-S01/I-B1 results separately from fake-host PASS; no production action is
   authorized by these steps.

## R15 read-only host plan generation

`make-plan.py` only observes local files, hostname, `systemctl cat/show`, the local
Tailscale socket (`status --json`, `debug prefs`) and `apt-mark showhold`. It does
not import the phase executor, change host settings, contact control APIs or run
release binaries. State is streamed into SHA256 only, never parsed or printed.
Run with Python 3.9+ from the checkout or a release containing `tools/bundle.py`.

Lead must supply exclusions as two nonempty JSON arrays of strings and existing
OOB evidence. Additional `--backup-inventory` JSON maps backup categories to lists
of existing absolute file paths. Automatic coverage includes daemon, CLI, effective
unit, reported drop-ins/EnvironmentFiles, configuration and the live explicit
`--state=` file. All 12 categories remain mandatory under `plan.py`; no empty or
ABSENT placeholders are generated. Missing categories are listed in the error.

Supply reviewed existing prefs, routes/rules, control snapshots and update-policy
records. For RouteInfo/ledger/prefs embedded in an opaque state file, Lead may map
that category to the actual backing state path **only after confirming the storage
layout**. For no drop-ins, map `dropins` to the existing effective unit as the
reviewed representative; native.dropins remains the actual empty systemd list.
An absent ledger cannot be invented: if no actual backing file or semantically
valid existing representative exists, stop and resolve the inventory with Lead.
The generator cannot establish the completeness of a human-provided inventory.
It does not create snapshots or read control-plane data to fill these gaps.

Example for Lead to adapt on the intended host (not authorization to execute):

```sh
python3 deploy/make-plan.py --release-dir /root/release \
  --configuration /root/all-off.json --deployment-id reviewed-unique-id \
  --exclusions-peers /root/exclude-peers.json \
  --exclusions-domains /root/exclude-domains.json \
  --oob-evidence /root/oob.json --backup-inventory /root/backup-inventory.json \
  --fallback-evidence /root/rehearsal.json --output /root/plan.json --dry-run
```

Remove `--dry-run` to create only the requested output, exclusively with mode 0600;
existing outputs and symlinks are refused. Stdout reports its exact SHA256 plus
OOB/fallback/approval **templates**, with passed/expiry/approval digest unset.
Dry-run writes nothing and prints the summary/templates only. `--host` must match
the actual hostname; default deadline is 900 seconds, valid range 60–1800.
Observation is repeated and rejects detected identity/prefs/unit/hash drift; this
is not an atomic host snapshot. Native preflight/switch must still recheck it.

Optional fallback/external evidence must exist when supplied. Omitted paths default
to `OUTPUT` with `.fallback.json` / `.external.json` suffixes; no files are created.
Native plans may use `externalSHA256:null` until future acceptance exists: native
commit binds the actual digest through approval and `--acceptance-sha256`, as before.
Offline external-evidence checking does not accept null as evidence. Fallback/OOB
contents are not certified by generation; native preflight still requires genuine
passed evidence and private root-owned paths. Templates cannot pass those gates.

Lead must fill templates from actual independent recovery/rehearsal evidence,
regenerate to pin final OOB bytes, review every path/exclusion/diff, and approve the
exact final plan digest separately. First-host cohort is the default; a second-host
plan additionally needs Lead's reviewed predecessor evidence bindings. Regenerate
and compare on the production machine immediately before review; a fake-host or dev
plan is never production approval. No G6 or serial-cohort gate is waived.

Validator lookup prefers checkout `../release/bundle.py`, then `tools/bundle.py`
and `../tools/bundle.py` relative to the planner. `--bundle FILE` explicitly selects
a reviewed validator (missing explicit paths fail closed). New builds include
`tools/bundle.py` before manifest/SHA256SUMS generation; never add files by hand
to an existing signed-off release directory. Exact file-list validation is retained.

## R16 first target-host rehearsal (explicit production switch)

**This is a real production switch followed by rollback**, with possible loss of
Tailscale connectivity and failure to start the old daemon. It requires a user-
approved exclusive maintenance window, a tested independent root OOB console,
Lead native VM acceptance, and an operator ready to recover locally. It is never
run by make-plan or ordinary preflight. Do not run both production hosts together.
The first run cannot assume state downgrade has already been proved on this
identity: automatic snapshot replay is prohibited for the entire bootstrap
transaction (including timer/boot recovery). If the old daemon cannot read the
current state, retain everything and recover through OOB with reviewed differences.

Prepare and review in this order (instructions only; no production execution by
Astra):

1. Build/verify the reviewed R16 release and transfer it with its manifest intact.
   For an older package use the reviewed checkout planner with `--bundle` if needed;
   never add scripts to a sealed release directory without rebuilding its manifest.
   Use one approved script revision for the entire transaction. Existing installed
   recovery payloads must not be edited in place.
2. On the target host, prepare genuine OOB evidence, exclusions and complete backup
   inventory; generate with make-plan `--dry-run`, then write a fresh plan. For the
   first run omit `--fallback-evidence`: `native.fallbackEvidence` defaults to the
   unused `OUTPUT.fallback.json`. Review that exact absolute destination in the
   plan; its existing parent must be root-owned and not writable by others. An
   existing file/symlink is refused, never overwritten. If a custom future path is
   needed, set `native.fallbackEvidence` in the plan **before** digest and approval.
3. Obtain user/Lead approval for this switch→rollback window. The private approval
   contains all normal fields shown above plus **`"rehearsal": true`**, binding the
   exact final plan SHA256, host, deployment ID, expiry, exclusions and exclusive
   serial window. This approval is not valid for ordinary preflight. No separate
   fallback placeholder with `passed:true` is needed or permitted.
4. Review `rehearse.sh --dry-run --rehearsal` with the complete target bindings.
   Only after approval, Lead runs the explicit execute form, for example:

   ```sh
   bash deploy/rehearse.sh --execute --rehearsal \
     --plan /root/rehearsal-plan.json --approval /root/rehearsal-approval.json \
     --deployment-id REVIEWED-ID --host REVIEWED-HOST --stable-id REVIEWED-STABLE-ID \
     --release-sha256 REVIEWED-MANIFEST-SHA256 \
     --approved-plan-sha256 REVIEWED-PLAN-SHA256
   ```

   All uppercase values are review placeholders. The shell performs the same
   target binding checks as every other phase; native entry also requires explicit
   `--rehearsal`. Neither `preflight.sh --rehearsal` nor a rehearsal approval alone
   creates a normal-deployment bypass.
5. The executor performs normal preflight → backup → stage → arm → switch. Only
   prior fallback evidence is omitted. OOB, approval, target identity, all-off,
   inventory, expected-before, package, resource and update checks remain. It pins
   private OOB/approval copies, snapshots, arm readback and recovery payloads.
   The independent installed `rehearse-worker` performs the actual switch, then
   local verify, immediately rollback with journal `rollbackReason:"operator"`,
   and verifies the original executable/Running/identity/prefs/listener and exact
   update/apt originals. It never commits. CLI exit only means the worker was
   queued; inspect the private journal and systemd worker result through OOB.
6. Only successful patched verification **and** successful original recovery
   publish mode-0600 JSON at the approved destination. It has `kind`, `passed:true`,
   `host`, `stableID`, `releaseSHA256`, `oldDaemonSHA256`, UTC `timestamp`, and
   `rehearsalID`. Publication is exclusive and atomic; no partial JSON is exposed.
   Any verify/rollback failure, timeout, timer recovery or reboot alone produces
   no passed evidence. Failed rollback leaves `rollback-failed` and guards,
   snapshots and OOB evidence for inspection. A failed rehearsal can roll back
   successfully and still produce no evidence. Do not manufacture a replacement.
7. Confirm recovery independently (including management/E2E), retain the private
   evidence and run terminal cleanup using the rehearsal plan/approval bindings.
   Cleanup removes the guard, not OOB or evidence. Re-observe the now-current state
   for a **new deployment ID and new ordinary approval**; supply the generated
   evidence via make-plan `--fallback-evidence`. Formal preflight still requires
   passed evidence with matching host/StableID/release/original-daemon hashes.
   Changed release or old daemon needs a new rehearsal. Stage permits read-only
   reuse only when its exact four files, bytes and modes match; partial/modified
   stages are refused. Do not delete recovery directories to force progress.

The evidence proves the observed all-off switch and return to the original
service on this host. Despite its legacy `state-downgrade-rehearsal` kind, it does
not prove forced incompatible-state snapshot recovery, power-loss handling or
external E2E. Native timer/reboot/fault cases and operator acceptance remain
separate I-B1/U-S01 requirements. Deadlines are not extended; the existing worker
180-second timeout and timer/boot guards remain. Worker operations hold the host
lock; the timer waits for that lock and process timeout/release, not a hard
realtime deadline. OOB must stay available throughout.

## R24 strict v2 rollout and migration

The planner, package/preflight and stage share the pinned strict v2 schema check.
The initial policy must have `schema_version:2`, `enabled:false`, no active
modules, and no DNS targets/path rules. Release examples explicitly include
`app_connector_ttl:{"enabled":false}`. v1, `lease`, mixed version fields, unknown
fields, invalid types/ranges and enabled submodules are rejected even when the
global switch is off. No Python third-party dependency or network schema lookup
is used. The packaged schema is `config/schema-v2.json`; preflight copies it into
the private recovery directory and arm includes it in payload evidence.

Future migration sequence: preserve old configuration/state and reviewed source
proof, translate v1 fields to v2 **all-off**, then complete the all-off rehearsal
and rollback on the isolated VM before any deployment decision. The old daemon
and any old lease writer must be stopped before starting the new daemon; no
parallel writer is allowed. Enable `app_connector_ttl` only in a separate reviewed
post-rehearsal step. v1 runtime parsing does not waive this deployment gate.
Downgrade after enabling TTL additionally needs durable handoff and native state
compatibility evidence; all-off rehearsal alone does not certify it.

`bash deploy/tests/selftest.sh` now uses v2 in planner and fake-host rehearsal,
including preflight/backup/stage/arm/switch/verify/rollback and a fresh formal
transaction through commit. Release tests use v2 manifest/schema payloads.
These synthetic host commands/evidence are not VM or production acceptance.
Lead still needs native v2 preflight → rehearsal → original-service recovery on
an isolated Linux VM, preserving exact config/plan/package hashes, journal,
identity/prefs invariants and OOB observations. Use an already reviewed VM package
or arrange its build separately; R24 did not build or deploy a release.
