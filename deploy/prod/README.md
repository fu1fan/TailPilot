# R35 — committed-release upgrade and durable TTL handoff

Status: **R35 DONE for the requested development adapters and dev loop; not production authorization**.
The adapters now support a pinned committed custom predecessor, exact drop-in
restoration, disabled v2-to-v1 policy-LKG compatibility migration, committed
reverse migration and durable TTL enable/disable. The sealed release is not
modified. R34's 83 tests remain the baseline; see `deploy/tests/r35_test.py` and
`lab/deploy-r35/` for added regression and native VM evidence procedures.

## Operator configuration

This public snapshot contains examples only. Supply a private target descriptor
and verify live host identity before deployment. Historical round identifiers
refer to development provenance, not current production state.

## Entry points and modes

Run from the implementation checkout; keep these scripts outside sealed release
payloads. A reviewed checkout needs its existing `deploy/`, `release/bundle.py`
and `featurepolicy/schema-v2.json`. Do not inject R34 files into the final
release or regenerate its manifest.

| Entry | Actions | Effects |
|---|---|---|
| `00-readonly` | review, release, probe, plan | Offline release verification; explicit read-only SSH/local observation; optional new evidence files |
| `10-alloff` | review, rehearse, start, verify, commit, cleanup | Existing v2 native executor, only with explicit execute and approval |
| `20-takeover` | review, config, adopt, reset, reset-rollback, enable | Candidate config; explicit local previews; approved CAS operations; durable enable |
| `30-acceptance` | review, check | Validate supplied external evidence; never synthesize E2E success or commit |
| `90-rollback` | review, release, reverse, disable | Roll back a pending native transaction; pending rollback, committed reverse and durable disable |

Every entry without arguments prints offline review. A selected mutation without
`--execute` only checks plan/target bindings and prints dry-run. `--dry-run` never
connects to a host or writes an artifact. `--connect-readonly` is required for SSH
probe; `--observe-local` for target-local plan generation or route preview.
Neither option means dry-run, and neither can be combined with `--execute` or
explicit `--dry-run`. Creating candidate/evidence/plan files requires
`--write-output`; exclusive 0600 creation refuses existing paths and symlinks.
Candidate creation is offline and is never installed as live policy.

Quick local commands (safe; no host access):

```bash
bash deploy/prod/00-readonly
bash deploy/prod/10-alloff
bash deploy/prod/20-takeover --action config --dry-run
bash deploy/prod/tests/selftest.sh
```

After preparing real reviewed files, define this Bash array locally on the
operator's chosen machine (uppercase names are placeholders, not shell commands):

```bash
bindings=(--target /root/review/target.json
          --plan /root/review/plan.json --plan-sha256 PLAN_SHA256
          --release-sha256 MANIFEST_SHA256 --oob-sha256 OOB_EVIDENCE_SHA256)
bash deploy/prod/10-alloff --action start "${bindings[@]}" --dry-run
```

Only an approved operator replaces dry-run with `--execute --approval FILE` for
one action at a time. All mutations require exact plan/release/OOB hashes, a
root-owned private target/plan/approval/evidence hierarchy, target Linux root,
a matching live StableID (except recovery when the daemon may be down), and an
exclusive maintenance window. No SSH mutation path or control-plane client exists.

Approval extends the existing native approval contract with:

- `targetSHA256`, `releaseSHA256`, `oobSHA256` binding the exact reviewed bytes;
- `prodActions`, an explicit list such as `["10-alloff:rehearse"]`;
- `windowStartUnix`, `windowEndUnix`, `expiresUnix`, `serialWindowExclusive:true`;
- exact plan `deploymentID`, `host`, `approvedPlanSHA256`, `excludePeers`, `excludeDomains`;
- `rehearsal:true` only for the rehearsal approval; ordinary deployment needs a
  distinct approval; cleanup after rehearsal may use that rehearsal approval;
- `acceptanceSHA256` for acceptance check and formal commit;
- for route mutations, `takeover` exactly containing `source`, `hash`, `generation`,
  `sourceID`, `manifestSHA256`, `claimsSHA256` (unused file hashes are JSON null).

The private approval is a local operator attestation, not a signature. Local
flock prevents concurrent batches on this host; the existing native lock handles
workers/recovery. Cross-host exclusivity remains a Lead responsibility. A queued
worker outlives the batch lock; do not start another phase until its journal has
reached the required state. Never run two hosts concurrently.

## 00: read-only precheck

`--action release --target FILE --release-sha256 SHA --release-dir DIR` verifies
all manifest payload hashes, v2 schema and amd64 ELF headers without executing
release binaries. The expected hash must come from the reviewed table, not be
trusted merely because it was calculated from the package being inspected.

After separate permission to access production, `--action probe` also requires
`--connect-readonly --oob-key ABSOLUTE_PATH --known-hosts ABSOLUTE_PATH
--remote-cli ABSOLUTE_PATH --socket ABSOLUTE_PATH`, plus the release inputs above.
The key path has no default; key contents are never read or printed by Python.
SSH disables user config/agents/forwardings and requires pinned known_hosts.
The only remote payload is `probe.py`: selected status/prefs, systemd metadata,
process hash, routes and apt hold. No identity-state content or control API.
Optional `--output FILE --write-output` saves sanitized evidence. An old CLI
without unified-policy status is refused; this is not a general upstream probe.

`--action plan --observe-local --planner-inputs FILE --output NEW_FILE
--write-output`, with target/release hash, delegates to `make-plan.py`. Its input
JSON uses underscore keys: `release_dir`, `configuration`, `deployment_id`,
`exclusions_peers`, `exclusions_domains`, `oob_evidence`, `backup_inventory`, and
optional `fallback_evidence`, `external_evidence`, `deadline_seconds` (60–1800).
Paths must follow the planner's absolute-path contract. Omit fallback evidence
for the first rehearsal. Output includes an **unapproved** templates companion;
fill it from actual evidence and regenerate to pin the final OOB bytes. Partial
output creation is retained for review, never overwritten or automatically deleted.

**Committed custom predecessor:** the planner recognizes only the versioned
`/usr/local/lib/tailscale-unified/<releaseID>/tailscaled` layout with a unique
committed predecessor journal, pinned original plan, binary/CLI hashes and exact
transaction drop-in. It records `native.previousDeployment`, includes the old
policy/plan/journal and all existing drop-ins in the backup, and requires live
applied all-off. A pending TTL handoff, foreign guard/drop-in or unrecognized
layout is refused. Old recovery records are retained, not deleted for preflight.
The new transaction and release IDs must differ from the predecessor. The R34
read-only probe's `nativeLayoutSupported` field describes its historical apt
first-install layout; custom eligibility is determined by the new planner and
native predecessor checks, not by treating that old boolean as authorization.

## 10: v2 all-off rehearsal and formal deployment

Only after validating the predecessor and approving the window:

1. Verify strict v2 global/module all-off config, complete 12-category backups,
   exact original hashes/unit/argv, management/Codex exclusions, independent OOB,
   available disk/memory, no package activity and the reviewed release.
2. Fresh rehearsal ID/plan/approval: `10-alloff --action rehearse` with bindings
   and explicit execute. This is a **real switch**, not simulation. Return means
   QUEUED ONLY. Inspect the installed journal until `rolled-back` and genuine
   rehearsal evidence exists; independently verify old service/identity/update
   policy and E2E. A timer rollback alone is not passed rehearsal evidence.
3. Approved `--action cleanup` after terminal recovery; retain all evidence/OOB.
4. Generate fresh formal plan/ID after state changes, consuming the genuine
   rehearsal evidence and a new ordinary approval. Native stage can reuse only
   the exact four staged files/bytes/modes from rehearsal; the batch planner no
   longer erroneously rejects that directory merely because it exists.
5. `--action start` runs preflight → backup → stage → arm → switch serially and
   stops on first failure. It queues the worker; it does not wait/retry/commit.
   Preserve the independent deadline timer and boot guard.
6. When journal is switched, `--action verify`; collect external acceptance below;
   `--action commit --acceptance-sha256 SHA` with updated approval only before
   the original deadlines. Commit then cleanup are separate explicit actions.

## 20: candidate configuration, adoption and reset previews

`20-takeover --action config` displays a strict v2 TTL-only idcfast candidate;
`--output NEW_FILE --write-output` saves it. Other modules remain off. This file
is **not applied** by config generation. Enable and disable are separate approved
transactions, described below.

For each of adopt/reset/reset-rollback use bindings plus `--source TICKET`.
Without `--observe-local` this is offline dry-run. With it, the target CLI returns
`clear_preview` without mutation. Adoption optionally takes `--manifest FILE`;
review every reference/reason, source lifetime, generation and snapshot hash.
Select explicit eligible `Reference` objects into `--claims FILE`; there is no
adopt-all or prefix inference. Preview is allowed without claims; execution is not.

Execution requires a committed all-off deployment journal, action approval and
`--expect-sha256 HASH --expect-generation N --expect-source-id N`. The wrapper
fetches a fresh preview, checks exact CAS and approved manifest/claims file hashes,
rejects empty/duplicate/ineligible claims, then invokes the daemon CAS operation.
The daemon is the final concurrency authority. A changed preview means stop and
review again, not auto-retry. These operations can still be refused by the daemon
while TTL is inactive; the wrapper never silently enables it.

Reset removes managed learning only. Review Withdraw/Retain and protections for
manual/static/default/shared/unclaimed owners before approval. Capture a fresh
reset preview for reset-rollback; intervening DNS/sweep/config/adoption/prefs
changes can invalidate the checkpoint. No daemon restart, whole-state replay or
synthetic DNS evidence. Real DNS relearning must be separately observed.

## 30: independent acceptance

Lead supplies a private `externalEvidence` JSON, then `30-acceptance --action
check` with bindings, explicit execute/approval and `--acceptance-sha256 SHA`.
This mode validates supplied proof and local policy status; it does not run
external probes or write control-plane settings. Formal commit independently
uses native verification and requires the same approved evidence digest.

Evidence binds `deploymentID`, `host`, `stableID`, `releaseSHA256`,
`configurationSHA256`, `kind:"external-e2e"`, `passed:true`, future `expiresUnix`,
`observedUnix` within the armed transaction window, exact journal `deadlineUnix`
and local policy `generation`. The journal must be verified and unexpired.
`checks` must contain exactly: oob, tailnetSSH, appConnectorEgress, dns, derp,
relay, codex, deepseek, routeCounts, longConnection. Each needs passed=true,
observer, evidenceSHA256 and measurement. Retain the actual source artifacts:
these fields are attestations; the script does not authenticate their authors
or fetch/rehash the independently stored measurement artifacts.

routeCounts.counts separately records advertisedBefore/After and enabledBefore/After,
nonnegative integers, unchanged for all-off. Never equate these two count types.
Acceptance here covers all-off only; TTL takeover route changes need a separate
reviewed matrix, not fabricated unchanged counts.

## 90: recovery and stop rules

`90-rollback --action release` with reviewed bindings/approval/execute invokes
native rollback for a pending transaction and verifies terminal `rolled-back`.
It remains callable with the daemon down. Timer/boot recovery uses the installed
private recovery payload independently of this wrapper and approval expiry.
Never edit that payload or disarm pending recovery to force progress.

`release` still rejects committed transactions instead of claiming success from
native rollback's terminal no-op. Use explicit `90-rollback --action reverse` for
a committed release, after durable all-off. Its action-scoped approval also needs
`reverse: {configurationSHA256, generation, dropinSHA256}` from fresh local
readback. Reverse records a fresh backup, rearms timer/boot recovery, then restores
the exact original layout under the native lock. Return to a custom predecessor
restores the saved drop-in; return from an apt first install restores the apt
layout. `cleanup` after rolled-back restores the predecessor recovery guard.
No manual deletion of guards/journals is part of the workflow.

For a v1 custom predecessor, `compatibility.py` runs only while the daemon is
stopped. It verifies policy-LKG checksums, all-off configuration and completed
TTL/ownership handoff, then translates only policy LKG `schema_version:2` and
`app_connector_ttl` to v1/`lease`. All identity, prefs, routes, ledger, lease and
other FileStore key/value bytes are preserved. Per-state before/after hashes,
private backup and fsynced intent allow idempotent CAS recovery. Unknown stores,
active profiles, incomplete handoff, corrupt checksums or foreign state edits
fail closed. A downgraded daemon must again report applied all-off; service
Running alone is insufficient. This never restores a historical state snapshot.

### Durable TTL enable/disable

Use `20-takeover --action enable` or `90-rollback --action disable` with ordinary
bindings plus `--configuration PRIVATE_CANDIDATE --operation UNIQUE_ID
--expect-sha256 CURRENT_POLICY_SHA --expect-generation CURRENT_GENERATION`.
Disable requires a strict v2 globally disabled idcfast candidate; enable permits
only TTL. Approval must additionally contain exactly:

```json
{"policy":{"operation":"ticket-1","beforeSHA256":"CURRENT_POLICY_SHA",
           "generation":123,"configurationSHA256":"CANDIDATE_SHA"}}
```

The wrapper checks the installed binary/drop-in, committed plan, candidate,
source hash and generation under the native host lock. It backs up state and
configuration privately, installs a persistent systemd timer/worker, and writes
`policy-intent.json` before publishing the candidate. **QUEUED is not success.**
Wait for phase `complete` plus policy/consumer readiness readback; retain the per-operation
`policy-<ID>/result.json`. A pending operation blocks another operation, upgrade
or reverse. There is no adoption, reset or route write in this adapter.

Recovery rolls forward the exact authorized candidate, never replays old routes
or state. The daemon is the sole ownership writer and performs durable handoff.
The file watcher may consume the candidate before the explicit reload CAS;
success still requires the exact source hash and readiness. TTL enable uses a
read-only lifecycle-authority adoption preview with matching full accepted fence
and a valid SourceID; it does not adopt anything. This sealed release does not
advance the broad `status.applied` bit for TTL. All-off/disable still requires
`applied=true`, and neither accepted configuration nor Running alone is success. Foreign file,
release or profile changes stop recovery. A daemon/OS restart permits rebinding
the generation only to the same profile and exact approved source, recorded by
systemd InvocationID/boot ID. Otherwise stale fences fail closed. The worker may
restart the same pinned daemon once after an application timeout to recover its
journal; the timer retains pending evidence if recovery still fails. Completed
timers are stopped; their installed records remain available across reboot.

On any failure preserve journal, LKG, backups, guard/timer and OOB. Inspect through
independent recovery access; do not manufacture evidence, extend the deadline,
retry with stale CAS, delete foreign state or start the second host. A stopped
process or interrupted sleep is neither success nor proof of failure recovery.

## Tests and remaining approvals

Run `bash deploy/prod/tests/selftest.sh`: Python AST, bash syntax, wrapper default
reviews, fake host command/probe fixtures, release integrity, argument negatives,
plan/approval/hash/target drift, all-off ordering and stop-on-error, adoption/reset
CAS, evidence freshness/count matrix and committed rollback refusal. Then the
existing deployment parser/native/static/rehearsal/planner suites run sequentially.
No production/dev connections, native systemd, release build or Go tests are part
of this command. Fixture tests are not native/production acceptance.

Before any production action Lead/user must review and approve:

- Current target/release hashes and actual all-off state; residential stays untouched.
- Review of R35 native upgrade/reverse/handoff evidence and the actual predecessor layout.
- Independent root OOB access, supplied key path/known_hosts and recovery operator.
- Complete private backups, durable recovery, exclusions and a serial window.
- Exact fresh plan and scoped approval hashes; separate rehearsal/formal approvals.
- External all-off E2E, real route counts, deadlines and evidence digest before commit.
- Separate TTL enable/disable operation approval and explicit selected claims
  before any takeover mutations; reset/rollback effects and fresh CAS review.
- OOB removal only after independent stability approval, never by these scripts.

R34 local validation recorded on 2026-10-23 (macOS, Python 3):
`bash deploy/prod/tests/selftest.sh` exited 0. **83 tests passed**: 28 new batch/
fake-host/static tests; existing suites 11 parser, 24 native fake-host, 1 generated
unit static, 11 rehearsal, 8 planner tests. `bash -n` covers all five entrypoints
and the test runner; Python AST covers both implementation scripts and the test
module. Expected injected-failure OOB diagnostics occurred in rehearsal tests;
all suites ended OK. No native/systemd or target-host result is claimed.

## R35 native result (2026-10-23)

Only dev `192.0.2.30` was accessed. An isolated QEMU overlay, restricted user
networking, real Linux/systemd/TUN and a loopback lab control server were used.
The old daemon was the documented `d8d7f5b7…` v1 release; final manifest remained
`e8f87f9b…`. Final `r35-upgrade-rehearsal6` and `r35-upgrade6` passed upgrade,
commit, actual batch enable/disable, both enabled/disabled daemon restarts,
worker exit-code failure plus daemon restart/timer recovery in both directions,
and actual batch reverse to applied v1 all-off. StableID, full prefs hash and the
four manual/static/default advertisements were unchanged. The migration changed
one policy LKG key and preserved nine other FileStore values exactly.

`bash deploy/prod/tests/selftest.sh`: **102 tests PASS** (83 baseline + 19 R35).
Offline tests and real native evidence are distinct. See `evidence/round35.md`
and `evidence/r35/summary.json`. VM commit attestations are explicitly lab-only;
no production E2E/forwarding, enabled-route control-plane counts, long-duration
stability, physical power loss or production rollout is claimed. Guest shutdown
completed; the dev host's main tailscaled remained inactive. No push/publication.
