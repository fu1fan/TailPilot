# Unified maintenance and rebase

Keep the official tag and pristine read-only anchor unchanged. Use a fresh writable
branch/worktree for each upstream version. Record the exact tag object/peeled base,
previous unified HEAD, Go distribution provenance, toolchain tree hash and module
cache inventory. Do not replace dependency versions through `go get ...@latest`.

The public R6 baseline is a sanitized aggregate commit, not the private series
of `unified:` commits. Use the [patch map](patch-map.md) and the full upstream
diff to review that baseline. For subsequent feature commits, inspect
`git range-diff` when replaying them. Re-audit authoritative
prefs/owner barriers and authenticated receive before replay/handshake side effects;
resolving textual conflicts is not sufficient. Preserve WireGuard licenses and
follow `third_party/wireguard-go/PATCH.md` in a new dependency copy when authorized;
regenerate/check its minimal patch and upstream hashes.

Run the required Go packages/full race plus the nested WireGuard module separately.
Run shell syntax and all release/deploy/lab selftests, then isolated repeated builds.
Validate example configuration with the matching offline CLI. Keep test commands
and errors, distinguish compiled-only, local unit, simulated, native VM and external
E2E outcomes. Never reuse an old release's I-B1/OOB/ownership evidence as current.

Archive release manifest, source tar/patch/series/range-diff, config/state schema
compatibility, test evidence, LKG and the installed recovery payload's hash.
The first deployment is all-off and one host at a time; subsequent policy changes
need their own reviewed diff/generation and external E2E evidence. No production
configuration or private state belongs in release artifacts.

Custom releases need a named maintenance owner and security-update deadline.
Keep AutoUpdate/apt policy deliberate: an official security update means either
rebase/test this patch set or roll back fully to official under the documented
recovery procedure. Restore saved original update values only when appropriate;
never assume all hosts originally had Apply=true or apt unheld.

Deployment acceptance must be established for the current candidate and target
host; historical implementation-stage notes do not establish that acceptance.
See [deployment limitations](../deploy/README.md) and [release builder](../release/README.md).
