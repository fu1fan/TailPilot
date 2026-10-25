# Patch06: authenticated receive seam

Base: `github.com/tailscale/wireguard-go`
`2e01ba5b00f0a02b0fb37e668c7cac6717880568`
(`v0.0.0-20260715223240-2e01ba5b00f0`). Imported using `git archive`, without
`.git`, submodules, module-cache symlinks, or paths outside this repository.
The root module replaces this dependency with `./third_party/wireguard-go`.
The original module requirements and go.sum are unchanged.

The base root LICENSE is **MIT**, not BSD as the initial task/design described.
All upstream license files and SPDX headers are retained verbatim. Magicsock's
integration remains under its existing BSD-3-Clause license.

## Diff and reproduction

`PATCH.diff` is the complete diff relative to the base (two production files
modified, one interface file and one test file added). It excludes these four
maintenance files: PATCH.md, PATCH.diff, UPSTREAM.sha256, verify_patch.py.
`UPSTREAM.sha256` records every archived upstream file, including hidden files.

From the unified checkout, without network or an external WireGuard clone:

```sh
python3 third_party/wireguard-go/verify_patch.py
```

The script copies the local source to a temporary directory, reverses PATCH.diff,
verifies the complete file set and hashes against UPSTREAM.sha256, then reapplies
the patch and verifies it reproduces the checked-in source. It does not modify
the working tree. SHA values attest reproducibility against the recorded base,
not a third-party signature on that base.

Original import:

```sh
mkdir -p third_party/wireguard-go
git -C /path/to/fixed-wireguard-clone archive 2e01ba5b00f0a02b0fb37e668c7cac6717880568 |
  tar -x -C third_party/wireguard-go
# Apply this checked-in PATCH.diff from that directory.
```

To regenerate PATCH.diff, put the exact archive in temporary directory `a` and
the modified source (excluding the four maintenance files) in sibling `b`.
Run `git diff --no-index --src-prefix= --dst-prefix= a b` from their parent;
exit status 1 means a diff exists. This produces `a/` and `b/` patch paths.
Do not regenerate from a dirty or moving upstream branch.

Offline Go builds require the pinned toolchain and the normal module dependency
cache (the entire Tailscale dependency graph is not vendored by this patch).
No external WireGuard checkout is required. Tests must enter this nested module;
root `go test ./...` does not discover nested-module tests.

## Gate placement (base source line numbers)

- `noise-protocol.go:433`: initiation commit lock, after static/timestamp AEAD
  and replay/flood checks. For gated endpoints recheck replay/flood under this
  lock before the pure predicate. Denial returns nil without timestamp, index,
  hash, chain key or handshake state writes.
- `noise-protocol.go:609`: response commit lock, after AEAD. A gated response
  rechecks the authenticated handshake hash/local index/state to prevent a
  concurrent response committing twice. Existing ConsumeMessageResponse calls
  remain source-compatible; the receive worker uses the new endpoint variant.
- `receive.go:484`: after decryption succeeded, before replayFilter acceptance,
  keypair promotion, FromPeer, byte accounting, timers, and TUN delivery.
  Keepalive is distinguished after decryption, not from an untrusted length.
- Handshake workers notify gated PeerAwareEndpoint.FromPeer only after Consume
  succeeds and releases handshake locks, before the existing timers/reply path.
  The original non-gated endpoint callbacks and cookie/DoS prefix are unchanged.

No encryption, KDF, message encoding, MAC, nonce, or wire protocol changes.
A denied transport packet does not consume replay state; an allowed replay can
reach the *pure predicate*, but cannot update health or TUN after replay rejection.
Cookie replies never invoke this predicate or the new health notification.
InitiationAwareEndpoint remains a pre-auth JIT hook: implementers must not use it
for authorization/health. Magicsock's gated wrapper deliberately omits it; the
existing Device.LookupPeer JIT configuration still runs.

## Integration and lock/lifetime contract

Magicsock installs the seam only before the first Bind.Open. Later installation
or removal is rejected, including after Close: packets may still be queued.
Nil/default leaves the original receive paths untouched. The implementation does
not install a gate in the application or configure any device rules.

Each gated UDP/Geneve/DERP packet owns a non-pooled immutable endpoint wrapper.
It survives receive-slot reuse and asynchronous WG queues. TransportContext is
returned/passed by value. Address cache hits do not authorize or update health.
Relay provenance is copied only from a matching, trusted bestAddr carrying a
successful relay handshake generation; unknown/expired provenance is explicitly
unverified. DERP source and verified relay terminal peer must match Noise identity.
A Geneve VNI is never sufficient to mark a relay verified.

The predicate runs under handshake locks for handshakes and before the replay
filter for transport. It must be bounded, pure, and lock/IO-free. The built-in
wrapper checks only value fields and calls the injected predicate. Health and
legacy lazyEndpoint association run outside WG locks after acceptance; no new
WG -> magicsock lock acquisition is added under handshake locks. Magicsock may
acquire its own locks while capturing context at ingress, before WG processing.

Generation currently identifies the startup installation, not a live policy
revision. RelaySession is the upstream relay handshake generation, scoped by
server, terminal peer and address, not a globally unique token. R8 must provide
live policy/identity epoch checks, relay expiration/revocation fences and late
callback handling. Captured provenance is historical evidence, not continuing
authorization. There is no path-policy state machine, Disco policy, send policy,
queue invalidation, policy publication API, or production enablement here.

## Tests and limits

- Real Noise initiation/response, malformed AEAD, altered sender/receiver index,
  replay, denial then acceptance, and concurrent commits.
- Actual handshake worker: denial preserves timer/state/health/byte counters,
  no handshake response or keepalive dispatch.
- Actual AEAD decryption + sequential receiver: mixed contexts, data/keepalive,
  denial before key promotion/replay acceptance, no denied TUN writes or health,
  replay deduplication, wrong session key.
- Receive ingress: expired key and unknown receiver index rejected before gate.
- Existing conn coalesce/split tests; magicsock 128-context reuse, Geneve provenance,
  DERP source spoof, gate under held Conn/endpoint locks, startup installation fence.
- Baseline/patched device+conn tests compared with GOPROXY=off after fetching the
  exact missing dependency versions. Detailed commands/results are in round7.md.

Linux kernel UDP GSO/GRO end-to-end and race/full Tailscale regression are Lead
acceptance work. Portable coalesce/split and batch tests are not kernel offload
proof. The per-packet allocation cost is not benchmarked. This seam alone does
not provide strict receive/send path restrictions.

## Rebase procedure

1. Keep the existing unified commit and verified old base available; archive the
   new exact upstream commit into a temporary sibling directory.
2. Apply PATCH.diff there with `git apply --check` first; manually resolve changes
   only after re-auditing AEAD, replay, handshake commit, callbacks and queue
   ownership locations. Do not blindly move gates to satisfy patch context.
3. Preserve the new upstream licenses/go.mod/go.sum. Regenerate the complete
   upstream SHA manifest and the minimal diff against that new archive; update
   the base commit/version and these line references.
4. Replace only this subtree, run verify_patch.py, test baseline vs patched
   device/conn, all authenticated-path tests, Linux batch/offload, full root
   regressions and race. Review lock ordering and context lifetime again.
5. Commit the import, patch and integration together in unified. No submodule,
   external replace, deployment or policy enablement is part of the rebase.
