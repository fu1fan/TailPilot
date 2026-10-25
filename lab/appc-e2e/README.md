# R29 CLI810 takeover readiness

**R29=PARTIAL; real Linux CLI810 awaits Lead.** See [round29.md](round29.md)
for the policy sequence, synthetic-history boundary, checks and rerun commands.

The runner now hot-loads v2 root+App Connector TTL through real CLI/LocalAPI,
verifies enabledModules and the current takeover consumer before seeding, and
checks readiness again after both restarts. A completed takeover restores its
journal, so the stopped-daemon fixture injects Control-only history into its
Unclaimed provenance as well as _routeInfo and advertised prefs. It preserves
ledger/fence/leases/identity and validates/rebuilds the journal checksum; only the
reviewed manifest and real adopt execute grant ownership. This is synthetic
archived history, not initial legacy migration or DNS evidence.

Python contracts and the Python-to-Go backend seed/adopt/reset regression pass
locally. The actual CLI lifecycle is BLOCKED on this Darwin host; successful Linux
scoped gates must still produce overall PARTIAL/exit 2 while DNS/OS/write-barrier
coverage is missing. No 810, retention or identity assertion is relaxed.

## Previous R28 envelope repair


**R28=PARTIAL; corrected Linux CLI lifecycle awaits Lead execution.** Lead's R27
result at `/root/unified-lab/r27-20261023-110655/cli810/` reports login PASS,
then adopt BLOCKED with `KeyError: Fence`. This is supplied evidence; that path
is not accessible on this macOS host.

## R28 repair and verification

The CLI prints `featurepolicy.Inspection`: the plan is inside `clear_preview`.
`preview()` now unwraps that object for both adopt and reset, including the initial
adopt used to construct the manifest. The original complete response remains in
`NNN.stdout`; the named preview JSON files contain the plan. Missing/null/nonobject
wrappers fail immediately. Execution still uses the exact inner SnapshotHash,
Fence.Generation and SourceID; no execute retry or lifecycle assertion changed.

`python3 lab/appc-e2e/cli810-selftest.py` passes the envelope/CAS regression for
both commands, raw-response preservation and malformed-envelope rejection. This
uses a simulated CLI response and is **not a daemon lifecycle pass**. Linux checks
now run it as `cli810-contract`. Startup namespace failures now also write
`cli810/result.json` with BLOCKED, phase and completed gates before exiting.

Local real lifecycle is BLOCKED before startup: this host is Darwin, without
Linux network namespaces; the configured local Docker socket is absent. No
server was accessed. The process inventory was denied by the sandbox; no claim
of zero leftover processes is made. See [round28.md](round28.md) for evidence.
The full successful scoped lifecycle still writes `cli810=PASS`, overall
`PARTIAL`, and exits 2 while DNS relearn / OS matrix / write barriers are missing.

## R27 login repair

PrivateNetwork contains only loopback. netmon excludes loopback from HaveV4/V6,
so LocalBackend.shouldPauseControlClientLocked pauses control HTTP activity.
`client.Login(2)` merely queues login and does not prove registration started.
The isolated daemon now sets the existing development-only
`TS_ASSUME_NETWORK_UP_FOR_TEST=true`; it does not add an interface, route, or
external network access. All control/DERP/STUN binds remain 127.0.0.1 in this runner.
The unused `--auth-key=lab-only` is removed. It was **not an auth rejection**:
TestDaemonLoginFixture exercises the real daemon Direct client and Noise server,
and succeeds with both empty and placeholder keys when RequireAuthKey is unset.
The complete Lead daemon log was not fetched here; Linux rerun must confirm this
pause diagnosis and Running transition in the actual namespace.

The helper also advertises store-appc-routes; the seeded RouteInfo wildcard uses
its stored suffix form (`example.test`). Commands now retain return codes and
partial output on timeout, phase and completed gates on failure, and decoded
journals plus state SHA256 after adopt/reset/restart. No assertion is relaxed.
No server operation is performed by building or reviewing these scripts.

## Incident and containment

Lead observed a public scanner request to `/board.cgi` hitting testcontrol on
`0.0.0.0:8080`; upstream `serveUnhandled` starts a goroutine that panics. That
kills the control process, then daemon login gets connection refused and policy
is not ready. This explains that failed attempt; it is not a takeover verdict.
Do not replay any shell payload from the incident logs. Preserve those logs.

`lab/g4-netns/control` now defaults to 127.0.0.1 and random ports for control,
DERP and STUN. `--port=8080` is optional; **never use 0.0.0.0**. Explicit bind is
restricted to literal IPv4 loopback or RFC1918 private addresses (g4 bridge).
The lab-only testcontrol fork protects plaintext AND Noise inner HTTP, including
malformed register/map bodies. It disables unneeded TKA/webclient/c2n endpoints.
Health is `GET /healthz`. Stop with SIGTERM, wait for process exit. Health proves
process liveness, not successful daemon login.

Before starting anything on dev, Lead must run:

```sh
sudo ss -lntup '( sport = :8080 or sport = :3340 )'
python3 lab/appc-e2e/preflight.py
```

Any nonloopback listener is a hard stop. Identify its PID/unit and stop ONLY the
previous run-owned helper; do not kill a production process or edit host service
configuration. If firewall containment is needed on the **isolated dev host**, a
Lead-owned temporary nftables table can deny external ingress (IPv4 and IPv6):

```sh
sudo nft add table inet r26_lab_guard
sudo nft 'add chain inet r26_lab_guard input { type filter hook input priority -10; policy accept; }'
sudo nft 'add rule inet r26_lab_guard input iifname != "lo" tcp dport { 8080, 3340 } drop'
sudo nft 'add rule inet r26_lab_guard input iifname != "lo" udp dport { 8080, 3340 } drop'
```

Do not flush rulesets. Keep containment until legacy listeners are gone. Remove
only this owned table afterward with `sudo nft delete table inet r26_lab_guard`.
The new CLI runner does not need these ports or public access: its entire process
tree lives in a transient systemd PrivateNetwork namespace. No firewall commands
are automated. Slirp forwarding to 10.0.2.2 requires its host-loopback option;
verify that option instead of widening the bind address.

## Lead commands

Use a clean isolated implementation checkout containing this commit, Linux Go
1.26.6 and existing module caches. Output must be outside the checkout; do not
use production binaries/state/socket. No download, release, deploy or push occurs.

```sh
cd /path/to/isolated/unified
export GO=/path/to/linux/go1.26.6/bin/go
export GOPATH=/path/to/existing/go-path GOCACHE=/path/to/test-go-cache
export R26_OUT=/root/unified-lab/r29-$(date +%Y%m%d-%H%M%S)
unset R27_OUT # avoid the older alias overriding R26_OUT
# Scoped acceptance; leave unrelated repository-wide suites out of this gate.
R26_ALL_PACKAGES=0 bash lab/appc-e2e/linux-checks.sh
# Inspect failures before the next step. Uses only a unique transient lab unit.
sudo env -u R27_OUT R26_OUT="$R26_OUT" bash lab/appc-e2e/systemd-cli.sh
# Expected exit 2 only after all scoped gates pass; inspect this JSON.
cat "$R26_OUT/cli810/result.json"
```

`linux-checks.sh` records HEAD, dirty status, toolchain, commands, exit codes,
normal/race for nine implementation packages plus the two lab packages, lab
selftests, security tests, binary builds and process-cut tests. With optional
`R26_ALL_PACKAGES=1` it ALSO runs repository-wide `go test ./...` and `go test -race ./...`.
Do not claim the repository-wide suites were run when that flag is omitted.

`systemd-cli.sh` requires systemd, root, Python 3, ss and the built binaries. It
sets PrivateNetwork, PrivateTmp, ProtectSystem=strict, explicit writable output,
KillMode=control-group and a 300-second lifetime. A unique unit is stopped on exit.
It never starts/stops `tailscaled.service` or uses its socket/state. Failed or
partial tests preserve evidence under R26_OUT (mode 0700; R27_OUT is also accepted and takes precedence); the state contains
lab private keys, so keep the directory private.

## Exact evidence boundaries

* `security-selftest.py`: a real helper process, real TCP requests, malicious
  path/oversized body, continued health/key service, rejected public binds and
  orderly stop. Unit/race tests also exercise real Noise registration and
  malformed/unknown requests followed by another valid map update.
* `cli810.py`: **R28 login PASS / adopt BLOCKED per Lead; R29 Linux rerun pending**. Real tailscaled userspace engine,
  real CLI, real Unix LocalAPI, login and Running, followed by shutdown and
  synthetic insertion of exactly 810 historical Control prefixes in the
  run-owned FileStore. The helper supplies assigned domain and a distinct static
  route via a real netmap. Generated proof records explicitly identify synthetic
  history, not DNS evidence. The script passes identical explicit claims and
  manifest to preview/execute, verifies Withdraw is exactly the 810 prefixes,
  clears them, retains manual/static/both Exit Node routes, then SIGKILLs and
  restarts after commit and checks node identity and routes. All CLI output,
  hashes/generation/source, state journals, commands and systemd logs are retained.
  **Even if those assertions pass, it exits 2/PARTIAL**, because real DNS packet
  relearn and the full profile/OS matrix are missing. It fails closed on stale
  snapshots rather than silently retrying execute or changing the claim set.
* `power-overlay.py` + `power_test.go.txt`: test-only overlay; no existing source
  or production binary is modified. Twelve separate child processes die by real
  SIGKILL before/after each of six backend Store writes. A fresh process restores
  the persisted snapshot and verifies complete journal, exact routes and hostname
  sentinel. Evidence includes barrier markers and cut/recovery logs. This is a
  backend/fake-engine fixture with durable snapshot transport; **not FileStore
  crash consistency, actual machine identity/service retention, or systemd daemon
  power-cut acceptance**. On Mac it fails before the barrier at engine creation.
* Profile enable/disable/handoff uses existing backend fixtures only. It is not
  a real two-profile login/switch or live systemd lifecycle matrix.

DNS boundary: `tailscale dns query` uses LocalBackend.QueryDNS and does not call
ObserveDNSResponse. Adding only a DNS extra record or calling that CLI would not
prove connector relearn. The minimum missing integration is an authorized second
lab peer sending DoH to the connector PeerAPI, a namespace-local resolver returning
`d0.example.test A 192.0.1.1` with TTL, and assertions that the same prefix is absent
after reset, then learned from that response and restored durably. Local testcontrol
is sufficient in principle; a production control plane is not required. This
traffic driver has **not been implemented or executed**; synthetic history is not
DNS learning evidence.

Minimum remaining work before full PASS: run the provided Linux checks; complete
and verify the real CLI path; add real DNS response traffic to the daemon and
assert relearn; implement real daemon write-boundary barriers (test-only build or
external traced write barriers), then repeat six cuts with live profile switches
and verify service configuration/identity/routes. A post-commit SIGKILL alone
cannot substitute for those barriers. None of these gaps is production permission.
