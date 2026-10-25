# Isolated lab plan skeleton

The four Bash scripts emit JSON only, default dry-run. `--execute` always refuses.
This is a provider-neutral skeleton, not a hypervisor driver. No VM, daemon,
firewall, route, DNS service or control-plane object is created by these scripts.

```bash
bash lab/create-topology.sh > /tmp/lab-plan.json
# Take runID from the returned JSON, then explicitly reuse it:
bash lab/run-case.sh --run-id lab-<32hex> --inventory /tmp/lab-plan.json \
  --case I-P001 --connector R --client-version 1.102.3
bash lab/collect.sh --run-id lab-<32hex> --inventory /tmp/lab-plan.json
bash lab/destroy-topology.sh --run-id lab-<32hex> --inventory /tmp/lab-plan.json
```

Create generates a fresh UUID runID unless explicitly supplied. Its creation list
has separate management/data networks, R/I VMs, original C1/C2, independent relay,
DERP 900/901, authoritative DNS and upstream cache. The host must never join the
tailnet or use a production default route. Use a dedicated test tailnet; a local
controller result cannot replace official App Connector/control-plane acceptance.

Every resource is runID-scoped. A future provider adapter must pin images/binaries,
record provider IDs and ownership immediately after each successful create, and
mark `created=true` only then. Destroy validates the complete list and emits only
created entries in reverse order. It must recheck provider ownership before real
delete; a JSON boolean is not ownership proof. No wildcard deletion, host firewall
flush or host default-route replacement is permitted. Failed partial creation and
cleanup must keep their inventory/evidence for safe retry.

Run-case enumerates I-P000–111/I-PDEF, I-D1–4, I-L1–2, I-V1, I-X1–3, I-M1 and I-B1.
It requires R or I and original client version 1.102.3 or 1.104.1 explicitly.
Both connectors and both versions are separate runs. Keep C2 continuously probing;
cover official/OSS/unified-off baselines. Path cases require new/existing TCP and
UDP/QUIC, both directions, strict/allowed preference, cold and pre-established
relay, denial counters and <=30s convergence; never silently relax policy.

Inject faults only in the owned VM data interfaces, retaining the independent
management NIC. Record DNS/local advertisement/approval/client-install timestamps
separately. Resource acceptance uses 1vCPU/913MiB and a 2h cycle, not dev-host CPU
results. DNSSEC and independent-alias/DoH boundaries are reported explicitly.
I-B1 requires native dev validation of the R11 deploy adapter; matrix plans cannot run it.

Lead injects disposable test credentials via protected console/stdin or root-only
tmpfs files. No key in argv, image, source, shell tracing, environment dumps or
shared logs. Collect's allowlist is **redacted** reports only; raw state/prefs,
credentials and packet captures remain private on the VM with retention limits.
Never infer PASS from the existence of a report. All generated reports start
NOT_RUN. A future collector must validate evidence assertions and hash redacted
files; the current script emits the collection contract only.

Run `bash lab/tests/selftest.sh` for scope/unique ID/reverse inventory and every
case × connector × client-version plan. This is no E2E or native topology proof.

## R11 executable provider: QEMU + VDE

`provider_qemu.sh` is now a separate executable provider entrypoint; the original
four provider-neutral matrix scripts above remain planning-only. Default mode
emits actual argv without probing binaries/images or creating any file:

```bash
bash lab/provider_qemu.sh create --dry-run \
  --run-id lab-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  --root /private/tmp/lab-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  --images lab/provider-images.example.json
```

`create --execute` requires a dedicated **non-root Linux** user, user systemd,
KVM access, qemu-system-x86_64 with VDE support, qemu-img and vde_switch. Supply
absolute image/seed paths and real SHA256s for all nine roles. Per-role qcow2
backing images are read-only; only run-owned overlays are written. The provider
starts a foreground VDE switch and nine foreground QEMU user units. It does not
invoke sudo, tap, bridge, ip, nft or iptables, and never changes host default routes
or firewall. Each VM has a separate restricted slirp management NIC with a unique
loopback SSH forward (default 24000–24008); the VDE NIC is the isolated data plane.
Management ports must be free. Data-plane fault injection must never touch the
management NIC. This topology is not a connected production tailnet.

Lead must prepare images/seeds **before** execution:

- R/I with the release and deployment tools; C1/C2 with pinned original clients
  (run 1.102.3 and 1.104.1 separately, regenerate image map).
- Independent relay, DERP900 and DERP901 images, plus authoritative DNS and cache.
  Configure stable isolated data addresses via the documented MACs in dry-run argv.
  Provide controlled DNS zones and certificates, and an isolated controller in
  the lab (it may be hosted on the DNS VM for this minimal topology). Restricted
  management slirp intentionally cannot contact an external control plane.
- Seeds containing only non-secret network/service configuration and a disposable
  **public** SSH key. Credentials are injected after boot over the protected local
  console/management connection; no auth/private key in images, argv or Git.
- About 9 GiB guest RAM plus host overhead, KVM, sufficient overlay disk and user
  systemd linger if the lab must survive logout. Reduce/consolidate resources only
  as a separately reviewed topology; the provider does not pretend to discover
  available dev-host capacity.

Use the identical runID/root/images/port arguments with `destroy`. It loads only
that inventory, reconstructs expected commands (never executes inventory text),
checks scope and unit Description, stops created/intended units in reverse order
and deletes only enumerated overlay files. An intent is persisted before creation
so interrupted creation can be cleaned after an ownership recheck. The VDE socket
and private inventory/run directory are retained as evidence; no recursive delete.
Partial failures retain progress. Never reuse an existing run directory.

`python3 lab/tests/provider_test.py` verifies create dry-run/no writes, management
separation, negative scope/tamper cases and reverse created/intent-only cleanup.
No VM was started in R11. Provider startup, guest provisioning, power-loss recovery,
service readiness and E2E assertions still require Lead's real dev run. Native
provider execution is implemented but **unverified**, and a local controller
cannot establish official control-plane/App Connector acceptance.

## G4 netns 最小 lab（R17；Lead 在独立 dev 执行）

`g4-netns/run.sh` is an executable, **default dry-run** alternative to the nine-VM
provider. Native execution has not been performed by Astra. It creates one
run-owned bridge and four namespaces, each with a veth and real TUN tailscaled:

```text
host: testcontrol (HTTP), test DERP (TLS), STUN (UDP)
                  | bind only bridge's private IPv4
        run-owned bridge /29 (no NAT)
          |       |       |       |
          R       I       C1      C2
       patched patched  official official
       C1 rule all-off   1.102.3  1.102.3
```

This is an **R20 scoped evidence lab**, not a complete G4 acceptance engine.
It runs all-off traffic first, then atomically replaces R's featurepolicy file,
selecting C1's actual StableID, strict `allow={direct:false,peer_relay:false,
derp:true}`. The existing file watcher must apply the exact SHA and select DERP
within 30 seconds. I stays all-off. Both phases probe C1/C2 ↔ R/I with disco ping
and real TCP + UDP echo over TUN, recording bytes/time and UDP nonce/sequence results. Existing C2→R/I TCP connections
continuously echo through reload; C2→R, C1→I and C2→I must retain direct paths.
No production deployment, official control plane, external credentials, SSH, VM image,
reboot, host default-route/firewall/sysctl/service modification is involved.
Namespaces receive only a connected underlay route, no default route. All child
processes use the run's private state/socket paths. Host DNS is untouched.

### R21 first-packet readiness and bounded retries

Lead R20 run5 observed C1→R CLI ping timing out while TCP and UDP (8/8)
succeeded; R was transitioning from PROBING to ACTIVE/derp. R21 retains the
30-second policy-to-ACTIVE deadline. After convergence, a separate bounded
R→C1 CLI ping positive control must succeed and report `via DERP(g4)` before
`strict-before` and the full strict traffic matrix. `strict-warmup.json` records
every attempt. This warm-up does not substitute for C1→R ping or any traffic check.

In both default and strict phases, each direction/protocol gets at most three
attempts within its own 30-second monotonic window (not 30 seconds for the whole
matrix). CLI ping uses one packet with a 2-second timeout per attempt and a
3-second subprocess cap; TCP/UDP caps are 20/21 seconds, clipped to the remaining
budget. Failed attempts are separated by at most 250 ms. All three protocols
record attempts, including timeout/launch errors; successful probes stop retrying.
UDP retries require a complete fresh 8/8 exchange, never a union of partial replies.

`default-traffic-attempts.json` and `strict-traffic-attempts.json` are saved after
each attempt with return code/output or error, elapsed time and subprocess budget.
The existing traffic files contain final booleans and final protocol results.
A final failed probe retains its last error and makes the case FAIL, even if the
other two protocols succeed. Missing required path telemetry remains BLOCKED.
All eight directions must finally pass ping, TCP and UDP in both phases; existing
policy, gate/epoch, direct-control and DERP-counter assertions remain mandatory.
Retries tolerate startup convergence and do not establish zero packet loss,
latency bounds, socket continuity or production reliability. Scope remains IPv4,
non-QUIC, no NAT or fragmentation. Reuse the R19 binaries without rebuilding;
R21 native acceptance needs a fresh Lead run and retained attempt evidence.

### R20 UDP acceptance and limits

The normal dry-run/execute commands below automatically include UDP; no new flag
or binary is needed. Each node starts `udp.py serve <tailnet IPv4>` on UDP 18081
inside its netns. Each phase runs TCP and UDP for all eight C1/C2 ↔ R/I directions
(sequential probes in the same observation window, not a concurrency/load test).
The UDP client uses unconnected `sendto`/`recvfrom`, eight small datagrams, a fresh
UUID nonce per probe and sequence 0–7. It validates the exact echo and source
IP/port and waits at most two seconds per reply without per-datagram retries.
Loss, duplication, reordering or stale nonce fails that attempt; R21 records
the failure before retrying the entire probe with a fresh socket and nonce. Each request/reply proves delivery both ways; both endpoints also initiate
independent probes. Payloads are below MTU and do not test fragmentation.

`default-traffic.json` and `strict-traffic.json` retain the existing source,
target, ping, tcp and pingOutput fields and add `udp` plus `udpResult`: return
code/raw output, parsed count/bytes/sequences/nonce/time on success, explicit error
on failure. Subprocess timeouts also become failed UDP results in these files.
PASS requires all eight UDP results in both phases, TCP and CLI ping, plus all
existing CurAddr, DERP counter, R18 gate/confirmation and C2 TCP continuity checks.
The UDP application uses the same tailnet TUN/WireGuard path; it has no bypass
transport. Counter deltas span TCP+UDP and are not protocol-specific accounting.
CLI `tailscale ping` verifies WG/Disco reachability only and cannot replace UDP echo.

This only covers **IPv4, non-QUIC, no NAT**, on one private bridge. It does not
cover real NAT traversal, MTU/fragmentation, IPv6, cross-public-network traffic,
QUIC migration, or UDP socket continuity across reload. Existing R19 netns PASS
is TCP-only; R20 native UDP acceptance requires a fresh Lead run.

### Dev prerequisites and pinned inputs

Lead runs on the independent Linux dev host (192.0.2.30), **not production**:
root, Python >=3.9, Bash, iproute2 with JSON output, util-linux `unshare`/`mount`, network namespace/veth/bridge
and TUN kernel support (`/dev/net/tun`). No nft/iptables/nc/iperf dependency;
`tailscale up --netfilter-mode=off --accept-dns=false --accept-routes=false` runs
inside each namespace. Each daemon additionally receives a private mount namespace
with run-owned `/etc` and `/run` bind mounts and a disabled system D-Bus address,
so DNS initialization cannot touch host resolver files or service sockets.
Per-role `--statedir` isolates auxiliary state too. Existing host firewall/bridge-netfilter rules can prevent
the test; report that failure, do not flush or change them. Choose an unused RFC1918
/29; preflight rejects overlap with any non-default IPv4 route in any host table.
Use a dedicated host without concurrent namespace/link management. This network
is an isolation lab, not a hostile-code security boundary; root-run binaries and
input directory must be trusted and immutable during the run.

Obtain original 1.102.3 from the [official stable package server](https://pkgs.tailscale.com/stable/)
(select older version 1.102.3). The server documents appending `.sha256` to an
artifact URL for its checksum. Download/extract the matching architecture static
tarball separately; verify the archive against that checksum, retain provenance,
then compute **each extracted binary's** SHA256. Do not substitute a source-built
or unified client. This runner never downloads anything; version/commit plus a
Lead-supplied hash proves input identity, not independent vendor authenticity.
Both official executables must report version `1.102.3`, plus commit
`9329c3677031109ff6d0b80abee0cddc8f35ff6f` or exact long version
`1.102.3-t9329c3677-ga522f65e9`. Conflicting metadata is rejected. Official binaries
stamp the **annotated tag object**; source/release manifests still use the
**peeled commit** `53a0d659afa51835dd7a9283873cca44261454f8`. A source-built
peeled stamp or unified stamp cannot substitute for the official input. Each
Lead-supplied executable SHA256 remains mandatory (including apt binaries).

Build only the lab helper in the existing checkout/cache on dev (no go get, no
new modules or go.sum edits). Example from the handoff root; adjust tool location
if Lead's dev layout differs:

```bash
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off \
 GOCACHE="$PWD/work/go-cache" GOPATH="$PWD/work/go-path" \
 work/toolchain/go1.26.6/bin/go -C work/unified build \
 -o /opt/g4/control ./lab/g4-netns/control
sha256sum /opt/g4/control
```

The helper reuses repository `testcontrol`/`derpserver` and STUN code, creates an
in-memory unauthenticated test tailnet, and reports ephemeral listener ports and
DERP map to its private log. TLS uses a test-only ephemeral certificate with
`InsecureForTests` in this map. It binds only the run bridge IP; the runner starts
and stops it automatically. Do not start it on a public/production interface.
It supplies a non-nil local DERP map; no public control or DERP is needed.

Copy `g4-netns/inputs.example.json` to a private file and fill all full SHA256s:
release directory, **complete** manifest SHA (the `a963a891…` prefix is insufficient),
patch HEAD, architecture, official CLI/daemon paths and hashes, helper path/hash.
R20 reuses the verified R19 release and helper; **no release rebuild is required**.
Keep inputs.patchHEAD at the R19 binary commit
`646963bc48228f019492ef7cff798b585c30eec0`, not the newer lab-only commit.
The minimum release must contain the R18 evidence code.
Old R16/R17 binaries have no `pathEvidence` schema and yield BLOCKED with a rebuild
message. Use the release builder with the actual clean patch HEAD and toolchain
tree hash; refresh the full manifest SHA and helper hash. Never spoof patchHEAD
or reuse old binary hashes. Building a release does not authorize deployment. Preflight checks the pinned manifest, upstream/patch identity, clean flag,
manifest hashes of both patched executables, and version/commit output of all
four binaries. The sample zero hashes deliberately cannot execute successfully.
This checks consumed binaries, not the release's entire file inventory; use the
existing release bundle verifier separately for complete release validation.

### Run and read the evidence

From `work/unified` on dev, with a fresh runID and non-existing short root path:

```bash
run_id="g4-$(python3 -c 'import uuid; print(uuid.uuid4().hex)')"
bash lab/g4-netns/run.sh --run-id "$run_id" --root "/var/lib/$run_id" \
 --inputs /opt/g4/inputs.json --subnet 10.203.77.0/29 --dry-run
# Lead reviews the plan, then executes the identical scope as root:
sudo bash lab/g4-netns/run.sh --run-id "$run_id" --root "/var/lib/$run_id" \
 --inputs /opt/g4/inputs.json --subnet 10.203.77.0/29 --execute
# exit 0: NOT_RUN/PASS; exit 1: FAIL; exit 2: BLOCKED
sudo cat "/var/lib/$run_id/report.json"
```

Dry-run reads only the input JSON, validates parameters and prints NOT_RUN; it
creates no files and probes no binaries/host resources. Execute exclusively
creates a mode-0700 root (never reuses one). Logs, policy, state, command results,
StableIDs/IPs, input hashes, aggregate policy/transport counters, status JSON
(`Relay`/`CurAddr`), phase snapshots and report remain private there. Share only
reviewed/redacted evidence; **do not publish raw daemon state**. Counter snapshots
cover both ends and both controls; `counter-deltas.json` includes DERP/direct/
relay transport deltas, while policy snapshots retain deny-decision counters.
Transport metrics remain aggregate process counters, not unique packets.

R19 fixes the idle convergence wait: policy reload clears endpoint activity,
so status polling alone does not start a reachability probe. Before applying the
policy, the lab waits up to 90 seconds for all four Running identities and each
peer's Home DERP (`Relay=g4`) to agree. After application it actively pings
R→C1 through the existing policy gate; the original **30 seconds from policy
write to ACTIVE/derp/ACTIVE** deadline remains. DERP socket readiness alone is
never accepted as path health. Both R's C1 and C1's R `CurAddr` must be empty.
C2/other direct controls and all R18 evidence checks remain mandatory.

Use a fresh `/var/lib/g4-<id>` root. `/run` is privately bind-mounted by the daemon
wrapper; placing the evidence/socket root underneath it hides that root from
the daemon. R19 accepts `/var/lib` without modifying host service configuration.
The reused R19 release includes the additional bounded `path_decision` log fields
(actual StableID, matched/allow, homeDERP, bestAddr/derpAddr, candidate presence and
probe times). These diagnostics contain peer identifiers/addresses, not metric
labels, and obey the existing log switch/rate budget. Candidate presence is not
proof of reachability. Default-off does not emit these policy decision logs.

`policy-readiness.json`, `policy-applied.json`, `R-policy.json` and
`convergence.json` preserve readiness, the first applied evidence epoch and each
convergence sample/probe output, including on timeout. Per-peer `expectedMatched`
and `expectedAllow` in convergence JSON describe the lab's intended rule, not a
new claim from the daemon; compare the exact applied SHA, actual R.log decision
and R18 peer scope/counters. Missing evidence or readiness is BLOCKED; a measured
30-second convergence failure or forbidden acceptance is FAIL. No actual netns
PASS is implied by the fake-host tests.

R18 additionally saves `path-evidence.json` and `policy.pathEvidence` in the
snapshots. JSON fields are `schema:1`, `generation`, `enabled`, `matchedPeers`,
`unmatchedPeers`, `counters`. All 144 counter cells are present, including zeroes:

- Key: `matched|unmatched|unknown` / `direct|peer_relay|derp|unknown` /
  `send|probe|receive` / `accepted|rejected`.
- Confirmation keys instead end in `health|last_recv|pong` / `confirmed|forbidden`.
  `forbidden` is an audit of actual confirmation sites on an allow=false path;
  it is never incremented merely for a rejected packet. `last_recv` counts actual
  post-acceptance activity callbacks (the underlying WG timestamp is throttled).
- Fixed groups avoid peer/domain cardinality. Only one matched peer (C1) and two
  unmatched peers are allowed in this topology; status/StableID/policy SHA bind
  that group to C1. C2 is independently checked by bidirectional TCP+UDP, CurAddr and
  the existing-session monitor. Unmatched counters alone cannot identify C2.
- Gates count decisions, potentially more than once per packet, including WG
  pre-replay candidates. They do not claim successful syscalls or TUN delivery.
  Positive TCP+UDP and transport observations accompany the counters. Health/Pong
  and activity callbacks are separate from the pure WG predicate; no hot logs.
- Enabled tables own fresh atomic counters on **every publication**, including
  netmap/identity changes. A no-op policy install retains counters. Disable clears
  visible evidence and counts nothing; re-enable starts a fresh generation. Old
  in-flight gate decisions stay with the table they evaluated. Cells are atomic,
  but the snapshot is not a transaction across cells. Epoch is the decision
  boundary, not a promise to recall an already authorized kernel send.

Expected R20 result is **PASS only with complete scoped evidence**, FAIL for an
observed violation, BLOCKED for missing schema/cells or a reset observation window:

- I-PDEF: all-off and unmatched C2 bidirectional TCP+UDP/direct controls plus C2
  existing-session continuity; default-off evidence stays zero. This scoped PASS
  does **not** certify upstream handshake/throughput equivalence.
- I-P001: existing SHA/application/DERP/TCP checks and mandatory bidirectional UDP plus C1 matched direct,
  peer_relay and unknown accepted send/probe/receive and all confirmations = 0
  **since activation**, with zero forbidden-health audit counters. DERP send,
  receive and activity counters advance, and DERP health is confirmed. Unmatched
  direct send/receive/activity advance. The runner checks the first activation
  generation is 1 after baseline 0 and stays unchanged through traffic, so a
  reset before the first poll cannot erase a violation. Ordinary netmap churn
  during this window may conservatively BLOCK; repeat with a fresh runID.
- Full G4 remains open: no independent relay is offered, so zero relay acceptance
  does not prove active relay rejection interoperability; no existing C1 TCP continuity,
  QUIC, throughput equivalence, VM reboot, DNS/route lease E2E or QoS proof.

Missing R18 telemetry is never interpreted as zero. A `PASS` report explicitly
names its R20 scope and preserves these limitations; production approval is a
separate gate. Lead must rerun R20 with the verified R19 binaries; the earlier TCP-only PASS
does not certify UDP. Active peer-relay adversarial traffic remains unverified.

Normal completion, caught failure and SIGINT/SIGTERM stop owned child process
groups, then delete only successfully created resources in reverse order.
Cleanup rechecks link ifindex / namespace inode and refuses replacements;
failures remain marked created in `resources.json`, with errors in the report.
Evidence is never recursively removed. A truncated journal/write failure,
SIGKILL or power loss can leave resources; there is deliberately no replay of
untrusted journal commands. Lead must inspect `resources.json`, `processes.json`,
`ip -j link`, `ip netns list`, namespace inodes and actual process start identity
before manual removal of exact owned objects. Never kill a PID merely because
it appears in the old journal, never wildcard-delete namespaces or flush host
firewall/routes, and never reuse a failed runID. This is not crash-recovery proof.

Local implementation checks (no Linux topology execution):

```bash
PYTHONDONTWRITEBYTECODE=1 python3 lab/g4-netns/test_run.py
bash lab/tests/selftest.sh
python3 lab/tests/provider_test.py
```
