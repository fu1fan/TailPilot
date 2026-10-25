# TailPilot on CNB

Repository: https://cnb.cool/fu1fan/TailPilot

The public baseline preserves upstream v1.102.3 ancestry and collapses the private
R6 development series into one sanitized commit. Operational evidence, real host
addresses and local paths are excluded. Keep the private original for provenance;
do not mirror its branches/tags to this public repository.

## Daily development

Open CNB cloud development to obtain Go 1.26.6, Python, Git and a C compiler.
Create a feature branch, implement the change, run `.ci/test.sh`, then submit a PR.
Push/PR verification builds the fork and an **unmodified v1.102.3 client** and runs:

- Race tests for leases, policy, LocalBackend, persistence and DNS forwarding.
- Concurrent AAAA filtering, IPv6 route learning and SIGKILL/restart durability.
- Clear old routes, restart, enable TTL, learn a fresh lease, SIGKILL/restart:
  cleared routes stay absent and fresh leases survive.

The branch button **用户态压测（15 分钟）** runs a 900-second cold-start workload:
633 domains, 2421 assigned routes, 16 workers, 12 queries/second, and 32 additional
queries every 30 seconds. Reports include actual cgroup resources, latency
percentiles, request failures, deadlines and lease counts. This is a 4-CPU CNB
profile, not the old 1-vCPU production-shaped native test.

Userspace load allows at most max(1, floor(queries × 0.001)) request failures and
corresponding queue/failure counters. Persistence errors, observation errors,
unrecovered stale captures and broken route invariants remain failures. This
threshold does not classify failures as network noise: inspect their counters and
repeat the specific scenario before assigning a cause. Deterministic reset and
IPv6 assertions are exact. No retries are hidden inside the measured workload.

## Isolation and limits

No production auth keys, SSH credentials, tailnet login or real control service
are required. Synthetic control, DERP and upstream DNS stay on loopback. The test
uses real tailscaled, SOCKS and PeerAPI HTTP/DNS; route assertions read actual
advertised preferences and persisted TTL ownership.

The CNB unit-test build tag `tailpilot_cnb_test` disables interface socket
marking in LocalBackend tests, matching the real userspace daemon startup.
Without it, upstream fake-engine tests fail on CNB with `SO_BINDTODEVICE: operation
not permitted`. The tagged `_test.go` file never enters release binaries.

The runtime needs container UID 0 because the unchanged policy reader requires
root-owned files and ancestors. It drops NET_ADMIN, NET_RAW and SYS_ADMIN before starting
both daemons, uses userspace-networking, and never opens TUN or KVM. Binding the
synthetic DNS on port 53 still needs bind-service capability on some kernels.

`.ci/run-lab.sh` **temporarily replaces the container's /etc/resolv.conf** and
restores its contents on exit. It refuses to run unless
`TAILPILOT_DISPOSABLE_CONTAINER=1`. Use only in a disposable CI container. It is
not a command to run directly on a production/development host. SIGKILL cannot
run cleanup; the container must be discarded in that case. No parallel lab
invocations in the same container. Policy/runtime files live under a private
root-owned directory, not a world-writable /tmp ancestor.

This proves application behavior, not Linux forwarding, NAT, real IPv6 egress,
MTU, or domestic direct/peer-relay/DERP path selection. Those retain a separate
native test-host gate before an operator-approved deployment. Neither a CNB pass
nor an amd64/arm64 build authorizes production rollout.

## Artifacts and candidate builds

The **构建候选包** button invokes the existing offline release builder, after an
explicit online module-cache preparation. It builds amd64 and arm64 twice with
separate caches, compares binaries and emits source, manifest and SHA256 sums.
The Go tree hash is recorded from this container; it is not asserted to equal the
historical R6 toolchain. The base image is version-pinned, not digest-pinned;
repeat-build equality is not supply-chain identity across future image rebuilds.

Safe test summaries and candidate packages are attached to the triggering commit
for 30 days. No tailscaled state, runtime credentials, pcap or raw commands/logs
are uploaded. Failed runs retain console diagnostics; artifact upload stages run
only after successful preceding stages. Download successful packages from the
commit's attachments. A candidate is not a production release. No pipeline
creates production secrets, edits ACLs or deploys servers.

## Upstream maintenance

Keep patch work in the existing modules and keep behavior in configuration for
both server roles. Bring upstream changes into a dedicated branch, preserve
licenses, run race + smoke + cold-burst checks, then run native acceptance.
Update the pinned upstream stock-client commit/tag and Go image intentionally
when changing the base. The release builder also pins upstream ancestry: update
its checks together, never silently bypass them.

## Platform references

- [Pipeline grammar](https://docs.cnb.cool/zh/build/grammar.html)
- [Trigger rules](https://docs.cnb.cool/zh/build/trigger-rule.html)
- [Development container](https://docs.cnb.cool/zh/workspaces/custom-dev-env.html)
- [Manual buttons](https://docs.cnb.cool/zh/build/web-trigger.html)
- [Attachment plugin](https://cnb.cool/cnb/plugins/cnbcool/attachments)
