#!/usr/bin/env bash
# Only use in a disposable build container: this temporarily changes its DNS.
set -euo pipefail
cd "$(dirname "$0")/.."
[[ ${TAILPILOT_DISPOSABLE_CONTAINER:-} == 1 ]] || { echo 'Requires an explicitly disposable container'; exit 2; }
[[ $(id -u) == 0 ]] || { echo 'Root ownership required by the production policy validator'; exit 2; }
mode=${1:-smoke}
case "$mode" in smoke|stress) ;; *) exit 2;; esac
build=${TAILPILOT_BUILD_DIR:-/root/tailpilot-build}
run=$(mktemp -d /root/tailpilot-lab.XXXXXXXX)
chmod 700 "$run"
cp /etc/resolv.conf "$run/resolv.conf.before"
cleanup() {
  rc=$?
  cat "$run/resolv.conf.before" > /etc/resolv.conf
  python3 .ci/collect.py "$run" .artifacts
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
printf 'nameserver 127.0.0.1\n' > /etc/resolv.conf
# No KVM, TUN, NET_ADMIN, NET_RAW or SYS_ADMIN in the test process. Keep bind-service
# for the synthetic upstream on port 53; all control/DERP endpoints are loopback.
run_case() {
  local name=$1
  shift
  setpriv --bounding-set=-net_admin,-net_raw,-sys_admin --no-new-privs \
    env TAILPILOT_USERSPACE=1 R4_CLIENT_DAEMON="$build/bin/stock-tailscaled" \
      R33_SCALE_SEED_LEASES=0 "$@" \
    timeout --signal=TERM --kill-after=20s 1500s \
    python3 lab/appc-e2e/scale.py --bin "$build/bin" --out "$run/$name"
}
if [[ $mode == smoke ]]; then
  run_case dualstack R6_DUALSTACK=1 R33_SCALE_SECONDS=60
  run_case reset R4_RESET=1 R33_SCALE_SECONDS=60
else
  run_case cold-burst R4_COLD=1 R33_SCALE_SECONDS=900 R33_SCALE_RATE=12 \
    R33_SCALE_WORKERS=16 R33_SCALE_NAMES=64 R33_SCALE_BURST_SECONDS=30 R33_SCALE_BURST=32
fi
