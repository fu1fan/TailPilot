#!/usr/bin/env bash
# R3 scale acceptance in a run-owned private network/mount namespace.
set -euo pipefail
[[ $(uname -s) == Linux && $EUID == 0 ]]
: "${R33_OUT:?existing gate output}"
root=$(cd "$(dirname "$0")/../.." && pwd)
[[ $R33_OUT == /root/unified-lab/r33-* && -d $R33_OUT/bin && ! -e $R33_OUT/scale ]]
python3 "$root/lab/appc-e2e/preflight.py"
printf 'nameserver 127.0.0.1\n' > "$R33_OUT/resolv.conf"
SECONDS=${R33_SCALE_SECONDS:-900}
unit="r3-scale-$(date +%s)-$$"
printf '%s\n' "$unit" > "$R33_OUT/scale-unit"
trap 'systemctl stop "$unit.service" >/dev/null 2>&1 || true' EXIT
set +e
systemd-run --unit="$unit" --wait --pipe --collect \
 --property=Type=exec --property=PrivateNetwork=yes --property=PrivateTmp=yes \
 --property=ProtectSystem=strict --property="ReadWritePaths=$R33_OUT" \
 --property="BindReadOnlyPaths=$R33_OUT/resolv.conf:/etc/resolv.conf" \
 --property=NoNewPrivileges=yes --property=KillMode=control-group \
 --property=RuntimeMaxSec=$((SECONDS + 1200)) --property=UMask=0077 \
 /usr/bin/env R6_DUALSTACK="${R6_DUALSTACK:-0}" R4_HTTP_REUSE="${R4_HTTP_REUSE:-1}" R4_CLIENT_DAEMON="${R4_CLIENT_DAEMON:-$R33_OUT/bin/tailscaled}" R4_RESET="${R4_RESET:-0}" R4_COLD="${R4_COLD:-0}" R33_PARENT_UNIT="$unit.service" R33_NATIVE_TUN="${R33_NATIVE_TUN:-scale-tun}" \
   R33_SCALE_DOMAINS="${R33_SCALE_DOMAINS:-632}" R33_SCALE_ROUTES="${R33_SCALE_ROUTES:-2420}" \
   R33_SCALE_SECONDS="$SECONDS" R33_SCALE_RATE="${R33_SCALE_RATE:-6}" \
   R33_SCALE_WORKERS="${R33_SCALE_WORKERS:-4}" R33_SCALE_BURST_SECONDS="${R33_SCALE_BURST_SECONDS:-60}" \
   R33_SCALE_BURST="${R33_SCALE_BURST:-8}" R33_SCALE_NAMES="${R33_SCALE_NAMES:-64}" \
   R33_SCALE_SEED_LEASES="${R33_SCALE_SEED_LEASES:-124}" \
   /usr/bin/python3 "$root/lab/appc-e2e/scale.py" --bin "$R33_OUT/bin" --out "$R33_OUT/scale" \
 > "$R33_OUT/scale-systemd.txt" 2>&1
rc=$?
set -e
journalctl -u "$unit.service" --no-pager > "$R33_OUT/scale-journal.txt"
printf '%s\n' "$rc" > "$R33_OUT/scale-exit"
exit "$rc"
