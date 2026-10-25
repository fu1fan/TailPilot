#!/usr/bin/env bash
set -euo pipefail
[[ $(uname -s) == Linux && $EUID == 0 ]]
: "${R33_OUT:?existing gate output}"
root=$(cd "$(dirname "$0")/../.." && pwd)
[[ $R33_OUT == /root/unified-lab/r33-* && -d $R33_OUT/bin && ! -e $R33_OUT/native ]]
python3 "$root/lab/appc-e2e/preflight.py"
printf 'nameserver 127.0.0.1\n' > "$R33_OUT/resolv.conf"
unit="r33-native-$(date +%s)-$$"
printf '%s\n' "$unit" > "$R33_OUT/native-unit"
trap 'systemctl stop "$unit.service" >/dev/null 2>&1 || true' EXIT
set +e
systemd-run --unit="$unit" --wait --pipe --collect \
 --property=Type=exec --property=PrivateNetwork=yes --property=PrivateTmp=yes \
 --property=ProtectSystem=strict --property="ReadWritePaths=$R33_OUT" \
 --property="BindReadOnlyPaths=$R33_OUT/resolv.conf:/etc/resolv.conf" \
 --property=NoNewPrivileges=yes --property=KillMode=control-group \
 --property=RuntimeMaxSec=1800 --property=UMask=0077 \
 /usr/bin/env R33_PARENT_UNIT="$unit.service" R33_NATIVE_TUN="${R33_NATIVE_TUN:-r33tun}" R33_FOCUS="${R33_FOCUS:-}" /usr/bin/python3 "$root/lab/appc-e2e/native.py" --bin "$R33_OUT/bin" --out "$R33_OUT/native" \
 > "$R33_OUT/native-systemd.txt" 2>&1
rc=$?
set -e
journalctl -u "$unit.service" --no-pager > "$R33_OUT/native-journal.txt"
printf '%s\n' "$rc" > "$R33_OUT/native-exit"
exit "$rc"
