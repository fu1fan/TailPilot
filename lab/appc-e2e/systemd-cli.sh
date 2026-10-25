#!/usr/bin/env bash
# Invoked by Lead only, on an isolated Linux dev host.
set -euo pipefail
# R26_OUT remains an alias for older Lead automation.
R26_OUT=${R27_OUT:-${R26_OUT:-}}
[[ $(uname -s) == Linux && $EUID == 0 ]]
: "${R26_OUT:?existing linux-checks output directory}"
root=$(cd "$(dirname "$0")/../.." && pwd)
[[ $R26_OUT == /* && -d $R26_OUT/bin && ! -e $R26_OUT/cli810 ]]
python3 "$root/lab/appc-e2e/preflight.py"
# A unique transient unit owns all helper/daemon descendants. No host DNS,
# routes or service sockets: userspace daemon, PrivateNetwork, explicit state/socket.
unit="r27-lab-$(date +%s)-$$"
cleanup() { systemctl stop "$unit.service" >/dev/null 2>&1 || true; }
trap cleanup EXIT
set +e
systemd-run --unit="$unit" --wait --pipe --collect \
 --property=Type=exec --property=PrivateNetwork=yes \
 --property=PrivateTmp=yes --property=ProtectSystem=strict \
 --property="ReadWritePaths=$R26_OUT" --property=NoNewPrivileges=yes \
 --property=KillMode=control-group --property=RuntimeMaxSec=300 \
 --property=UMask=0077 \
 /usr/bin/python3 "$root/lab/appc-e2e/cli810.py" --bin "$R26_OUT/bin" --out "$R26_OUT/cli810" \
 > "$R26_OUT/systemd-cli.txt" 2>&1
rc=$?
set -e
journalctl -u "$unit.service" --no-pager > "$R26_OUT/systemd-journal.txt"
printf 'CLI runner exit=%s (2 means scoped lifecycle completed, full matrix still PARTIAL)\n' "$rc"
exit "$rc"
