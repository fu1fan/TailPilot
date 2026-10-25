#!/usr/bin/env bash
# No SSH, deployment, downloads, host service changes, or firewall mutation.
set -euo pipefail
# R26_OUT remains an alias for older Lead automation.
R26_OUT=${R27_OUT:-${R26_OUT:-}}
: "${GO:?absolute Linux Go 1.26.6 binary}"
: "${R26_OUT:?new absolute output directory outside checkout}"
: "${GOCACHE:?existing cache}"
: "${GOPATH:?existing dependency cache}"
[[ $(uname -s) == Linux && $R26_OUT == /* && ! -e $R26_OUT ]]
[[ $("$GO" version) == 'go version go1.26.6 linux/'* ]]
cd "$(dirname "$0")/../.."
export GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off
umask 077
mkdir -p "$R26_OUT/bin"
git rev-parse HEAD > "$R26_OUT/HEAD"
git status --porcelain > "$R26_OUT/status"
[[ ! -s "$R26_OUT/status" ]]
"$GO" version > "$R26_OUT/go-version"
python3 lab/appc-e2e/preflight.py | tee "$R26_OUT/preflight.txt"
failed=0
run() {
 local name=$1 rc=0; shift
 { printf 'COMMAND:'; printf ' %q' "$@"; printf '\n'; "$@" || rc=$?; printf 'EXIT_STATUS=%s\n' "$rc"; } > "$R26_OUT/$name.txt" 2>&1
 printf '%s: %s\n' "$name" "$rc"
 if ((rc)); then failed=1; fi
}
pkgs=(./featurepolicy ./appc ./ipn/ipnlocal ./net/tstun ./wgengine/magicsock ./ipn/localapi ./client/local ./cmd/route-reconcile ./cmd/tailscale/cli ./lab/internal/testcontrol ./lab/g4-netns/control)
run packages "$GO" test "${pkgs[@]}" -count=1
run race "$GO" test -race "${pkgs[@]}" -count=1
run cli810-contract python3 lab/appc-e2e/cli810-selftest.py
run lab bash lab/tests/selftest.sh
run control-build "$GO" build -o "$R26_OUT/bin/control" ./lab/g4-netns/control
run security python3 lab/appc-e2e/security-selftest.py "$R26_OUT/bin/control"
run cli-build "$GO" build -o "$R26_OUT/bin/tailscale" ./cmd/tailscale
run daemon-build "$GO" build -o "$R26_OUT/bin/tailscaled" ./cmd/tailscaled
python3 lab/appc-e2e/daemon-overlay.py "$R26_OUT/daemon-overlay"
run barrier-build "$GO" build -overlay="$R26_OUT/daemon-overlay/overlay.json" -o "$R26_OUT/bin/tailscaled-barrier" ./cmd/tailscaled
python3 lab/appc-e2e/power-overlay.py "$R26_OUT/overlay"
run cli810-seed "$GO" test -overlay="$R26_OUT/overlay/overlay.json" ./ipn/ipnlocal -run '^TestR29PythonSeed810$' -count=1 -v
export R26_POWER_OUT="$R26_OUT/power"
run power "$GO" test -overlay="$R26_OUT/overlay/overlay.json" ./ipn/ipnlocal -run '^TestR26ProcessPowerCuts$' -count=1 -v
run profile-fixture "$GO" test -race ./ipn/ipnlocal -run '^TestConnectorDaemonDisableAndProfileHandoff$' -count=1 -v
# Optional repository-wide suites; these include unrelated upstream environment tests.
if [[ ${R26_ALL_PACKAGES:-0} == 1 ]]; then
 run repository-all "$GO" test ./... -count=1
 run repository-all-race "$GO" test -race ./... -count=1
fi
exit "$failed"
