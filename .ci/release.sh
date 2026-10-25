#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export GOTOOLCHAIN=local
[[ $(git rev-parse --is-shallow-repository) == false ]] || git fetch --unshallow origin
git fetch origin tag v1.102.3
head=$(git rev-parse HEAD)
go_bin=$(command -v go)
# Records the observed container toolchain, not the historical R6 toolchain.
toolhash=$(python3 release/toolchain-hash.py "$(go env GOROOT)")
out=$(mktemp -d /root/tailpilot-release.XXXXXXXX)
bash release/prepare-modcache.sh --go "$go_bin" --expect-head "$head" \
  --toolchain-sha256 "$toolhash" --proxy https://proxy.golang.org --arm64
bash release/build-release.sh --build --go "$go_bin" --expect-head "$head" \
  --toolchain-sha256 "$toolhash" --output "$out/package" --arm64
mkdir -p .artifacts
tar -czf ".artifacts/TailPilot-$head.tar.gz" -C "$out" package
sha256sum .artifacts/TailPilot-*.tar.gz > .artifacts/SHA256SUMS
