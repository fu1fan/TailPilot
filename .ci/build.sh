#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
[[ $(go env GOVERSION) == go1.26.6 ]]
export GOTOOLCHAIN=local GOWORK=off GOFLAGS=-mod=readonly
out=${TAILPILOT_BUILD_DIR:-/root/tailpilot-build}
mkdir -p "$out/bin"
for cmd in tailscale tailscaled; do
  CGO_ENABLED=0 go build -trimpath -o "$out/bin/$cmd" "./cmd/$cmd"
done
CGO_ENABLED=0 go build -trimpath -o "$out/bin/control" ./lab/g4-netns/control
# Compare against an unmodified upstream client, never against a second fork.
base=53a0d659afa51835dd7a9283873cca44261454f8
git show-ref --verify --quiet refs/tags/v1.102.3 || git fetch origin tag v1.102.3
[[ $(git rev-parse 'v1.102.3^{}') == "$base" ]]
stock=$(mktemp -d)
trap 'rm -rf "$stock"' EXIT
git archive "$base" | tar -x -C "$stock"
(cd "$stock" && CGO_ENABLED=0 go build -trimpath -o "$out/bin/stock-tailscaled" ./cmd/tailscaled)
sha256sum "$out"/bin/* > "$out/SHA256SUMS"
