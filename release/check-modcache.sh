#!/usr/bin/env bash
# Source this only from the pinned-toolchain release scripts, in the source root.
# go list loads the exact build dependency closure; mod verify alone does not.
check_release_modcache() {
 local go=$1 arm64=$2 arch
 local arches=(amd64)
 [[ $arm64 = false ]] || arches+=(arm64)
 if ! "$go" list -mod=readonly -m -json all >/dev/null; then
  printf '%s\n' 'release: incomplete offline module graph; run release/prepare-modcache.sh with an explicit proxy' >&2
  return 1
 fi
 for arch in "${arches[@]}"; do
  if ! GOARCH=$arch "$go" list -mod=readonly -deps ./cmd/tailscaled ./cmd/tailscale ./cmd/route-reconcile >/dev/null; then
   printf '%s\n' "release: incomplete offline linux/$arch dependencies or source checksums; run release/prepare-modcache.sh (do not edit go.sum during build)" >&2
   return 1
  fi
 done
 "$go" mod verify
}
