#!/usr/bin/env bash
set -euo pipefail
umask 077
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
die() { printf '%s\n' "release prepare: $*" >&2; exit 1; }
go=; proxy=; head=; toolhash=; arm64=false; seen=' '
while (($#)); do
 [[ $seen != *" $1 "* ]] || die 'duplicate option'
 seen="$seen$1 "
 case "$1" in
 --help)
  echo 'Usage: prepare-modcache.sh --go /absolute/go --expect-head SHA --toolchain-sha256 SHA --proxy https://proxy.golang.org [--arm64]'
  echo 'Explicit ONLINE cache preparation only; no compilation, source edits or deployment.'
  exit 0;;
 --arm64) arm64=true; shift;;
 --go|--expect-head|--toolchain-sha256|--proxy)
  (($# >= 2)) || die 'missing option value'
  case "$1" in --go) go=$2;; --expect-head) head=$2;; --toolchain-sha256) toolhash=$2;; --proxy) proxy=$2;; esac
  shift 2;;
 *) die 'unknown argument';;
 esac
done
[[ $head =~ ^[0-9a-f]{40}$ && $toolhash =~ ^[0-9a-f]{64}$ ]] || die 'full head/toolchain SHA required'
[[ $go = /* && -x $go && ! -L $go ]] || die 'absolute non-symlink Go required'
# One explicit HTTPS proxy, no implicit direct/network fallback or credentials.
[[ $proxy = https://* && $proxy != *','* && $proxy != *'|'* && $proxy != *'@'* && $proxy != *'?'* && $proxy != *'#'* && $proxy != *' '* ]] || die 'one explicit HTTPS proxy URL required'
cd "$root"
[[ $(git rev-parse HEAD) = "$head" && -z $(git status --porcelain --untracked-files=all) ]] || die 'clean expected HEAD required'
export GOTOOLCHAIN=local GOWORK=off GOENV=off GOFLAGS= CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1 GOARM64=v8.0
export GOROOT="$(cd -- "$(dirname -- "$go")/.." && pwd -P)"
unset GOEXPERIMENT
[[ $(python3 release/toolchain-hash.py "$GOROOT") = "$toolhash" ]] || die 'toolchain tree hash mismatch'
[[ $("$go" env GOVERSION) = go1.26.6 ]] || die 'Go 1.26.6 required'
# Fix proxy/checksum policy, even if the invoking shell has private-module rules.
export GOPROXY="$proxy" GOSUMDB=sum.golang.org GONOSUMDB= GONOPROXY= GOPRIVATE=
# Resolve once: both the temporary source and subsequent builder use this cache.
export GOMODCACHE="$("$go" env GOMODCACHE)"
[[ $GOMODCACHE = /* ]] || die 'absolute module cache required'
tmp=$(mktemp -d "${TMPDIR:-/tmp}/unified-modcache.XXXXXXXX")
trap 'rm -rf -- "$tmp"' EXIT
# download all may add sums for dependencies of dependency tests. Isolate these
# additions from the release source; final offline checks use ORIGINAL go.sum.
git archive --format=tar "$head" > "$tmp/source.tar"
mkdir "$tmp/source"
tar -xf "$tmp/source.tar" -C "$tmp/source"
printf 'Preparing module cache ONLINE via %s (checksum DB sum.golang.org)\n' "$proxy"
(cd "$tmp/source" && "$go" mod download all && "$go" mod verify)
# Any required source sum absent from the committed source now fails, rather
# than silently copying temporary sums back. Such a change needs a source commit.
export GOPROXY=off GOSUMDB=off
source release/check-modcache.sh
check_release_modcache "$go" "$arm64"
[[ $(git rev-parse HEAD) = "$head" && -z $(git status --porcelain --untracked-files=all) ]] || die 'source changed during preparation'
printf 'Prepared and checked OFFLINE: %s (HEAD %s, arm64=%s); no binaries built\n' "$GOMODCACHE" "$head" "$arm64"
