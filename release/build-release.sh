#!/usr/bin/env bash
set -euo pipefail
umask 077
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
usage() { cat <<'USAGE'
Usage: build-release.sh [--dry-run|--build] --expect-head SHA --go /absolute/go
       --toolchain-sha256 SHA --output /absolute/new-directory [--arm64]
Default: validate and print a build plan; no output directory or binaries created.
--build is local/offline compilation only; never installs or executes binaries.
USAGE
}
die() { printf '%s\n' "release: $*" >&2; exit 1; }
mode=dry-run; head=; go=; toolhash=; out=; arm64=false
seen=' '
while (($#)); do
 [[ $seen != *" $1 "* ]] || die 'duplicate option'
 seen="$seen$1 "
 case "$1" in
 --help) usage; exit 0;;
 --dry-run) mode=dry-run; shift;;
 --build) mode=build; shift;;
 --arm64) arm64=true; shift;;
 --expect-head|--go|--toolchain-sha256|--output)
  (($# >= 2)) || die 'missing option value'
  case "$1" in --expect-head) head=$2;; --go) go=$2;; --toolchain-sha256) toolhash=$2;; --output) out=$2;; esac
  shift 2;;
 *) die 'unknown argument';;
 esac
done
[[ $head =~ ^[0-9a-f]{40}$ && $toolhash =~ ^[0-9a-f]{64}$ ]] || die 'full head/toolchain SHA required'
[[ $go = /* && -x $go && $out = /* && ! -e $out && ! -L $out ]] || die 'absolute Go and unused absolute output required'
[[ -d $(dirname -- "$out") && $(basename -- "$out") != . && $(basename -- "$out") != .. ]] || die 'output parent must exist'
out="$(cd -- "$(dirname -- "$out")" && pwd -P)/$(basename -- "$out")"
case "$out/" in "$root/"*) die 'output must be outside source tree';; esac
cd "$root"
[[ $(git rev-parse HEAD) = "$head" ]] || die 'HEAD mismatch'
[[ -z $(git status --porcelain --untracked-files=all) ]] || die 'dirty source tree'
[[ $(git rev-parse --is-shallow-repository) = false ]] || die 'shallow source tree'
base=53a0d659afa51835dd7a9283873cca44261454f8
tag=9329c3677031109ff6d0b80abee0cddc8f35ff6f
[[ $(git rev-parse 'v1.102.3^{}') = "$base" && $(git rev-parse v1.102.3) = "$tag" ]] || die 'base/tag mismatch'
git merge-base --is-ancestor "$base" "$head" || die 'base not ancestor'
export GOTOOLCHAIN=local GOWORK=off GOPROXY=off GOSUMDB=off GOENV=off GOFLAGS=-mod=readonly GONOPROXY=off GONOSUMDB= GOPRIVATE=
export CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1 GOARM64=v8.0 TZ=UTC LC_ALL=C
unset GOEXPERIMENT
[[ ! -L $go ]] || die 'Go binary symlink not accepted'
export GOROOT="$(cd -- "$(dirname -- "$go")/.." && pwd -P)"
actual=$(python3 release/toolchain-hash.py "$GOROOT")
[[ $actual = "$toolhash" ]] || die 'toolchain tree hash mismatch'
[[ $("$go" env GOVERSION) = go1.26.6 ]] || die 'Go 1.26.6 required'
python3 third_party/wireguard-go/verify_patch.py
version=1.102.3-unified.u1
ldflags="-s -w -X tailscale.com/version.longStamp=$version-$head -X tailscale.com/version.shortStamp=$version -X tailscale.com/version.gitCommitStamp=$head"
printf 'mode=%s version=%s patch=%s GOOS=linux CGO=0 GOAMD64=v1 tags=<empty> arm64-build-only=%s\n' "$mode" "$version" "$head" "$arm64"
cmp featurepolicy/schema-v2.json release/config/schema.json || die "v2 schema copy differs"
PYTHONDONTWRITEBYTECODE=1 python3 - <<'PYCONFIG'
import sys
sys.path.insert(0, 'deploy')
import plan
for name in ('idcfast', 'residential'):
    plan.all_off_config(plan.read('release/config/' + name + '.json'))
PYCONFIG
[[ $mode = build ]] || exit 0
source release/check-modcache.sh
check_release_modcache "$go" "$arm64"
parent=$(dirname -- "$out")
[[ -d $parent && ! -L $parent ]] || die 'output parent must exist'
tmp=$(mktemp -d "$parent/.unified-build.XXXXXXXX")
trap 'rm -rf -- "$tmp"' EXIT
mkdir -p "$tmp/package/source" "$tmp/package/config" "$tmp/package/tools"
git archive --format=tar "$head" > "$tmp/package/source/patched-source.tar"
git log --reverse --format='%H %s' "$base..$head" > "$tmp/package/source/series"
git diff --binary "$base" "$head" > "$tmp/package/source/unified.patch"
printf '%s\n' "$base" > "$tmp/package/source/base.txt"
printf '%s\n' "$head" > "$tmp/package/source/patch-head.txt"
printf '%s\n' 2e01ba5b00f0a02b0fb37e668c7cac6717880568 > "$tmp/package/source/wireguard-base.txt"
cp third_party/wireguard-go/{PATCH.diff,UPSTREAM.sha256,LICENSE} "$tmp/package/source/"
cp featurepolicy/schema-v2.json release/config/*.json "$tmp/package/config/"
cp -R deploy lab "$tmp/package/"
cp release/bundle.py release/bundle-release.sh "$tmp/package/tools/"
cp release/build-release.sh release/prepare-modcache.sh release/check-modcache.sh release/manifest.py release/toolchain-hash.py "$tmp/package/tools/"
"$go" list -m -json all > "$tmp/modules.raw"
python3 - "$tmp/modules.raw" "$tmp/package/source/modules.json" <<'PYMODULES'
import json,sys
text=open(sys.argv[1]).read(); dec=json.JSONDecoder(); modules=[]
while text.strip():
 obj,n=dec.raw_decode(text.lstrip()); text=text.lstrip()[n:]
 def clean(o):
  out={k:v for k,v in o.items() if k in ('Path','Version','Sum','GoModSum','GoVersion','Main')}
  if 'Replace' in o: out['Replace']=clean(o['Replace'])
  return out
 modules.append(clean(obj))
open(sys.argv[2],'w').write(json.dumps(modules,sort_keys=True,indent=2)+'\n')
PYMODULES
arches=(amd64)
if [[ $arm64 = true ]]; then arches+=(arm64); fi
for arch in "${arches[@]}"; do
 export GOARCH=$arch
 for pass in first second; do
  export GOCACHE="$tmp/cache-$pass"
  mkdir -p "$tmp/$pass/linux-$arch"
  for binary in tailscaled tailscale route-reconcile; do
   "$go" build -trimpath -buildvcs=false -tags '' -ldflags "$ldflags" -o "$tmp/$pass/linux-$arch/$binary" "./cmd/$binary"
  done
 done
 for binary in tailscaled tailscale route-reconcile; do
  cmp "$tmp/first/linux-$arch/$binary" "$tmp/second/linux-$arch/$binary" || die 'repeat build mismatch'
  "$go" version -m "$tmp/first/linux-$arch/$binary" > "$tmp/first/linux-$arch/$binary.buildinfo"
 done
 mv "$tmp/first/linux-$arch" "$tmp/package/"
done
[[ -z $(git status --porcelain --untracked-files=all) && $(git rev-parse HEAD) = "$head" ]] || die 'source changed during build'
# Marker means repeated BUILD only, never production approval or lab acceptance.
printf '%s\n' 'repeated-build-only; lab and deployment gates NOT_RUN' > "$tmp/package/release-ready"
python3 release/manifest.py "$tmp/package" "$head" "$toolhash" "$ldflags" "$arm64"
[[ ! -e $out && ! -L $out ]] || die 'output appeared during build'
mv -- "$tmp/package" "$out"
printf 'Built (not deployed): %s\n' "$out"
