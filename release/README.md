# Unified release builder

`build-release.sh` defaults to validation/dry-run. It does not install, execute
built binaries, access servers or change networking. `--build` is an explicit
local build operation. The R10 run only exercised syntax, selftests and dry-run;
a real repeated build is still required. This is a public-source custom release,
not byte-for-byte reproduction of official Tailscale.

Prerequisites: Bash, Git with full history/tag v1.102.3, Python 3 standard library,
tar, cmp, fixed Go 1.26.6 and an already populated module cache. No downloads:
GOTOOLCHAIN=local, GOWORK=off, GOPROXY=off, GOSUMDB=off, GOENV=off. A missing module
is a build failure, not permission to fetch newer dependencies.

Example (review placeholders; commands are not automatic deployment):

```bash
head=$(git rev-parse HEAD)
toolhash=$(python3 release/toolchain-hash.py /opt/go1.26.6)
export GOPATH=/absolute/pinned/go-path
bash release/build-release.sh --dry-run --expect-head "$head" \
  --go /opt/go1.26.6/bin/go --toolchain-sha256 "$toolhash" \
  --output /absolute/new-release-directory
```

For a controlled build replace `--dry-run` with `--build`; optionally add
`--arm64`. The expected toolchain tree hash should come from a trusted inventory;
computing the hash on the current tree does not establish its download provenance.
The hash covers all relative names and file bytes in GOROOT, not just `bin/go`.
The toolchain itself is checked before invoking Go. Symlinks in it are refused.

The builder verifies clean HEAD, exact base/tag object and ancestor, full history,
WireGuard reverse/forward reproduction against UPSTREAM.sha256, pinned toolchain,
linux/CGO=0/amd64-v1 (optional arm64-v8.0), empty tags and exact single ldflags.
Both version stamps and gitCommitStamp identify unified.u1 and actual patch HEAD.
There is no supplemental official hash or claim of official equivalence.

Each repeat uses a separate empty GOCACHE and output directory. All three commands
(tailscaled, tailscale, route-reconcile) must match byte-for-byte. Independent
cache rebuilds can be expensive; ensure dev disk/RAM capacity first. Cross-built
Linux binaries are inspected with `go version -m`, never executed on macOS.

Output includes exact source archive, binary patch/series, base/HEAD, WireGuard
PATCH.diff/base/hash/license, sanitized module inventory, build info, config v2
schema and two globally disabled examples, scripts, manifest.json, SHA256SUMS,
RELEASE-NOTES.md, TEST-REPORT.md and evidence-index.json. Schema examples contain
no real domains, peers or credentials. The manifest includes every payload hash;
SHA256SUMS also hashes manifest.json (it cannot hash itself).

`release-ready` means **repeat-build ready only**. Its text explicitly states
that native/lab/deployment acceptance is NOT_RUN, and it is covered by the hash
inventory. Failed validation/build/compare produces no final output directory or
ready marker. Temporary build directories are removed on failure. Never treat
this marker as production approval. A failed concurrent source mutation check
also blocks publication; build from an isolated checkout with no concurrent writer.

Run `bash release/tests/selftest.sh` for parsing, fixture manifest hash integrity
and toolchain inventory sensitivity. These tests do not claim to compile binaries.
The deployed program's native version output and manifest must be compared by Lead.
See [maintenance](../docs/unified-maintenance.md), [deployment](../deploy/README.md)
and [lab](../lab/README.md) for remaining gates.

R13 module preparation is a separate, explicitly ONLINE operation. On a clean dev
checkout use the same absolute GOPATH/GOMODCACHE for preparation and building:

```bash
bash release/prepare-modcache.sh --expect-head "$head" \
  --go /opt/go1.26.6/bin/go --toolchain-sha256 "$toolhash" \
  --proxy https://proxy.golang.org --arm64
```

This downloads the full pinned graph with `go mod download all` in a temporary
`git archive` of the exact HEAD, verifies downloads, then checks the ORIGINAL
source offline with `go list -mod=readonly -m -json all` and the dependency closure
of all three release commands for each requested architecture. `go mod download`
without `all` does not necessarily populate the lazy-loaded transitive graph.
`go mod verify` alone is not a cache-completeness check.

The explicit HTTPS proxy and checksum database sum.golang.org require network
access during preparation; private/direct proxy overrides are disabled. Additional
checksums produced by `download all` are confined to the temporary copy and never
copied into source. If the original source lacks a checksum needed for the actual
release targets, preparation fails: review and commit an authenticated source
`go.sum` update separately. No source checksum update is included in R13.

The builder stays offline (`GOPROXY=off`, `GONOPROXY=off`, `GOSUMDB=off`) and uses
`-mod=readonly`. Before any compilation/output directory, it checks the module
inventory and exact target dependency closure and verifies cached content. Missing
cache reports how to prepare it, without automatically fetching anything. Dry-run
still validates the source/toolchain plan only; it does NOT certify cache readiness.
Preparation checks dependency availability, not compilation, independent repeat
build equality, or fresh-machine acceptance. Lead must run the real clean dev
preparation and repeated build; preserve those logs as release evidence. Keep the
cache and source free of concurrent writers throughout either operation.

## R15 offline transport bundle

```sh
bash release/bundle-release.sh --release-dir /absolute/built-release \
  --output /absolute/new-release.tar
bash release/bundle-release.sh --verify /absolute/new-release.tar
```

The bundler accepts an already built release, validates clean-source/repeat-build
metadata, releaseID/patchHEAD, required payload, every file digest and the exact
SHA256SUMS (including manifest.json). It refuses extra files, missing files,
symlinks, changed inputs and existing outputs. It does not build, download, deploy,
modify or delete the original release. `sourceDirty:false` is the recorded build
claim, not authentication of a producer; retain the trusted manifest digest from
Lead. A historical release need not match the bundler checkout's current HEAD.

The uncompressed USTAR has sorted names, fixed UID/GID/mtime, empty owner names,
and normalized executable/data modes. The same release bytes produce identical
tar bytes regardless of source permissions or mtimes. SHA256SUMS inside the tar is
the verified canonical payload checksum list; stdout prints the transport SHA256
for Lead to retain independently and compare after upload. Verification unpacks
members in memory, validates the manifest/checksums and exact canonical tar bytes;
it never extracts paths onto disk. Memory consumption is proportional to the
complete release plus tar; run on a dev machine with sufficient RAM. No signing
or production approval is implied. Preserve the external trusted transport digest:
a malicious producer can replace both payload and its unsigned hashes.

New builds include the bundle validator beside deploy scripts for make-plan.py.
Older R14 releases can be validated and bundled using the R15 checkout without
modifying their pinned manifests; run the R15 plan generator from that checkout.
Tests use synthetic payloads, not a new native build or server acceptance.

R16 packages the offline validator as `tools/bundle.py` (and its shell wrapper in
`tools/`) before generating manifest.json and SHA256SUMS. Packaged
`deploy/make-plan.py` discovers that path; a source checkout prefers
`release/bundle.py`. Explicit `--bundle FILE` is supported. The exact release file
list remains enforced; never patch an existing release in place to add the tool.

## R24 policy packaging

New manifests use `schemaVersion:2`. `release/config/schema.json` is a byte-identical
copy of `featurepolicy/schema-v2.json`; the builder checks equality and validates
both all-off examples even in dry-run. The package includes `config/schema.json`
and `config/schema-v2.json`. Missing/mismatched v2 schema copies fail bundle
validation. The transport validator still reads historical v1 bundles for offline
inspection, but the current deployment planner rejects v1 policy configurations.
Do not modify old sealed bundles to inject the new schema or scripts.

For future upgrades, first translate old `lease` configuration to all-off v2
(`app_connector_ttl.enabled=false`) and perform the isolated rehearsal. Enabling
TTL follows separately, with no simultaneous old v1 writer. Full native state
handoff/downgrade acceptance remains required. R24 ran fixture tests only: no
release build, push, host switch or production E2E is claimed.
