#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export GOTOOLCHAIN=local GOWORK=off GOFLAGS=-mod=readonly
python3 third_party/wireguard-go/verify_patch.py
# Race detection covers asynchronous leases, storage and DNS forwarding.
go test -race -count=1 -timeout=12m ./appc ./featurepolicy ./ipn/ipnlocal ./ipn/store ./net/dns/resolver ./lab/g4-netns/control
