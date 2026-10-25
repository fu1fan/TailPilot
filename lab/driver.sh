#!/usr/bin/env bash
set -euo pipefail
umask 077
export PYTHONDONTWRITEBYTECODE=1
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
action=${1:?internal action required}; shift
usage() {
 printf '%s\n' "Usage: $action.sh [--dry-run] [--run-id lab-<32 lowercase hex>]" \
  '       [--inventory FILE] [--case CASE] [--connector R|I] [--client-version 1.102.3|1.104.1]' \
  'create-topology generates a unique runID. Other actions require its inventory.' \
  'Outputs JSON plans only. --execute is rejected; no virtualization/network adapter.'
}
die() { printf '%s\n' "lab: $*" >&2; exit 1; }
run=; inventory=; caseid=; connector=; version=; seen=' '
while (($#)); do
 case "$1" in
 --help) usage; exit 0;;
 --dry-run) shift;;
 --execute) die 'execution adapter unavailable; planning only';;
 --run-id|--inventory|--case|--connector|--client-version)
  key=$1
  [[ $seen != *" $key "* ]] || die 'duplicate option'
  seen="$seen$key "
  (($# >= 2)) && [[ -n $2 && $2 != --* ]] || die 'missing value'
  case "$1" in --run-id) run=$2;; --inventory) inventory=$2;; --case) caseid=$2;; --connector) connector=$2;; --client-version) version=$2;; esac
  shift 2;;
 *) die 'unknown argument';;
 esac
done
python3 "$here/plan.py" "$action" "$run" "$inventory" "$caseid" "$connector" "$version"
