#!/usr/bin/env bash
set -euo pipefail
umask 077
export PYTHONDONTWRITEBYTECODE=1
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
phase=${1:?internal phase required}; shift
usage() {
 printf '%s\n' "Usage: $phase.sh [--dry-run] --plan FILE --deployment-id ID --host HOST" \
  '       --stable-id ID --release-sha256 SHA --approved-plan-sha256 SHA' \
  '       [--rehearsal (rehearse.sh only)]' \
  '       [--boot-recovery] [--reason deadline|failure|operator|boot]' \
  'Default: review-only dry-run. Linux native execution requires --execute --approval FILE.' \
  'Native execution still requires Lead dev-systemd acceptance before production.'
}
die() { printf '%s\n' "deploy: $*" >&2; exit 1; }
rehearsal=false; execute=false; mode=; approval=; acceptance=; plan=; id=; host=; stable=; release=; approved=; boot=false; reason=operator
seen=' '
while (($#)); do
 case "$1" in
 --rehearsal) [[ $phase = rehearse && $rehearsal = false ]] || die 'rehearsal flag only valid once for rehearse'; rehearsal=true; shift;;
 --help) usage; exit 0;;
 --execute) [[ -z $mode ]] || die 'duplicate/conflicting execution mode'; mode=execute; execute=true; shift;;
 --dry-run) [[ -z $mode ]] || die 'duplicate/conflicting execution mode'; mode=dry-run; shift;;
 --boot-recovery) [[ $phase = rollback ]] || die 'boot only valid for rollback'; boot=true; shift;;
 --plan|--deployment-id|--host|--stable-id|--release-sha256|--approved-plan-sha256|--approval|--acceptance-sha256|--reason)
  key=$1
  [[ $seen != *" $key "* ]] || die 'duplicate option'
  seen="$seen$key "
  (($# >= 2)) && [[ -n $2 && $2 != --* ]] || die 'missing value'
  case "$key" in
   --acceptance-sha256) acceptance=$2;; --approval) approval=$2;; --plan) plan=$2;; --deployment-id) id=$2;; --host) host=$2;; --stable-id) stable=$2;;
   --release-sha256) release=$2;; --approved-plan-sha256) approved=$2;; --reason) reason=$2;;
  esac
  shift 2;;
 *) die 'unknown argument';;
 esac
done
[[ $phase != rehearse || $rehearsal = true ]] || die 'rehearse requires --rehearsal'
[[ -n $plan && -n $id && -n $host && -n $stable && $release =~ ^[0-9a-f]{64}$ && $approved =~ ^[0-9a-f]{64}$ ]] || die 'all target and approval bindings required'
case "$reason" in deadline|failure|operator|boot) :;; *) die 'invalid rollback reason';; esac
[[ $phase = rollback || $reason = operator ]] || die 'reason only valid for rollback'
if [[ $execute = true ]]; then
 python3 "$here/review.py" "$phase" "$plan" "$id" "$host" "$stable" "$release" "$approved" "$boot" "$reason" >/dev/null
else
 python3 "$here/review.py" "$phase" "$plan" "$id" "$host" "$stable" "$release" "$approved" "$boot" "$reason"
fi

if [[ $execute = true ]]; then
 [[ -n $approval ]] || die '--execute requires --approval FILE'
 [[ $boot = false ]] || die 'boot recovery uses the installed private payload only'
 extra=()
 if [[ $rehearsal = true ]]; then extra+=(--rehearsal); fi
 exec python3 "$here/native.py" "${extra[@]}" --phase "$phase" --plan "$plan" --approval "$approval" --approved "$approved" --acceptance-sha256 "$acceptance"
fi
