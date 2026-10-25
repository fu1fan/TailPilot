#!/usr/bin/env python3
"""Render a non-executable transaction contract. No host probes or writes."""
import json
import sys
from plan import load, digest

ACTIONS = {
 'reverse': ['Approved committed-release reverse migration; require completed durable all-off, live CAS, rearm recovery and preserve current state/routes.'],
 'rehearse': [
  'CONTROLLED PRODUCTION SWITCH: explicit rehearsal approval, independent OOB and exclusive window required.',
  'Same preflight/backup/stage/arm/switch checks, except no prior fallback proof; bootstrap state replay prohibited.',
  'Independent worker verifies patched service then immediately rolls back (operator) and verifies original service.',
  'Only successful local verification AND rollback publish bound 0600 evidence; failures retain OOB artifacts.',
  'Never commit; local evidence does not establish external E2E, power-loss or incompatible-state recovery.'
 ],
 'preflight': [
  'Acquire machine-global flock (not only deploymentID); reject another pending transaction.',
  'Verify actual hostname, local status Self.ID, architecture and release manifest/files.',
  'Verify current independent OOB/root recovery evidence hash and expiry; require G0-G7.',
  'Check first host has terminal evidence before second; coordinator holds cohort lease.',
  'Verify management/Codex exclusions; first configuration must be globally disabled.',
  'Compare all expected-before hashes and complete unit/EnvironmentFile inventory.',
  'Check disk, clock, package-manager exclusion and original AutoUpdate Check/Apply/apt hold.'
 ],
 'backup': [
  'Seal binary/CLI, unit and all drop-ins/EnvironmentFiles, config, prefs/state, RouteInfo/ledger.',
  'Seal route/rule snapshots, control-plane domains/approvals/ACL/DERP/ETag and update originals.',
  'Use root-only 0700 directory/0600 objects, UID/GID/mode/hash/restore map; never log contents.',
  'Pre-stop snapshot is provisional. Final consistent state snapshot follows stop in switch.',
  'Never put backups in Git/release/image or collect them as shareable lab evidence.'
 ],
 'stage': [
  'Verify manifest SHA and every binary, copy into a new immutable release directory.',
  'Keep apt binaries intact; retain previous daemon and CLI locally as LKG.',
  'Render drop-in by replacing only executable token; retain full argv and EnvironmentFile.',
  'Verify original unit/drop-ins again and systemd-analyze verify candidate; no service switch.'
 ],
 'arm': [
  'Install root-owned offline recovery code and immutable bound plan under transaction directory.',
  'Atomic fsync journal pending/deadline under common flock BEFORE timer installation.',
  'Install/enable boot recovery ordered Before=tailscaled.service; pending implies rollback.',
  'Arm independent systemd-run --on-active timer; explicit full rollback argv and timeout.',
  'Read back timer deadline, ExecStart, payload hash, ownership and boot ordering; failure blocks switch.'
 ],
 'switch': [
  'Reacquire common flock; CAS armed/deadline/expected-before; reconfirm timer and boot guard.',
  'Disable daemon AutoUpdate Apply, apt hold; save/read back original Check/Apply/hold.',
  'Run in local independent systemd task. Stop daemon then seal final consistent state.',
  'Atomically install only transaction-owned drop-in and disabled config; reload/start.',
  'Any failure enters same-lock rollback immediately, preserving timer/recovery if rollback fails.'
 ],
 'verify': [
  'Check local PID executable/hash/version, service Running, interface, prefs and StableID.',
  'Use versioned absolute CLI; verify accepted/applied generation and configuration hash.',
  'Record local layer only; do not equate active service or status with external E2E.'
 ],
 'commit': [
  'Hold common deadline/rollback flock; require verified phase and unexpired deadline.',
  'Validate Lead external E2E evidence bound to txn/StableID/release/config/generation.',
  'CAS/fsync committed FIRST; only then cancel timer and disable boot recovery.',
  'If rollback started or deadline elapsed, reject commit; never revive switched phase.'
 ],
 'rollback': [
  'Take same machine-global flock; terminal committed/rolled-back is an idempotent no-op.',
  'Persist rolling-back; stop patched service (boot path must not synchronously start ordered service).',
  'CAS-remove only this transaction drop-in; restore configuration only if after-hash matches.',
  'Preserve current identity state by default; use offline LKG daemon/CLI.',
  'Apply only ownership-aware sidecar/RouteInfo difference; unknown/manual/control conflicts block overwrite.',
  'Incompatible/corrupt state requires previously rehearsed fallback snapshot and identity checks.',
  'Restore recorded update policy only when returning to official/LKG maintenance policy.',
  'Verify local identity/routes; retain failed journal/recovery for OOB. Control plane is Lead responsibility.'
 ],
 'cleanup': [
  'Only terminal committed/rolled-back, no other active transaction; remove own transient units/files.',
  'Retain LKG, final backup, journal, evidence and maintenance owner/deadline.',
  'Do not unhold resident custom binary automatically; restore original policy on official rollback.',
  'OOB removal is last and separate Lead-confirmed operation after independent stability evidence.'
 ]
}

def main():
 phase,path,ident,host,stable,release,approved,boot,reason=sys.argv[1:]
 p=load(path)
 if phase not in ACTIONS: raise ValueError('phase')
 if (p['deploymentID'],p['host'],p['stableID'],p['releaseSHA256'],digest(path)) != (ident,host,stable,release,approved):
  raise ValueError('binding mismatch')
 argv=['/usr/local/lib/tailscale-unified-recovery/'+ident+'/rollback.sh', '--plan',
       '/var/lib/tailscale-unified-deploy/'+ident+'/plan.json','--deployment-id',ident,
       '--host',host,'--stable-id',stable,'--release-sha256',release,
       '--approved-plan-sha256',approved,'--reason','deadline']
 print(json.dumps({'schema':1,'mode':'dry-run','executable':False,'phase':phase,
   'deploymentID':ident,'target':{'host':host,'stableID':stable},
   'releaseSHA256':release,'approvedPlanSHA256':approved,
   'stageDirectory':'/usr/local/lib/tailscale-unified/'+p['releaseID'],
   'lock':'/run/lock/tailscale-unified-deploy.lock',
   'journal':'/var/lib/tailscale-unified-deploy/'+ident+'/journal.json',
   'bootRecovery':boot=='true','reason':reason,'rollbackArgv':argv,
   'nativeRecoveryArgv':['/usr/bin/python3','/var/lib/tailscale-unified-deploy/'+ident+'/native.py',
      '--internal','rollback','--transaction','/var/lib/tailscale-unified-deploy/'+ident],
   'actions':ACTIONS[phase], 'executionBlocker':'dry-run selected; native contract and private approval required for execution'},indent=2))

if __name__=='__main__':
 try: main()
 except (ValueError,OSError,KeyError,TypeError):
  print('deploy: plan validation or binding failed (contents redacted)',file=sys.stderr); sys.exit(1)
