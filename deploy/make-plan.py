#!/usr/bin/env python3
"""Read-only host observation. A plan is not approval. No deployment phases."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys

sys.dont_write_bytecode = True
import plan

CATEGORIES = {'daemon','cli','unit','dropins','config','prefs','state','routeinfo','ledger','routes','control','updates'}


def require(ok, message):
    if not ok:
        raise ValueError(message)


class Host:
    def path(self, name):
        return Path(name)

    def hostname(self):
        return platform.node()

    def machine(self):
        return platform.machine()

    def run(self, *args):
        r = subprocess.run(args, capture_output=True, timeout=15,
                           env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
        require(r.returncode == 0, 'read-only local probe failed')
        return r.stdout.decode()


def filehash(path):
    # Hash opaque state bytes; never decode, parse or emit their contents.
    p = Path(path)
    require(p.is_file() and not p.is_symlink(), 'required regular file missing or symlink')
    h = hashlib.sha256()
    with p.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def observe(h):
    require(h.machine() == 'x86_64', 'unsupported layout: Linux amd64 apt required')
    def show(prop):
        return h.run('/usr/bin/systemctl','show','tailscaled.service','--property='+prop,'--value').strip()
    cat = h.run('/usr/bin/systemctl','cat','tailscaled.service')
    starts = [s for s in cat.splitlines() if s.startswith('ExecStart=')]
    require(starts and not starts[-1].endswith('\\'), 'unsupported effective unit')
    daemon = starts[-1].removeprefix('ExecStart=').split(' ')[0]
    cli = '/usr/bin/tailscale'
    previous = None
    if daemon != '/usr/sbin/tailscaled':
        parent = Path(daemon).parent
        require(parent.parent == Path('/usr/local/lib/tailscale-unified') and plan.ID.fullmatch(parent.name) and Path(daemon).name == 'tailscaled', 'unsupported effective unit')
        cli = str(parent/'tailscale')
        matches = []
        for jf in h.path('/var/lib/tailscale-unified-deploy').glob('*/journal.json'):
            j = plan.read(jf)
            pf = jf.with_name('plan.json')
            if j.get('phase') == 'committed' and pf.exists():
                old = plan.read(pf)
                if old.get('releaseID') == parent.name:
                    require(j.get('approved') == filehash(pf), 'predecessor plan changed')
                    matches.append(jf.parent.name)
        require(len(matches) == 1, 'unique committed predecessor required')
        previous = matches[0]
        policy_file = h.path(str(parent/'policy.json'))
        plan.predecessor_alloff(plan.read(policy_file))
        policy = json.loads(h.run(cli, 'debug', 'unified-policy', 'status', '--json'))
        require(policy.get('source_sha256') == filehash(policy_file) and policy.get('applied') and policy.get('runtimeReady') and not any(policy.get('enabledModules', {'unknown': True}).values()), 'predecessor must be applied all-off')
    else:
        require('TS_UNIFIED_POLICY_FILE' not in cat, 'unsupported effective unit')
    unit = show('FragmentPath'); drops = show('DropInPaths').split(); env = show('EnvironmentFiles')
    envfiles = re.findall(r'(/[A-Za-z0-9_./-]+) \(ignore_errors=(?:yes|no)\)', env)
    require(' '.join(re.findall(r'/[A-Za-z0-9_./-]+ \(ignore_errors=(?:yes|no)\)', env)) == env, 'unsupported EnvironmentFiles layout')
    pid = show('MainPID')
    require(pid.isdigit() and int(pid) > 0, 'running original daemon required')
    argv = h.path('/proc/'+pid+'/cmdline').read_bytes().decode().split('\0')
    states = [s[8:] for s in argv if s.startswith('--state=')]
    sockets = [s[9:] for s in argv if s.startswith('--socket=')]
    require(len(states) == len(sockets) == 1 and states[0].startswith('/') and sockets[0].startswith('/'), 'unsupported state/socket layout')
    for p in envfiles:
        require('TS_UNIFIED_POLICY_FILE' not in h.path(p).read_text(), 'existing policy override unsupported')
    status = json.loads(h.run(cli,'--socket='+sockets[0],'status','--json'))
    prefs = json.loads(h.run(cli,'--socket='+sockets[0],'debug','prefs'))
    require(status.get('BackendState') == 'Running', 'daemon not Running')
    identity = status['Self']
    require(identity.get('ID') and identity.get('TailscaleIPs'), 'missing identity')
    held = 'tailscale' in h.run('/usr/bin/apt-mark','showhold').splitlines()
    return dict(daemon=daemon, cli=cli, previous=previous, host=h.hostname(), cat=cat, start=starts[-1], unit=unit, drops=drops,
                env=env, envfiles=envfiles, states=states, socket=sockets[0],
                stable=identity['ID'], ips=sorted(identity['TailscaleIPs']),
                check=prefs['AutoUpdate']['Check'], apply=prefs['AutoUpdate']['Apply'], held=held,
                prefsHash=hashlib.sha256(json.dumps(prefs, sort_keys=True).encode()).hexdigest())


def bundle_path(explicit=None):
    here = Path(__file__).resolve().parent
    candidates = [Path(explicit)] if explicit else [here.parent/'release/bundle.py',
                                                    here/'tools/bundle.py', here.parent/'tools/bundle.py']
    for candidate in candidates:
        if candidate.is_file() and not candidate.is_symlink():
            return candidate
    raise ValueError('bundle.py missing; supply --bundle with the reviewed validator')


def generate(a, h=None):
    h = h or Host()
    # Shared offline release validator; no binaries from the release are executed.
    spec = importlib.util.spec_from_file_location('bundle', bundle_path(getattr(a, 'bundle', None)))
    bundle = importlib.util.module_from_spec(spec); spec.loader.exec_module(bundle)
    payload = bundle.directory(a.release_dir)
    manifest = json.loads(payload['manifest.json'])
    require(manifest.get('schemaVersion') == 2, 'v2 rollout requires a v2 release')
    config_hash = filehash(a.configuration)
    config = plan.read(a.configuration)
    plan.all_off_config(config)
    peers = plan.read(a.exclusions_peers); domains = plan.read(a.exclusions_domains)
    require(isinstance(peers,list) and peers and isinstance(domains,list) and domains, 'nonempty JSON exclusion arrays required')
    first = observe(h)
    require(not a.host or a.host == first['host'], 'hostname mismatch')
    inventory = plan.read(a.backup_inventory) if a.backup_inventory else {}
    require(isinstance(inventory,dict) and not set(inventory)-CATEGORIES, 'invalid backup inventory categories')
    backups = {k: list(inventory.get(k, [])) for k in CATEGORIES}
    for k, values in {'daemon':[first['daemon']], 'cli':[first['cli']],
                      'unit':[first['unit']], 'dropins':first['drops'],
                      'config':[a.configuration], 'state':first['states']}.items():
        backups[k] = sorted(set(backups[k] + values))
    if first['previous']:
        prior = '/var/lib/tailscale-unified-deploy/' + first['previous']
        backups['config'] += [str(Path(first['daemon']).with_name('policy.json')), prior+'/plan.json', prior+'/journal.json']
    missing = sorted(k for k,v in backups.items() if not v)
    require(not missing, 'missing backup categories: '+', '.join(missing)+
            '; Lead: provide --backup-inventory JSON category -> existing absolute paths; use actual backing state only when reviewed to contain that category; no placeholder files')
    paths = set(first['envfiles'])
    for entries in backups.values():
        require(all(isinstance(v,str) and v.startswith('/') for v in entries), 'backup paths must be absolute')
        paths.update(entries)
    before = {p:filehash(h.path(p)) for p in sorted(paths)}
    require(filehash(a.configuration) == config_hash, 'configuration changed during observation')
    oobhash = filehash(a.oob_evidence)
    external = a.external_evidence or str(Path(a.output).absolute().with_suffix('.external.json'))
    fallback = a.fallback_evidence or str(Path(a.output).absolute().with_suffix('.fallback.json'))
    if a.fallback_evidence:
        filehash(fallback)
    cohort = getattr(a, 'cohort', 'first') or 'first'
    predecessor = getattr(a, 'predecessor_evidence', None)
    require(cohort in ('first', 'second'), 'invalid cohort')
    if cohort == 'second':
        require(predecessor and Path(predecessor).is_file() and not Path(predecessor).is_symlink(),
                'second cohort requires first-host terminal stability evidence')
        predecessor_hash = filehash(predecessor)
    else:
        require(not predecessor, 'predecessor evidence is reserved for the second cohort')
        predecessor_hash = ''
    n = dict(socket=first['socket'], tailscaleIPs=first['ips'], daemon=first['daemon'],
             cli=first['cli'], unit=first['unit'], dropins=first['drops'], stateFiles=backups['state'],
             unitCatSHA256=hashlib.sha256(first['cat'].encode()).hexdigest(), environmentFilesShow=first['env'],
             minFreeBytes=1024**3, minAvailableMemoryBytes=128*1024**2,
             fallbackEvidence=fallback,
             predecessorEvidenceFile=(str(Path(predecessor).absolute()) if predecessor else
                                      str(Path(a.output).absolute().with_suffix('.predecessor.json'))))
    if first['previous']: n['previousDeployment'] = first['previous']
    p = dict(deploymentID=a.deployment_id, host=first['host'], stableID=first['stable'],
             releaseID=manifest['releaseID'], releaseDirectory=a.release_dir,
             releaseSHA256=filehash(Path(a.release_dir)/'manifest.json'), deadlineSeconds=a.deadline_seconds,
             oobEvidence=a.oob_evidence, oobSHA256=oobhash, externalEvidence=external,
             externalSHA256=filehash(external) if a.external_evidence else None,
             backupFiles=backups, expectedBefore=before, originalExecStart=first['start'],
             environmentFiles=first['envfiles'], configuration=a.configuration,
             configurationSHA256=config_hash, excludePeers=peers, excludeDomains=domains,
             cohort=cohort, predecessorEvidence=predecessor_hash, autoUpdateCheck=first['check'],
             autoUpdateApply=first['apply'], aptHeld=first['held'], native=n)
    plan.validate(p)
    require(before[a.configuration] == config_hash, 'configuration changed during observation')
    require(observe(h) == first and all(filehash(h.path(f)) == v for f,v in before.items()), 'host changed during observation; regenerate')
    require(bundle.directory(a.release_dir) == payload and filehash(a.oob_evidence) == oobhash,
            'inputs changed during observation')
    return p


def templates(p):
    binding = {k:p[k] for k in ('deploymentID','host','stableID','releaseSHA256')}
    return {'notice':'TEMPLATES ONLY: Lead must fill actual evidence, review and regenerate on production; generation is not approval',
            'oob':dict(binding, kind='oob', independent=None, rootRecovery=None, passed=None, expiresUnix=None),
            'fallback':dict(binding, kind='state-downgrade-rehearsal', passed=None,
                            oldDaemonSHA256=p['expectedBefore'][p['native']['daemon']]),
            'approval':dict(deploymentID=p['deploymentID'], host=p['host'], approvedPlanSHA256=None,
                            expiresUnix=None, serialWindowExclusive=None, excludePeers=p['excludePeers'], excludeDomains=p['excludeDomains'])}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    for key in ('release-dir','configuration','deployment-id','exclusions-peers','exclusions-domains','oob-evidence','output'):
        ap.add_argument('--'+key, required=True)
    for key in ('host','fallback-evidence','external-evidence','backup-inventory','bundle'):
        ap.add_argument('--'+key)
    ap.add_argument('--deadline-seconds',type=int,default=900)
    ap.add_argument('--cohort',choices=('first','second'),default='first',
                    help='second requires --predecessor-evidence from the first host terminal state')
    ap.add_argument('--predecessor-evidence')
    ap.add_argument('--dry-run',action='store_true')
    a = ap.parse_args()
    require(60 <= a.deadline_seconds <= 1800, 'deadline must be 60–1800 seconds')
    for key in ('release_dir','configuration','exclusions_peers','exclusions_domains','oob_evidence','output','fallback_evidence','external_evidence','backup_inventory','predecessor_evidence'):
        if getattr(a,key): setattr(a,key,str(Path(getattr(a,key)).absolute()))
    p = generate(a)
    if not a.dry_run:
        # Exclusive creation refuses symlinks, existing files and accidental input overwrite.
        fd = os.open(a.output, os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600)
        with os.fdopen(fd,'w') as f:
            os.fchmod(f.fileno(),0o600)
            json.dump(p,f,sort_keys=True,indent=2); f.write('\n'); f.flush(); os.fsync(f.fileno())
        print('SHA256='+filehash(a.output))
    print(json.dumps(dict(mode='dry-run' if a.dry_run else 'review-required', host=p['host'],
                         backupCategories=sorted(p['backupFiles']), templates=templates(p)),sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (UnicodeError, json.JSONDecodeError):
        sys.exit('make-plan: invalid local encoding/JSON (contents redacted)')
    except ValueError as e:
        # Only fixed diagnostics from our checks; JSON decoder values are never echoed.
        if type(e) is ValueError: sys.exit('make-plan: '+str(e))
        sys.exit('make-plan: invalid local JSON (contents redacted)')
    except (OSError, KeyError, TypeError, subprocess.SubprocessError):
        sys.exit('make-plan: local observation failed (contents redacted)')
