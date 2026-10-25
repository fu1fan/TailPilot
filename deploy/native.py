#!/usr/bin/env python3
"""Offline Linux transaction runner. Never imported by the planning path.

All host effects are behind Host; tests inject a filesystem and fake commands.
Production entrypoints never accept a root prefix or alternate command runner.
"""
import argparse
import contextlib
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import stat
import subprocess
import sys
import tempfile
import time

import plan

BASE = '/var/lib/tailscale-unified-deploy'
UNIT = 'tailscaled.service'
TERMINAL = {'committed', 'rolled-back'}
READINESS_SECONDS = 30


class ReadinessError(ValueError):
    def __init__(self, category):
        self.category = category
        super().__init__('readiness: ' + category)


def require(ok, message):
    if not ok:
        raise ValueError(message)


def private(path):
    p = Path(path)
    for part in [p, *p.parents]:
        s = part.lstat()
        require(not stat.S_ISLNK(s.st_mode) and s.st_uid == 0 and not s.st_mode & 0o022,
                'root-owned non-writable path required')
    require(p.is_file() and not p.stat().st_mode & 0o077, 'private regular evidence required')


def durable_bytes(path, data, mode=0o600):
    path = Path(path)
    require(not path.is_symlink(), 'symlink destination')
    fd, name = tempfile.mkstemp(prefix='.unified-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as out:
            os.fchmod(out.fileno(), mode)
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
        os.replace(name, path)
        syncdir(path.parent)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def syncdir(path):
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class Host:
    def path(self, name):
        return Path(name)

    def run(self, *args, timeout=120):
        # No inherited PATH, shell, output of secret-bearing commands or network fetches.
        r = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           timeout=timeout, env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
        require(r.returncode == 0, 'local command failed: ' + Path(args[0]).name)
        return r.stdout.decode()

    def ctl(self, *args, timeout=120):
        return self.run('/usr/bin/systemctl', *args, timeout=timeout)

    def sleep(self, seconds):
        time.sleep(seconds)

    def now(self):
        return time.time(), time.monotonic(), self.path('/proc/sys/kernel/random/boot_id').read_text().strip()


class Transaction:
    def __init__(self, p, approved, host=None, acceptance_hash=None):
        self.p, self.approved, self.h = p, approved, host or Host()
        self.acceptance_hash = acceptance_hash
        self.root = self.h.path(BASE)
        self.d = self.root / p['deploymentID']
        self.jf = self.d / 'journal.json'
        self.prefix = 'unified-' + p['deploymentID']
        self.boot = self.prefix + '-recovery.service'
        self.drop = self.h.path('/etc/systemd/system/tailscaled.service.d/90-unified-transaction.conf')
        self.guard = self.h.path('/etc/systemd/system/tailscaled.service.d/89-unified-recovery.conf')
        self.stage = self.h.path('/usr/local/lib/tailscale-unified/' + p['releaseID'])
        self.n = p['native']

    @contextlib.contextmanager
    def lock(self):
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        with open(self.root / 'host.lock', 'a') as f:
            os.chmod(f.name, 0o600)
            fcntl.flock(f, fcntl.LOCK_EX)
            for other in self.root.glob('*/journal.json'):
                if other != self.jf:
                    require(plan.read(other)['phase'] in TERMINAL, 'another host transaction is pending')
            yield

    def journal(self):
        return plan.read(self.jf)

    def write(self, phase, **extra):
        j = self.journal() if self.jf.exists() else {}
        j.update(extra, phase=phase, deploymentID=self.p['deploymentID'], approved=self.approved)
        plan.atomic(self.jf, j)

    def valid_deadline(self):
        j = self.journal()
        wall, mono, boot = self.h.now()
        require(boot == j['bootID'] and mono < j['monotonicDeadline'] and wall < j['wallDeadline'], 'deadline expired or boot changed')

    def argv(self, action):
        return ['/usr/bin/python3', str(self.d / 'native.py'), '--internal', action,
                '--transaction', str(self.d)]

    def install(self, path, data, mode=0o600):
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        durable_bytes(path, data.encode() if isinstance(data, str) else data, mode)

    def cli(self, *args, old=False, timeout=120):
        exe = self.d / 'lkg-tailscale' if old else self.stage / 'tailscale'
        return self.h.run(str(exe), '--socket=' + self.n['socket'], *args, timeout=timeout)

    def snapshot(self, label):
        out = self.d / label
        out.mkdir(mode=0o700)
        records = {}
        for i, name in enumerate(self.p['expectedBefore']):
            src = self.h.path(name)
            if not src.exists():
                records[name] = {'sha256': 'ABSENT'}
                continue
            require(src.is_file() and not src.is_symlink(), 'nonregular backup')
            s = src.stat()
            fd = os.open(src, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(fd, 'rb') as f:
                data = f.read()
            require(hashlib.sha256(data).hexdigest() == plan.digest(src), 'backup source changed')
            self.install(out / str(i), data)
            records[name] = dict(file=str(i), sha256=hashlib.sha256(data).hexdigest(),
                                 mode=stat.S_IMODE(s.st_mode), uid=s.st_uid, gid=s.st_gid)
        plan.atomic(out / 'manifest.json', records)
        syncdir(self.d)

    def before(self):
        for name, expected in self.p['expectedBefore'].items():
            f = self.h.path(name)
            if f == self.guard and self.n.get('previousDeployment') and self.jf.exists() and self.journal()['phase'] in ('armed', 'queued'):
                expected = hashlib.sha256(('[Unit]\nRequires='+self.boot+'\nAfter='+self.boot+'\n').encode()).hexdigest()
            require(not f.is_symlink(), 'symlink source')
            require((not f.exists()) if expected == 'ABSENT' else
                    f.is_file() and plan.digest(f) == expected, 'expected-before conflict')

    def identity(self, old=False):
        s = json.loads(self.cli('status', '--json', old=old))
        require(s['BackendState'] == 'Running' and s['Self']['ID'] == self.p['stableID'] and
                sorted(s['TailscaleIPs']) == sorted(self.n['tailscaleIPs']), 'local identity mismatch')
        return s

    def wait_ready(self, old=False):
        # One monotonic budget includes subprocess time; no unbounded status call.
        end = self.h.now()[1] + READINESS_SECONDS
        delay = 0.1
        category = 'service-unavailable'
        identity_changed = False
        saw_active = False
        while True:
            if not old:
                self.valid_deadline()
            remaining = end - self.h.now()[1]
            if remaining <= 0:
                raise ReadinessError('identity-mismatch' if identity_changed else category)
            try:
                active = self.h.ctl('is-active', UNIT, timeout=min(2, remaining)).strip() == 'active'
            except (ValueError, OSError, subprocess.SubprocessError):
                active = False
            saw_active |= active
            category = 'status-unavailable' if saw_active else 'service-unavailable'
            remaining = end - self.h.now()[1]
            if active and remaining > 0:
                try:
                    s = json.loads(self.cli('status', '--json', old=old, timeout=min(2, remaining)))
                except (ValueError, OSError, subprocess.SubprocessError):
                    s = {}
                if isinstance(s, dict) and s.get('BackendState'):
                    category = 'backend-not-running'
                    if s['BackendState'] == 'Running':
                        peer = s.get('Self') or {}
                        matches = (isinstance(peer, dict) and peer.get('ID') == self.p['stableID'] and
                                   isinstance(s.get('TailscaleIPs'), list) and
                                   all(isinstance(ip, str) for ip in s['TailscaleIPs']) and
                                   sorted(s['TailscaleIPs']) == sorted(self.n['tailscaleIPs']))
                        # A Running identity change must never be hidden by a later good sample.
                        identity_changed |= not matches
                        if matches and not identity_changed and self.h.now()[1] < end:
                            if not old:
                                self.valid_deadline()
                            return
            remaining = end - self.h.now()[1]
            if remaining > 0:
                self.h.sleep(min(delay, remaining))
            delay = min(delay * 2, 1)

    def package_idle(self):
        for name in ('/var/lib/dpkg/lock', '/var/lib/dpkg/lock-frontend', '/var/lib/apt/lists/lock'):
            with open(self.h.path(name), 'r+') as lock:
                fcntl.lockf(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                fcntl.lockf(lock, fcntl.LOCK_UN)

    def fallback_evidence(self, path):
        private(path)
        fb = plan.read(path)
        require(fb.get('passed') is True and fb.get('host') == self.p['host'] and
                fb.get('stableID') == self.p['stableID'] and
                fb.get('releaseSHA256') == self.p['releaseSHA256'] and
                fb.get('oldDaemonSHA256') == self.p['expectedBefore'][self.n['daemon']] and
                fb.get('kind') == 'state-downgrade-rehearsal', 'fallback rehearsal missing or binding mismatch')

    def rehearsal_destination(self):
        out = Path(self.n['fallbackEvidence'])
        require(not out.exists() and not out.is_symlink(), 'rehearsal output must be unused')
        for part in [out.parent, *out.parent.parents]:
            st = part.lstat()
            require(stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and not st.st_mode & 0o022,
                    'unsafe rehearsal output parent')
        return out

    def predecessor(self):
        """Authenticate a committed custom layout; never erase its recovery record."""
        ident = self.n.get('previousDeployment')
        if not ident:
            return
        d = self.root / ident
        pending = d / 'policy-intent.json'
        require(not pending.exists() or plan.read(pending)['phase'] == 'complete', 'predecessor policy handoff pending')
        old = plan.read(d / 'plan.json')
        j = plan.read(d / 'journal.json')
        require(j.get('phase') == 'committed' and j.get('approved') == plan.digest(d / 'plan.json') and
                old['host'] == self.p['host'] and old['stableID'] == self.p['stableID'] and
                self.n['daemon'] == '/usr/local/lib/tailscale-unified/' + old['releaseID'] + '/tailscaled',
                'committed predecessor binding mismatch')
        require(self.drop.is_file() and plan.digest(self.drop) == j['candidateSHA256'], 'predecessor drop-in drift')
        require(plan.digest(self.h.path(self.n['daemon'])) == j['daemonSHA256'] and
                plan.digest(self.h.path(self.n['cli'])) == j['cliSHA256'], 'predecessor binary drift')
        if self.guard.exists():
            expected = '[Unit]\nRequires=unified-' + ident + '-recovery.service\nAfter=unified-' + ident + '-recovery.service\n'
            require(self.guard.read_text() == expected, 'foreign predecessor guard')
        policy_file = self.h.path(str(Path(self.n['daemon']).with_name('policy.json')))
        plan.predecessor_alloff(plan.read(policy_file))
        status = json.loads(self.h.run(self.n['cli'], '--socket=' + self.n['socket'],
                                      'debug', 'unified-policy', 'status', '--json'))
        require(status.get('source_sha256') == plan.digest(policy_file) and status.get('applied') and status.get('runtimeReady') and
                not any(status.get('enabledModules', {'unknown': True}).values()), 'predecessor not all-off')

    def restore_layout_file(self, path, candidate):
        """Idempotent compare-and-restore, from the sealed pre-switch snapshot."""
        require(not path.is_symlink(), 'symlink layout target')
        records = plan.read(self.d / 'readable/manifest.json')
        name = str(path) if type(self.h) is Host else '/' + str(path.relative_to(self.h.path('/')))
        record = records.get(name, {'sha256': 'ABSENT'})
        current = plan.digest(path) if path.exists() else 'ABSENT'
        if current == record['sha256']:
            return
        require(current == candidate, 'foreign layout edit; OOB required')
        if record['sha256'] == 'ABSENT':
            path.unlink(); syncdir(path.parent)
        else:
            data = (self.d / 'readable' / record['file']).read_bytes()
            require(hashlib.sha256(data).hexdigest() == record['sha256'], 'layout backup drift')
            self.install(path, data, record['mode'])

    def preflight(self, source, approval, rehearsal=False):
        require(not self.d.exists(), 'transaction already exists')
        require(platform.node() == self.p['host'], 'hostname mismatch')
        require(platform.machine() == 'x86_64', 'only reviewed amd64 adapter supported')
        self.before()
        self.package_idle()
        plan.package(self.p)
        plan.evidence(self.p['oobEvidence'], self.p['oobSHA256'], self.p, 'oob')
        require(plan.read(self.p['oobEvidence']).get('host') == self.p['host'], 'OOB host mismatch')
        for name in (source, approval, self.p['oobEvidence']):
            private(name)
        a = plan.read(approval)
        require(a.get('approvedPlanSHA256') == self.approved and a.get('host') == self.p['host'] and
                a.get('deploymentID') == self.p['deploymentID'] and a.get('expiresUnix', 0) > time.time() and
                a.get('serialWindowExclusive') is True and
                a.get('excludePeers') == self.p['excludePeers'] and
                a.get('excludeDomains') == self.p['excludeDomains'], 'approval/window mismatch')
        if rehearsal:
            require(a.get('rehearsal') is True, 'explicit rehearsal approval required')
            self.rehearsal_destination()
        else:
            require(a.get('rehearsal') is not True, 'rehearsal approval cannot authorize deployment')
            self.fallback_evidence(self.n['fallbackEvidence'])
        if self.p['cohort'] == 'second':
            private(self.n['predecessorEvidenceFile'])
            prev = plan.read(self.n['predecessorEvidenceFile'])
            require(plan.digest(self.n['predecessorEvidenceFile']) == self.p['predecessorEvidence'] and
                    prev.get('phase') in TERMINAL and prev.get('stable') is True and
                    prev.get('host') != self.p['host'], 'first host terminal stability proof missing')
        # Exact reviewed effective unit and complete systemd-reported inventory.
        cat = self.h.ctl('cat', UNIT)
        require(hashlib.sha256(cat.encode()).hexdigest() == self.n['unitCatSHA256'], 'unit view changed')
        starts = [line for line in cat.splitlines() if line.startswith('ExecStart=')]
        require(starts and starts[-1] == self.p['originalExecStart'] and not starts[-1].endswith('\\'), 'effective ExecStart mismatch')
        for prop, expected in [('DropInPaths', self.n['dropins']), ('FragmentPath', [self.n['unit']])]:
            require(self.h.ctl('show', UNIT, '--property=' + prop, '--value').split() == expected, 'unit inventory changed')
        require(self.h.ctl('show', UNIT, '--property=EnvironmentFiles', '--value').strip() == self.n['environmentFilesShow'], 'EnvironmentFile inventory changed')
        if self.n.get('previousDeployment'):
            self.predecessor()
        else:
            require(not self.drop.exists() and not self.guard.exists(), 'reserved drop-in exists')
        for name in self.p['environmentFiles']:
            require('TS_UNIFIED_POLICY_FILE' not in self.h.path(name).read_text(), 'policy env override')
        require(self.n.get('previousDeployment') or 'TS_UNIFIED_POLICY_FILE' not in cat, 'existing policy override unsupported')
        pid = self.h.ctl('show', UNIT, '--property=MainPID', '--value').strip()
        require(pid.isdigit() and int(pid) > 0, 'running original daemon required')
        argv = self.h.path('/proc/' + pid + '/cmdline').read_bytes().decode().split('\x00')
        require('--socket=' + self.n['socket'] in argv, 'socket path not explicit in live argv')
        require(any('--state=' + name in argv for name in self.n['stateFiles']), 'state path not explicit in live argv')
        for name in (self.n['daemon'], self.n['cli'], self.n['unit'], *self.n['dropins'], *self.p['environmentFiles'], *self.n['stateFiles']):
            require(name in self.p['expectedBefore'] and self.p['expectedBefore'][name] != 'ABSENT', 'required backup absent')
        require(shutil.disk_usage(self.root).free >= self.n['minFreeBytes'], 'insufficient backup disk')
        mem = self.h.path('/proc/meminfo').read_text().split('MemAvailable:')[1].split()[0]
        require(int(mem)*1024 >= self.n['minAvailableMemoryBytes'], 'insufficient memory')
        # Refuse active package operations; apt hold is not a package-manager mutex.
        require(not self.h.ctl('list-jobs', '--no-legend').strip(), 'systemd jobs pending')
        self.d.mkdir(mode=0o700)
        self.install(self.d / 'plan.json', Path(source).read_bytes())
        self.install(self.d / 'unit-before.txt', cat)
        self.install(self.d / 'argv-before.json', json.dumps(argv))
        self.install(self.d / 'approval.json', Path(approval).read_bytes())
        for name in ('native.py', 'plan.py', 'compatibility.py'):
            self.install(self.d / name, Path(__file__).with_name(name).read_bytes())
        self.install(self.d / 'schema-v2.json', plan.policy_schema_path().read_bytes())
        self.install(self.d / 'lkg-tailscale', self.h.path(self.n['cli']).read_bytes(), 0o700)
        self.install(self.d / 'lkg-tailscaled', self.h.path(self.n['daemon']).read_bytes(), 0o700)
        self.identity(old=True)
        prefs = json.loads(self.cli('debug', 'prefs', old=True))
        require(prefs['AutoUpdate']['Check'] == self.p['autoUpdateCheck'] and
                prefs['AutoUpdate']['Apply'] == self.p['autoUpdateApply'], 'update originals mismatch')
        held = 'tailscale' in self.h.run('/usr/bin/apt-mark', 'showhold').splitlines()
        require(held == self.p['aptHeld'], 'apt original mismatch')
        self.install(self.d / 'prefs-before.json', json.dumps(prefs))
        self.install(self.d / 'oob-evidence.json', Path(self.p['oobEvidence']).read_bytes())
        if not rehearsal:
            self.install(self.d / 'fallback-evidence.json', Path(self.n['fallbackEvidence']).read_bytes())
        self.install(self.d / 'routes-before.json', self.h.run('/usr/sbin/ip', '-json', 'route', 'show', 'table', 'all'))
        self.install(self.d / 'routes6-before.json', self.h.run('/usr/sbin/ip', '-6', '-json', 'route', 'show', 'table', 'all'))
        self.install(self.d / 'rules6-before.json', self.h.run('/usr/sbin/ip', '-6', '-json', 'rule', 'show'))
        self.install(self.d / 'rules-before.json', self.h.run('/usr/sbin/ip', '-json', 'rule', 'show'))
        self.write('preflight', rehearsal=rehearsal)

    def backup(self):
        self.before()
        self.snapshot('readable')
        self.write('backup')

    def stage_release(self):
        plan.package(self.p)
        reuse = self.stage.exists()
        require(not self.stage.is_symlink(), 'symlink release directory')
        if reuse:
            require({f.name for f in self.stage.iterdir()} == {'tailscaled', 'tailscale', 'route-reconcile', 'policy.json'},
                    'unexpected staged files')
        else:
            self.stage.mkdir(mode=0o755, parents=True)
        for name in ('tailscaled', 'tailscale', 'route-reconcile'):
            data = (Path(self.p['releaseDirectory']) / 'linux-amd64' / name).read_bytes()
            require(data[:5] == b'\x7fELF\x02' and data[18:20] == b'\x3e\x00', 'not amd64 ELF')
            if reuse:
                f = self.stage / name
                require(not f.is_symlink() and f.is_file() and f.read_bytes() == data and
                        stat.S_IMODE(f.stat().st_mode) == 0o755, 'existing stage differs')
            else:
                self.install(self.stage / name, data, 0o755)
        if reuse:
            f = self.stage / 'policy.json'
            require(not f.is_symlink() and f.is_file() and
                    f.read_bytes() == Path(self.p['configuration']).read_bytes() and
                    stat.S_IMODE(f.stat().st_mode) == 0o600, 'existing policy differs')
        else:
            self.install(self.stage / 'policy.json', Path(self.p['configuration']).read_bytes())
        self.h.run(str(self.stage / 'tailscale'), 'debug', 'unified-policy', 'validate', '--offline', '--file', str(self.stage / 'policy.json'))
        text = '[Service]\nExecStart=\n' + self.p['originalExecStart'].replace(self.n['daemon'], str(self.stage / 'tailscaled'), 1) + '\nEnvironment=TS_UNIFIED_POLICY_FILE=' + str(self.stage / 'policy.json') + '\n'
        self.install(self.d / 'candidate.conf', text)
        self.install(self.d / 'tailscaled.service', self.h.ctl('cat', UNIT) + '\n' + text)
        self.h.run('/usr/bin/systemd-analyze', 'verify', str(self.d / 'tailscaled.service'))
        self.write('stage', candidateSHA256=plan.digest(self.d / 'candidate.conf'),
                   daemonSHA256=plan.digest(self.stage / 'tailscaled'), cliSHA256=plan.digest(self.stage / 'tailscale'))

    def arm(self):
        wall, mono, boot = self.h.now()
        # Publish pending before anything can be switched. An interrupted arm is recoverable.
        self.write('pending', wallDeadline=wall+self.p['deadlineSeconds'],
                   monotonicDeadline=mono+self.p['deadlineSeconds'], bootID=boot)
        command = ' '.join(self.argv('boot'))  # all components fixed or ID validated
        unit = '[Unit]\nDescription=Unified local boot recovery\nAfter=local-fs.target\nBefore=tailscaled.service\n[Service]\nType=oneshot\nRemainAfterExit=yes\nTimeoutStartSec=180\nExecStart=' + command + '\n'
        self.install(self.h.path('/etc/systemd/system/' + self.boot), unit)
        self.install(self.guard, '[Unit]\nRequires=' + self.boot + '\nAfter=' + self.boot + '\n')
        self.h.run('/usr/bin/systemd-analyze', 'verify', str(self.h.path('/etc/systemd/system/' + self.boot)))
        self.h.ctl('daemon-reload')
        # Starting guard in original boot is harmless; it must NOT rollback until reboot.
        self.h.ctl('start', self.boot)
        self.h.run('/usr/bin/systemd-run', '--unit=' + self.prefix + '-rollback',
                   '--on-active=' + str(self.p['deadlineSeconds']) + 's', '--timer-property=AccuracySec=1s',
                   '--property=Type=oneshot', '--property=TimeoutStartSec=180s', *self.argv('rollback'))
        self.armed_evidence()
        self.write('armed')

    def armed_evidence(self):
        require(self.h.ctl('is-active', self.prefix + '-rollback.timer').strip() == 'active', 'timer not active')
        timer = self.h.ctl('show', self.prefix + '-rollback.timer', '--property=NextElapseUSecMonotonic')
        service = self.h.ctl('show', self.prefix + '-rollback.service', '--property=ExecStart')
        require(str(self.d / 'native.py') in service and 'rollback' in service and
                timer.strip() not in ('', 'NextElapseUSecMonotonic=0'), 'timer readback incomplete')
        require(self.h.ctl('is-active', self.boot).strip() == 'active', 'boot guard not ready')
        self.install(self.d / 'arm-evidence.txt', timer + service)
        plan.atomic(self.d / 'payload-evidence.json', {str(f): {'sha256': plan.digest(f), 'mode': stat.S_IMODE(f.stat().st_mode)}
                   for f in (self.d / 'native.py', self.d / 'plan.py', self.d / 'compatibility.py', self.d / 'schema-v2.json', self.d / 'plan.json',
                             self.h.path('/etc/systemd/system/' + self.boot), self.guard)})

    def switch(self):
        self.valid_deadline()
        self.armed_evidence()
        self.before()
        self.write('queued')
        self.h.run('/usr/bin/systemd-run', '--no-block', '--unit=' + self.prefix + '-switch',
                   '--property=Type=oneshot', '--property=TimeoutStartSec=180s', *self.argv('rehearse-worker' if self.journal().get('rehearsal') else 'switch-worker'))

    def switch_worker(self):
        self.valid_deadline()
        self.armed_evidence()
        self.before()
        self.package_idle()
        require(plan.digest(self.stage / 'tailscaled') == self.journal()['daemonSHA256'] and
                plan.digest(self.stage / 'tailscale') == self.journal()['cliSHA256'] and
                plan.digest(self.stage / 'policy.json') == self.p['configurationSHA256'] and
                plan.digest(self.d / 'candidate.conf') == self.journal()['candidateSHA256'], 'staged file changed')
        self.write('switching')
        self.cli('set', '--auto-update=false', old=True)
        self.h.run('/usr/bin/apt-mark', 'hold', 'tailscale')
        require(json.loads(self.cli('debug', 'prefs', old=True))['AutoUpdate']['Apply'] is False and
                'tailscale' in self.h.run('/usr/bin/apt-mark', 'showhold').splitlines(), 'update lock failed')
        self.h.ctl('stop', UNIT)
        self.snapshot('consistent')
        self.install(self.drop, (self.d / 'candidate.conf').read_bytes())
        self.h.ctl('daemon-reload')
        self.valid_deadline()
        self.h.ctl('start', UNIT)
        self.write('switched')

    def verify(self, old=False):
        self.wait_ready(old=old)
        pid = self.h.ctl('show', UNIT, '--property=MainPID', '--value').strip()
        require(pid.isdigit() and int(pid) > 0, 'missing daemon PID')
        exe = self.h.path('/proc/' + pid + '/exe')
        expected = self.h.path(self.n['daemon']) if old else self.stage / 'tailscaled'
        pinned = self.p['expectedBefore'][self.n['daemon']] if old else self.journal()['daemonSHA256']
        require(plan.digest(exe) == plan.digest(expected) == pinned, 'running executable hash mismatch')
        version = self.cli('version', old=old).strip()
        require(version, 'version missing')
        self.install(self.d / ('version-rollback.txt' if old else 'version-local.txt'), version)
        prefs = json.loads(self.cli('debug', 'prefs', old=old))
        before = plan.read(self.d / 'prefs-before.json')
        # AdvertiseRoutes may gain manual/control routes; verification preserves them.
        for key in ('RunSSH', 'RouteAll', 'ExitNodeID'):
            require(prefs.get(key) == before.get(key), 'prefs drift')
        listeners = self.h.run('/usr/bin/ss', '-H', '-lnup')
        require('pid=' + pid + ',' in listeners, 'daemon listener missing')
        self.install(self.d / ('rollback-local.json' if old else 'local.json'), json.dumps(dict(
            stableID=self.p['stableID'], releaseSHA256=self.p['releaseSHA256'], layer='local-only', passed=True)))
        if not old or self.n.get('previousDeployment'):
            expected_policy = self.p['configurationSHA256'] if not old else plan.digest(self.h.path(str(Path(self.n['daemon']).with_name('policy.json'))))
            end = self.h.now()[1] + READINESS_SECONDS
            while True:
                status = json.loads(self.cli('debug', 'unified-policy', 'status', '--json', old=old))
                ready = (status.get('schemaValid') and status.get('runtimeReady') and status.get('applied') and
                         status.get('source_sha256') == expected_policy and
                         not any(status.get('enabledModules', {'unknown': True}).values()))
                if ready: break
                require(self.h.now()[1] < end, 'local policy not applied all-off')
                if not old: self.valid_deadline()
                self.h.sleep(.25)
            self.install(self.d / ('policy-rollback.json' if old else 'policy-local.json'), json.dumps(status))
            if not old:
                self.valid_deadline()
                self.write('verified')

    def disarm(self):
        if self.h.ctl('show', self.prefix + '-rollback.timer', '--property=LoadState', '--value').strip() != 'not-found':
            self.h.ctl('stop', self.prefix + '-rollback.timer')
        # Retain boot guard and journal until cleanup. Committed boot is a no-op.

    def commit(self):
        require(not self.journal().get('rehearsal'), 'rehearsal cannot commit')
        self.valid_deadline()
        self.verify()  # refresh live local fence/identity immediately before acceptance CAS
        private(self.p['externalEvidence'])
        require(self.acceptance_hash and plan.HEX.fullmatch(self.acceptance_hash), 'fresh acceptance hash required')
        plan.evidence(self.p['externalEvidence'], self.acceptance_hash, self.p, 'external-e2e')
        e = plan.read(self.p['externalEvidence'])
        local = plan.read(self.d / 'policy-local.json')
        require(e.get('generation') == local['acceptedFence']['Generation'], 'external generation mismatch')
        require(e.get('deadlineUnix') == self.journal()['wallDeadline'] and e.get('host') == self.p['host'], 'external deadline/host mismatch')
        self.write('committed')  # fsync before stopping recovery
        self.disarm()

    def reverse(self):
        require(self.journal()['phase'] == 'committed', 'reverse requires committed release')
        pending = self.d / 'policy-intent.json'
        require(not pending.exists() or plan.read(pending)['phase'] == 'complete', 'policy handoff still pending')
        plan.all_off_config(plan.read(self.stage / 'policy.json'))
        status = json.loads(self.cli('debug', 'unified-policy', 'status', '--json'))
        require(status.get('source_sha256') == plan.digest(self.stage / 'policy.json') and status.get('applied') and status.get('runtimeReady') and
                not any(status.get('enabledModules', {'unknown': True}).values()), 'durable all-off required before reverse')
        require(getattr(self, 'reverse_binding', None) == {
                    'configurationSHA256': plan.digest(self.stage / 'policy.json'),
                    'generation': status['acceptedFence']['Generation'],
                    'dropinSHA256': plan.digest(self.drop)}, 'reverse CAS approval mismatch')
        require(plan.digest(self.drop) == self.journal()['candidateSHA256'], 'reverse layout drift')
        self.identity()
        self.snapshot('reverse-before')
        self.arm()  # durable pending, boot guard and independent rollback timer
        self.rollback()

    def restore_updates(self):
        self.cli('set', '--auto-update=' + str(self.p['autoUpdateApply']).lower(), old=True)
        self.h.run('/usr/bin/apt-mark', 'hold' if self.p['aptHeld'] else 'unhold', 'tailscale')
        prefs = json.loads(self.cli('debug', 'prefs', old=True))
        require(prefs['AutoUpdate']['Check'] == self.p['autoUpdateCheck'] and
                prefs['AutoUpdate']['Apply'] == self.p['autoUpdateApply'], 'update restoration failed')
        require(('tailscale' in self.h.run('/usr/bin/apt-mark', 'showhold').splitlines()) == self.p['aptHeld'], 'hold restoration failed')

    def rollback(self, boot=False):
        j = self.journal()
        if j['phase'] in TERMINAL:
            return
        self.write('rolling-back')
        if not boot:
            self.h.ctl('stop', UNIT)
        import compatibility
        compatibility.restore_v1(self)
        # No route/prefs/state rewind: this all-off deployment has no owned route delta.
        # Never replay whole route snapshots. Preserve concurrent manual/control changes.
        if self.n.get('previousDeployment'):
            self.restore_layout_file(self.drop, j.get('candidateSHA256'))
        else:
            for f in (self.drop,):
                if f.exists():
                    require(plan.digest(f) == j.get('candidateSHA256'), 'foreign drop-in edit; OOB required')
                    f.unlink()
                    syncdir(f.parent)
        # Original unit/daemon/config were never overwritten. Refuse concurrent edits.
        for name in [self.n['daemon'], self.n['cli'], self.n['unit'], *self.n['dropins'],
                     *self.p['environmentFiles'], *self.p['backupFiles']['config']]:
            if name == '/etc/systemd/system/tailscaled.service.d/89-unified-recovery.conf':
                continue  # current recovery guard remains armed until terminal cleanup
            expected = self.p['expectedBefore'][name]
            f = self.h.path(name)
            require((not f.exists()) if expected == 'ABSENT' else plan.digest(f) == expected,
                    'original restore target changed; OOB required')
        self.h.ctl('daemon-reload')
        if boot:
            # Never synchronously start a unit ordered after this boot guard.
            self.write('boot-restored')
            self.h.run('/usr/bin/systemd-run', '--no-block', '--unit=' + self.prefix + '-finish',
                       '--property=After=' + self.boot, '--property=Type=oneshot',
                       '--property=TimeoutStartSec=180s', *self.argv('finish'))
            return
        self.finish()

    def finish(self):
        try:
            self.h.ctl('start', UNIT)
        except (ValueError, OSError, subprocess.SubprocessError):
            # A failed start job is eligible for the existing conservative fallback.
            self.retry_original()
        else:
            try:
                self.verify(old=True)
            except ReadinessError as error:
                if error.category != 'service-unavailable':
                    raise
                self.retry_original()
        self.restore_updates()
        self.write('rolled-back', routePolicy='preserved-current-no-owned-delta')
        self.disarm()

    def retry_original(self):
        self.h.ctl('stop', UNIT)
        self.fallback()
        self.h.ctl('start', UNIT)
        self.verify(old=True)

    def fallback(self):
        # Rehearsal is required by preflight. Additionally prove no state write since
        # final backup. If any byte changed, a full rewind could erase a new owner.
        require(not self.journal().get('rehearsal'), 'bootstrap has no prior fallback proof; OOB required')
        require((self.d / 'consistent/manifest.json').exists(), 'no consistent fallback')
        records = plan.read(self.d / 'consistent/manifest.json')
        for name in self.n['stateFiles']:
            require(plan.digest(self.h.path(name)) == records[name]['sha256'],
                    'state changed: refuse destructive fallback; OOB diff required')
        for name in self.n['stateFiles']:
            r = records[name]
            self.install(self.h.path(name), (self.d / 'consistent' / r['file']).read_bytes(), r['mode'])
            os.chown(self.h.path(name), r['uid'], r['gid'])

    def cleanup(self):
        self.disarm()
        # Remove only files with exact generated content; retain all LKG/evidence.
        expected = '[Unit]\nRequires=' + self.boot + '\nAfter=' + self.boot + '\n'
        if self.guard.exists():
            require(self.guard.read_text() == expected, 'foreign guard edit')
            if self.n.get('previousDeployment') and self.journal()['phase'] == 'rolled-back':
                self.restore_layout_file(self.guard, hashlib.sha256(expected.encode()).hexdigest())
            else:
                self.guard.unlink()
                syncdir(self.guard.parent)
        unit = self.h.path('/etc/systemd/system/' + self.boot)
        if unit.exists():
            require(' '.join(self.argv('boot')) in unit.read_text(), 'foreign recovery unit')
            unit.unlink()
            syncdir(unit.parent)
        self.h.ctl('daemon-reload')
        # Dependency must be removed/reloaded BEFORE stopping the recovery unit;
        # stopping it while tailscaled Requires it could stop the daemon too.
        for name in (self.boot, self.prefix + '-switch.service', self.prefix + '-finish.service',
                     self.prefix + '-rollback.service', self.prefix + '-rollback.timer'):
            if self.h.ctl('show', name, '--property=LoadState', '--value').strip() != 'not-found':
                self.h.ctl('stop', name)
                self.h.ctl('reset-failed', name)
        # OOB is external and intentionally never removed automatically.
        self.write(self.journal()['phase'], cleaned=True)

    def rehearse(self, source, approval):
        self.preflight(source, approval, rehearsal=True)
        for action in ('backup', 'stage', 'arm', 'switch'):
            self.dispatch(action)
        # switch queues the installed independent worker; caller exit is not PASS.

    def rehearse_worker(self):
        require(self.journal().get('rehearsal') is True, 'not a rehearsal transaction')
        self.switch_worker()
        self.verify()
        self.write('verified', rollbackReason='operator')
        self.rollback()
        require(self.journal()['phase'] == 'rolled-back', 'rollback incomplete')
        out = self.rehearsal_destination()
        evidence = dict(kind='state-downgrade-rehearsal', passed=True,
                        host=self.p['host'], stableID=self.p['stableID'],
                        releaseSHA256=self.p['releaseSHA256'],
                        oldDaemonSHA256=self.p['expectedBefore'][self.n['daemon']],
                        timestamp=datetime.now(timezone.utc).isoformat(),
                        rehearsalID=self.p['deploymentID'])
        # Publish only complete fsynced bytes, exclusively; never replace old evidence.
        fd, temporary = tempfile.mkstemp(prefix='.rehearsal-', dir=out.parent)
        published = False
        try:
            with os.fdopen(fd, 'w') as f:
                os.fchmod(f.fileno(), 0o600)
                json.dump(evidence, f, sort_keys=True); f.write('\n')
                f.flush(); os.fsync(f.fileno())
            os.link(temporary, out)  # same filesystem, exclusive atomic publication
            published = True
            syncdir(out.parent)
            self.write('rolled-back', rehearsalEvidenceSHA256=plan.digest(out))
        except (ValueError, OSError):
            if published:
                out.unlink()
                syncdir(out.parent)
            raise
        finally:
            os.unlink(temporary)

    def execute(self, action, source=None, approval=None):
        # Caller holds the host lock, including all failure recovery.
        try:
            if action == 'rehearse':
                self.rehearse(source, approval)
            elif action == 'preflight':
                self.preflight(source, approval)
            else:
                require(plan.digest(self.d / 'plan.json') == self.approved, 'installed plan mismatch')
                self.dispatch(action)
        except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError) as error:
            if self.jf.exists():
                self.install(self.d / 'failure.json', json.dumps(dict(action=action, phase=self.journal()['phase'], category=str(error) if type(error) is ValueError else type(error).__name__)))
            if action in ('switch-worker', 'rehearse-worker', 'rehearse', 'switch', 'arm', 'reverse') and self.jf.exists():
                try:
                    self.rollback()
                except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError):
                    self.write('rollback-failed')
            elif action in ('rollback', 'boot', 'finish') and self.journal()['phase'] not in TERMINAL:
                self.write('rollback-failed')
            print('OOB: use independent console; stop tailscaled; retain transaction directory; compare current state/routes with consistent/manifest.json; restore only reviewed differences; start original service and verify StableID. Do not copy old state over new manual/control routes.', file=sys.stderr)
            raise

    def dispatch(self, action):
        phase = self.journal()['phase']
        if self.journal().get('rehearsal'):
            require(action not in ('switch-worker', 'verify', 'commit'), 'rehearsal requires complete worker')
        allowed = {'backup': {'preflight'}, 'stage': {'backup'}, 'arm': {'stage'},
                   'switch': {'armed'}, 'switch-worker': {'queued'}, 'rehearse-worker': {'queued'}, 'verify': {'switched'},
                   'commit': {'verified'}, 'reverse': {'committed'}, 'cleanup': TERMINAL, 'finish': {'boot-restored', 'rolling-back', 'rollback-failed'}}
        if action == 'boot':
            if phase in TERMINAL or self.h.now()[2] == self.journal().get('bootID'):
                return
            return self.rollback(boot=True)
        if action == 'rollback':
            return self.rollback()
        require(phase in allowed.get(action, set()), 'invalid phase transition')
        method = {'stage': self.stage_release, 'switch-worker': self.switch_worker, 'rehearse-worker': self.rehearse_worker}.get(action)
        return (method or getattr(self, action))()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--internal', choices=['boot', 'rollback', 'switch-worker', 'rehearse-worker', 'finish'])
    ap.add_argument('--transaction')
    ap.add_argument('--phase')
    ap.add_argument('--rehearsal', action='store_true')
    ap.add_argument('--plan')
    ap.add_argument('--approval')
    ap.add_argument('--approved')
    ap.add_argument('--acceptance-sha256')
    args = ap.parse_args()
    require(args.rehearsal == (args.phase == 'rehearse') and not (args.internal and args.rehearsal),
            '--rehearsal is required only for rehearse')
    require(sys.platform == 'linux' and os.geteuid() == 0, 'Linux root required')
    os.umask(0o077)
    Path(BASE).mkdir(mode=0o700, parents=True, exist_ok=True)
    for path in (Path(BASE), *Path(BASE).parents):
        st = path.lstat()
        require(not stat.S_ISLNK(st.st_mode) and st.st_uid == 0 and not st.st_mode & 0o022, 'unsafe transaction root')
    require(not (Path(BASE) / 'host.lock').is_symlink(), 'unsafe host lock')
    if args.internal:
        d = Path(args.transaction)
        require(d.parent == Path(BASE) and plan.ID.fullmatch(d.name), 'invalid transaction location')
        private(d / 'plan.json')
        require(Path(__file__).resolve() == d / 'native.py', 'recovery must use installed payload')
        p = plan.load(d / 'plan.json')
        approved = plan.digest(d / 'plan.json')
        require(plan.read(d / 'journal.json')['approved'] == approved, 'recovery plan mismatch')
        action = args.internal
    else:
        require(args.phase and args.plan and args.approval and args.approved, 'approval required')
        p = plan.load(args.plan)
        require(plan.digest(args.plan) == args.approved, 'plan binding mismatch')
        approved, action = args.approved, args.phase
        private(args.approval)
        a = plan.read(args.approval)
        require(a.get('approvedPlanSHA256') == approved and a.get('deploymentID') == p['deploymentID'] and
                a.get('host') == p['host'] and a.get('expiresUnix', 0) > time.time() and
                a.get('serialWindowExclusive') is True, 'approval mismatch')
        if action == 'commit':
            require(a.get('acceptanceSHA256') == args.acceptance_sha256, 'acceptance approval mismatch')
    require('native' in p, 'native contract required')
    t = Transaction(p, approved, acceptance_hash=args.acceptance_sha256)
    if not args.internal:
        t.reverse_binding = a.get('reverse')
    # Boot guard started by arm must return before trying the lock held by arm.
    if action == 'boot' and t.jf.exists() and t.h.now()[2] == t.journal().get('bootID'):
        return
    with t.lock():
        t.execute(action, args.plan, args.approval)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError) as error:
        if isinstance(error, ReadinessError) or type(error) is ValueError:
            print(str(error), file=sys.stderr)
        print('deploy: native operation refused/failed (contents redacted)', file=sys.stderr)
        sys.exit(1)
