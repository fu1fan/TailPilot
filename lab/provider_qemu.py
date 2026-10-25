#!/usr/bin/env python3
"""QEMU/VDE provider. Default is argv-only, without probes or writes.

User systemd units, userspace Ethernet and slirp: no host routes/firewall/tap.
Images and per-role cloud-init seed ISOs must be prepared by Lead offline.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time

ROLES = ['R', 'I', 'C1', 'C2', 'relay', 'derp900', 'derp901', 'authoritative-dns', 'dns-cache']


def check(ok, why):
    if not ok:
        raise ValueError(why)


def save(path, obj):
    fd, tmp = tempfile.mkstemp(dir=path.parent)
    with os.fdopen(fd, 'w') as f:
        os.fchmod(f.fileno(), 0o600)
        json.dump(obj, f, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def run(*argv):
    r = subprocess.run(argv, capture_output=True, text=True, timeout=60)
    check(r.returncode == 0, 'provider command failed; retain inventory for retry')
    return r.stdout


def topology(run_id, root, images, port):
    data = root / 'data.vde'
    resources = []
    def resource(role, argv, files):
        name = run_id + '-' + role
        resources.append(dict(role=role, name=name, created=False, intent=False, files=files,
            command=['systemd-run', '--user', '--unit=' + name, '--property=Type=exec',
                     '--property=Description=' + name, '--property=KillMode=control-group', '--', *argv]))
    resource('data', ['vde_switch', '--sock', str(data), '--mod', '700'], [])
    for i, role in enumerate(ROLES):
        overlay = root / (role + '.qcow2')
        resource(role, ['qemu-system-x86_64', '-enable-kvm', '-m', '1024', '-smp', '1',
            '-name', run_id + '-' + role, '-display', 'none', '-monitor', 'none', '-serial', 'none',
            '-drive', 'file=' + str(overlay) + ',format=qcow2,if=virtio',
            '-drive', 'file=' + images[role]['seed'] + ',format=raw,media=cdrom,readonly=on',
            '-netdev', 'user,id=management,restrict=on,hostfwd=tcp:127.0.0.1:' + str(port+i) + '-:22',
            '-device', 'virtio-net-pci,netdev=management,mac=52:54:00:11:00:' + format(i+1,'02x'),
            '-netdev', 'vde,id=data,sock=' + str(data),
            '-device', 'virtio-net-pci,netdev=data,mac=52:54:00:22:00:' + format(i+1,'02x')],
            [str(overlay)])
        resources[-1]['prepare'] = ['qemu-img', 'create', '-f', 'qcow2', '-F', 'qcow2', '-b',
                                    images[role]['image'], str(overlay)]
    return dict(schema=1, provider='qemu-vde', runID=run_id, root=str(root), resources=resources,
                mode='dry-run', result='NOT_RUN', management='per-VM restricted slirp, loopback hostfwd; no data faults here')


def validate_images(images, execute):
    check(set(images) == set(ROLES), 'all nine role images/seeds required')
    for role, entry in images.items():
        check(set(entry) == {'image', 'imageSHA256', 'seed', 'seedSHA256'}, 'image fields')
        for field in ('image', 'seed'):
            p = Path(entry[field])
            check(p.is_absolute() and '..' not in p.parts and re.fullmatch(r'/[A-Za-z0-9_./-]+', str(p)), 'unsafe image path')
            check(re.fullmatch('[a-f0-9]{64}', entry[field+'SHA256']), 'image/seed digest required')
            if execute:
                check(not p.is_symlink() and p.is_file(), 'missing image/seed')
                h = hashlib.sha256()
                with p.open('rb') as f:
                    for b in iter(lambda: f.read(1024*1024), b''):
                        h.update(b)
                check(h.hexdigest() == entry[field+'SHA256'], 'image/seed digest mismatch')


def main():
    p = argparse.ArgumentParser()
    p.add_argument('action', choices=['create','destroy'])
    p.add_argument('--run-id', required=True)
    p.add_argument('--root', required=True)
    p.add_argument('--images', required=True)
    p.add_argument('--management-port', type=int, default=24000)
    mode = p.add_mutually_exclusive_group()
    mode.add_argument('--dry-run', action='store_true')
    mode.add_argument('--execute', action='store_true')
    a = p.parse_args()
    check(re.fullmatch(r'lab-[0-9a-f]{32}', a.run_id), 'invalid runID')
    root = Path(a.root)
    check(root.is_absolute() and root.name == a.run_id and '..' not in root.parts and
          re.fullmatch(r'/[A-Za-z0-9_./-]+', str(root)), 'root must end in exact runID')
    check(1024 <= a.management_port <= 65526, 'invalid management port range')
    images = json.loads(Path(a.images).read_text())
    validate_images(images, a.execute and a.action == 'create')
    spec = topology(a.run_id, root, images, a.management_port)
    inv = root / 'inventory.json'
    if a.action == 'destroy':
        current = json.loads(inv.read_text())
        # Never execute commands loaded from inventory. Reconstruct and compare scope.
        check(current['runID'] == a.run_id and current['root'] == str(root) and
              len(current['resources']) == len(spec['resources']), 'foreign inventory')
        for saved, expected in zip(current['resources'], spec['resources']):
            check(all(saved[k] == expected[k] for k in ('name','role','command','files')), 'inventory changed')
        spec = current
    if not a.execute:
        if a.action == 'destroy':
            spec = dict(mode='dry-run', result='NOT_RUN', runID=a.run_id,
                        reverseDeletionPlan=[r for r in reversed(spec['resources']) if r['created'] or r['intent']])
        print(json.dumps(spec, indent=2))
        return
    check(sys.platform == 'linux' and os.geteuid() != 0, 'execute as dedicated non-root Linux lab user')
    if a.action == 'create':
        root.mkdir(mode=0o700)  # exclusive, never adopt an existing scope
    check(not root.is_symlink() and root.stat().st_uid == os.geteuid() and root.stat().st_mode & 0o077 == 0, 'private owned scope required')
    with open(root/'provider.lock', 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if a.action == 'create':
            save(inv, spec)
            for r in spec['resources']:
                check(run('systemctl','--user','show',r['name']+'.service','--property=LoadState','--value').strip() == 'not-found', 'unit collision')
                r['intent'] = True
                save(inv, spec)
                if 'prepare' in r:
                    run(*r['prepare'])
                run(*r['command'])
                if r['role'] == 'data':
                    deadline = time.monotonic() + 10
                    while not (root / 'data.vde' / 'ctl').is_socket():
                        check(time.monotonic() < deadline, 'VDE socket not ready')
                        time.sleep(0.1)
                check(run('systemctl', '--user', 'is-active', r['name']+'.service').strip() == 'active', 'provider unit inactive')
                r['created'] = True
                save(inv, spec)
            spec['mode'] = 'executed'
            spec['result'] = 'CREATED_NOT_TESTED'
            save(inv, spec)
        else:
            for r in reversed(spec['resources']):
                if not (r['created'] or r['intent']):
                    continue
                unit = r['name']+'.service'
                loaded = run('systemctl','--user','show',unit,'--property=LoadState','--value').strip()
                if loaded != 'not-found':
                    check(run('systemctl','--user','show',unit,'--property=Description','--value').strip() == r['name'], 'unit ownership mismatch')
                    run('systemctl','--user','stop',unit)
                for name in r['files']:
                    file = Path(name)
                    check(file.parent == root and not file.is_symlink(), 'foreign file')
                    file.unlink(missing_ok=True)
                r.update(created=False, intent=False)
                save(inv, spec)
            # Inventory, seeds (external), logs and run directory are retained.
            spec['result'] = 'DESTROYED_EVIDENCE_RETAINED'
            save(inv, spec)
    print(json.dumps(dict(runID=a.run_id, result=spec['result'])))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError):
        print('lab provider: invalid input or operation failed; inspect private inventory', file=sys.stderr)
        sys.exit(1)
