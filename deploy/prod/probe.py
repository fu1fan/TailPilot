# Read-only SSH payload. PARAMS is injected as a Python literal by batch.py.
# No state files, private keys, Environment values, auth tokens or control API.
import hashlib
import json
import platform
from pathlib import Path
import subprocess


def run(*args):
    p = subprocess.run(args, capture_output=True, timeout=10,
                       env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
    if p.returncode:
        raise RuntimeError('probe failed')
    return p.stdout.decode()


def probe(params, command=run):
    cli = [params['cli'], '--socket=' + params['socket']]
    status = json.loads(command(*cli, 'status', '--json'))
    policy = json.loads(command(*cli, 'debug', 'unified-policy', 'status', '--json'))
    # CLI debug prefs returns a redacted prefs view (see prefsPretty in CLI).
    prefs = json.loads(command(*cli, 'debug', 'prefs'))
    def show(key):
        return command('/usr/bin/systemctl', 'show', 'tailscaled.service', '--property=' + key, '--value').strip()
    pid = show('MainPID')
    if not pid.isdigit() or int(pid) <= 0:
        raise RuntimeError('missing PID')
    exe = Path('/proc/' + pid + '/exe')
    digest = hashlib.sha256(exe.read_bytes()).hexdigest()
    modules = policy.get('enabledModules', {})
    required = {'app_connector_ttl', 'auto_ipv6', 'dns_ipv4_only', 'path_policy'}
    off = (policy.get('applied') is True and policy.get('schemaValid') is True and
           policy.get('runtimeReady') is True and set(modules) == required and
           all(value is False for value in modules.values()))
    return dict(host=platform.node(), stableID=status['Self']['ID'], backend=status['BackendState'],
                allOff=off, policySHA256=policy.get('source_sha256'), fence=policy.get('acceptedFence'),
                service=show('ActiveState'), mainPID=int(pid), executableSHA256=digest,
                unit=show('FragmentPath'), dropins=show('DropInPaths').split(),
                prefs={k: prefs.get(k) for k in ('RunSSH', 'RouteAll', 'ExitNodeID', 'AdvertiseRoutes', 'AutoUpdate')},
                advertisedCount=len(prefs.get('AdvertiseRoutes') or []),
                routes4=json.loads(command('/usr/sbin/ip', '-json', 'route', 'show', 'table', 'all')),
                routes6=json.loads(command('/usr/sbin/ip', '-6', '-json', 'route', 'show', 'table', 'all')),
                aptHeld='tailscale' in command('/usr/bin/apt-mark', 'showhold').splitlines(),
                finalReleaseInstalled=(digest == params['daemonSHA256'] or
                    Path('/usr/local/lib/tailscale-unified', params['releaseID']).exists()),
                nativeLayoutSupported=(str(exe.resolve()) == '/usr/sbin/tailscaled' and not show('DropInPaths')))


if __name__ == '__main__':
    try:
        print(json.dumps(probe(PARAMS), sort_keys=True))
    except Exception:
        raise SystemExit('read-only probe failed (contents redacted)')
