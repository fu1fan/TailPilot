#!/usr/bin/env python3
"""R3 scale acceptance: real daemon, 1 vCPU quota, 24xx routes / 63x domains.

Runs in a run-owned systemd private network/mount namespace. Reuses the cli810
helper prefix (root/bin/state/sock/save/command/cli/start/stop/until) and adds a
real-TUN daemon with CPUQuota=100% and MemoryMax=913M, a scale control fixture,
a synthetic upstream DNS server, a SOCKS/PeerAPI DoH load generator and strict
sample-based acceptance.
"""
from pathlib import Path
source = Path(__file__).with_name('cli810.py').read_text()
exec(compile(source.split('\ntry:\n')[0].replace('r27-synthetic-control', 'r3-scale'), 'scale-helpers', 'exec'))
import socket
import struct
import threading
import http.client
import queue
from urllib.parse import urlsplit

# --- reviewed scale profile (residential production shape) -------------------
DOMAINS = int(os.environ.get('R33_SCALE_DOMAINS', '632'))   # + *.example.test = 633
ROUTES = int(os.environ.get('R33_SCALE_ROUTES', '2420'))    # + 198.51.100.0/24 = 2421
SECONDS = int(os.environ.get('R33_SCALE_SECONDS', '900'))
RATE = float(os.environ.get('R33_SCALE_RATE', '6'))         # aggregate queries/sec
WORKERS = int(os.environ.get('R33_SCALE_WORKERS', '4'))
BURST_EVERY = int(os.environ.get('R33_SCALE_BURST_SECONDS', '60'))
BURST_N = int(os.environ.get('R33_SCALE_BURST', '8'))
SAMPLE = 10
TUN = os.environ.get('R33_NATIVE_TUN', 'scale-tun')
ROOTS = ['*.d%d.example.test' % i for i in range(DOMAINS)]
TARGETS = ['*.d%d.example.test' % i for i in range(min(16, DOMAINS))]
NAME_COUNT = int(os.environ.get('R33_SCALE_NAMES', '64'))
NAMES = ['q%d.d%d.example.test' % (i, i % max(1, min(16, DOMAINS))) for i in range(NAME_COUNT)]
SEED_LEASES = int(os.environ.get('R33_SCALE_SEED_LEASES', '124'))
COLD = os.environ.get('R4_COLD', '0') == '1'
unit_props = ('CPUQuota=100%', 'MemoryMax=913M', 'MemorySwapMax=0')


def until(fn, label, timeout=30):
    end = time.monotonic() + timeout
    while True:
        value = fn()
        if value:
            return value
        if time.monotonic() > end:
            raise RuntimeError('timeout: ' + label)
        time.sleep(.25)


class DaemonService:
    serial = 0

    def __init__(self):
        while not http_pool.empty():
            http_pool.get_nowait().close()
        DaemonService.serial += 1
        self.unit = f'r3-scale-daemon-{os.getpid()}-{DaemonService.serial}.service'
        self.returncode = None
        parent = os.environ['R33_PARENT_UNIT']
        argv = ['systemd-run', '--unit=' + self.unit, '--property=Type=exec',
                '--property=PrivateNetwork=yes', '--property=JoinsNamespaceOf=' + parent,
                '--property=BindsTo=' + parent, '--property=PartOf=' + parent,
                '--property=PrivateTmp=yes', '--property=ProtectSystem=strict',
                '--property=ReadWritePaths=' + str(root), '--property=NoNewPrivileges=yes',
                '--property=BindReadOnlyPaths=' + str(root.parent / 'resolv.conf') + ':/etc/resolv.conf',
                '--property=UMask=0077', '--property=RuntimeMaxSec=' + str(SECONDS + 600)]
        for prop in unit_props:
            argv.append('--property=' + prop)
        argv += ['/usr/bin/env', 'TS_UNIFIED_POLICY_FILE=' + str(policy), 'TS_NO_LOGS_NO_SUPPORT=true',
                 'TS_ASSUME_NETWORK_UP_FOR_TEST=true',
                 str(bin / 'tailscaled'), '--tun=' + TUN, '--state=' + str(state),
                 '--socket=' + str(sock), '--port=0', '--statedir=' + str(root / 'daemon')]
        command(argv)
        self.pid = int(subprocess.check_output(['systemctl', 'show', self.unit, '-p', 'MainPID', '--value']))
        assert self.pid > 0
        processes.append(self)
        save(self.unit + '.json', {'unit': self.unit, 'pid': self.pid, 'parent': parent,
                                   'cpu_quota': '100%', 'memory_max': '913M'})
    def poll(self):
        if self.returncode is not None:
            return self.returncode
        data = subprocess.check_output(['systemctl', 'show', self.unit, '-p', 'ActiveState',
                                        '-p', 'ExecMainCode', '-p', 'ExecMainStatus'], text=True)
        props = dict(line.split('=', 1) for line in data.splitlines() if '=' in line)
        if props.get('ActiveState') in ('active', 'activating', 'deactivating'):
            return None
        status = int(props.get('ExecMainStatus', '0'))
        self.returncode = -status if props.get('ExecMainCode') == '2' else status
        save(self.unit + '-exit.json', props)
        return self.returncode
    def terminate(self):
        subprocess.run(['systemctl', 'stop', self.unit], check=True, capture_output=True)
    def wait(self, timeout=10):
        subprocess.run(['systemctl', 'stop', self.unit], capture_output=True)
        return self.poll()
    def archive(self):
        (root / (self.unit + '.log')).write_bytes(
            subprocess.check_output(['journalctl', '-u', self.unit, '--no-pager']))
        subprocess.run(['systemctl', 'stop', self.unit], capture_output=True)
        subprocess.run(['systemctl', 'reset-failed', self.unit], capture_output=True)


class DNSServer:
    """One upstream A/AAAA answer per name; the connector's PeerAPI forwards here."""

    def __init__(self):
        self.sockets = []
        for typ in (socket.SOCK_DGRAM, socket.SOCK_STREAM):
            s = socket.socket(socket.AF_INET, typ)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(('127.0.0.1', 53))
            self.sockets.append(s)
            if typ == socket.SOCK_STREAM:
                s.listen(64)
            threading.Thread(target=self.serve, args=(s, typ), daemon=True).start()
        self.lock = threading.Lock()
        self.count = 0

    def answer(self, q):
        i = 12
        labels = []
        while q[i]:
            n = q[i]
            labels.append(q[i + 1:i + 1 + n].decode())
            i += n + 1
        end = i + 5
        domain = '.'.join(labels)
        qt = struct.unpack('!H', q[i + 1:i + 3])[0]
        h = int(hashlib.sha256(domain.encode()).hexdigest()[:8], 16)
        if qt == 28:
            ip = '2001:db8::%x' % (h % 65535 + 1)
            rdata = socket.inet_pton(socket.AF_INET6, ip)
            suffix = struct.pack('!HHIH', 28, 1, 300, 16)
        elif qt == 1:
            ip = '192.0.2.%d' % (h % 250 + 1)
            rdata = socket.inet_aton(ip)
            suffix = struct.pack('!HHIH', 1, 1, 300, 4)
        else:
            # Scripted upstream: unsupported qtypes get NODATA, never a failure.
            return q[:2] + struct.pack('!HHHHH', 0x8180, 1, 0, 0, 0) + q[12:end]
        response = q[:2] + struct.pack('!HHHHH', 0x8180, 1, 1, 0, 0) + q[12:end] + b'\xc0\x0c' + suffix + rdata
        with self.lock:
            self.count += 1
            if self.count % 500 == 0:
                save('dns-count.json', {'count': self.count, 'time': time.time()})
        return response

    def serve(self, s, typ):
        while True:
            try:
                if typ == socket.SOCK_DGRAM:
                    q, addr = s.recvfrom(65535)
                    s.sendto(self.answer(q), addr)
                else:
                    c, _ = s.accept()
                    with c:
                        c.settimeout(10)
                        size = struct.unpack('!H', recv(c, 2))[0]
                        r = self.answer(recv(c, size))
                        c.sendall(struct.pack('!H', len(r)) + r)
            except socket.timeout:
                continue
            except OSError:
                return
            except Exception as e:
                (root / 'dns-error.txt').write_text(repr(e))
                continue

    def close(self):
        for s in self.sockets:
            s.close()


def recv(s, n):
    b = b''
    while len(b) < n:
        part = s.recv(n - len(b))
        if not part:
            raise RuntimeError('unexpected EOF')
        b += part
    return b


socks_port = None
peerapi_addr = None
dns = None
daemon_svc = None
client_proc = None
http_pool = queue.LifoQueue()
HTTP_REUSE = os.environ.get("R4_HTTP_REUSE", "1") == "1"


def doh(qname, qtype='A', timeout=5.0):
    global peerapi_addr
    if peerapi_addr is None:
        status = running()
        url = next(u for u in status['Self']['PeerAPIURL'] if urlsplit(u).hostname.count('.') == 3)
        peerapi_addr = urlsplit(url)
    addr = peerapi_addr
    t0 = time.perf_counter()
    if HTTP_REUSE:
        try:
            connection = http_pool.get_nowait()
        except queue.Empty:
            connection = http.client.HTTPConnection(addr.hostname, addr.port, timeout=timeout)
            c = socket.create_connection(('127.0.0.1', socks_port), timeout=timeout)
            try:
                c.sendall(b'\x05\x01\x00')
                assert recv(c, 2) == b'\x05\x00'
                c.sendall(b'\x05\x01\x00\x01' + socket.inet_aton(addr.hostname) + struct.pack('!H', addr.port))
                head = recv(c, 4)
                assert head[:2] == b'\x05\x00', head
                recv(c, 4 if head[3] == 1 else 16)
                recv(c, 2)
                connection.sock = c
            except BaseException:
                c.close()
                raise
        try:
            # No retry: any handshake, HTTP or DNS failure remains a gate failure.
            connection.request('GET', f'/dns-query?q={qname}&t={qtype}')
            response = connection.getresponse()
            body = response.read()
            if response.status != 200:
                raise RuntimeError(('doh status', response.status))
            result = json.loads(body)
            if connection.sock is not None:
                http_pool.put(connection)
            return result, time.perf_counter() - t0
        except BaseException:
            connection.close()
            raise
    with socket.create_connection(('127.0.0.1', socks_port), timeout=timeout) as c:
        c.sendall(b'\x05\x01\x00')
        assert recv(c, 2) == b'\x05\x00'
        c.sendall(b'\x05\x01\x00\x01' + socket.inet_aton(addr.hostname) + struct.pack('!H', addr.port))
        head = recv(c, 4)
        assert head[:2] == b'\x05\x00', head
        recv(c, 4 if head[3] == 1 else 16)
        recv(c, 2)
        c.sendall(f'GET /dns-query?q={qname}&t={qtype} HTTP/1.0\r\nHost: {addr.netloc}\r\n\r\n'.encode())
        response = b''
        while True:
            part = c.recv(65536)
            if not part:
                break
            response += part
    head, _, body = response.partition(b'\r\n\r\n')
    dt = time.perf_counter() - t0
    if b'200 OK' not in head.split(b'\r\n')[0]:
        raise RuntimeError(('doh status', head[:80]))
    return json.loads(body), dt


def metric_value(name):
    for line in cli('debug', 'metrics').splitlines():
        fields = line.split()
        if len(fields) == 2 and fields[0] == name:
            return int(fields[1])
    return 0


def metric_snapshot():
    wanted = ('unified_dns_queue_deadline', 'unified_dns_queue_full', 'unified_dns_queue_stale',
              'unified_dns_failure', 'unified_dns_observe_error', 'unified_dns_commit_prewrite_stale',
              'unified_dns_commit_observer_stale', 'unified_dns_commit_storage',
              'unified_dns_commit_ttl_blocked', 'unified_dns_managed',
              'unified_dns_stale_capture_seen', 'unified_dns_stale_capture_retry',
              'unified_dns_stale_capture_final',
              'appc_lease_invalid_question_name', 'appc_lease_invalid_record_name')
    return {name: metric_value(name) for name in wanted}


def policy_apply(config, label):
    save(label + '-policy.json', config)
    (root / 'policy.json').write_text(json.dumps(config))
    desired = hashlib.sha256((root / 'policy.json').read_bytes()).hexdigest()
    end = time.monotonic() + 90
    while True:
        try:
            status = cli('debug', 'unified-policy', 'status', '--json')
            if status.get('source_sha256') == desired:
                break
            cli('debug', 'unified-policy', 'reload',
                '--expect-generation=' + str(status['acceptedFence']['Generation']),
                '--expect-sha256=' + desired)
        except RuntimeError:
            pass
        if time.monotonic() > end:
            raise RuntimeError('policy not applied: ' + label)
        time.sleep(.25)
    return desired


def wait_status(label, want_dns, timeout=180):
    """Wait for the installed consumer, not merely a compiled snapshot."""
    end = time.monotonic() + timeout
    while True:
        status = cli('debug', 'unified-policy', 'status', '--json')
        modules = status.get('enabledModules') or {}
        if (status.get('runtimeReady') and not status.get('degraded')
                and modules.get('lease') and modules.get('root')
                and bool(modules.get('dns_ipv4_only')) == want_dns
                and status.get('consumerFence') == status.get('acceptedFence')
                and status.get('ttlBlocked') is not True):
            save(label + '-status.json', status)
            return status
        if time.monotonic() > end:
            save(label + '-status.json', status)
            raise RuntimeError('scale consumer not ready: ' + label)
        time.sleep(.5)


def wait_leases(minimum, timeout=300):
    end = time.monotonic() + timeout
    while True:
        s = cli('debug', 'unified-policy', 'status', '--json')
        if s.get('leaseCount', 0) >= minimum:
            return s
        if time.monotonic() > end:
            raise RuntimeError('lease seeding timeout: %r' % s.get('leaseCount'))
        time.sleep(.5)


def doh_retry(qname, qtype='A', timeout=45):
    """Pre-load seeding may observe a documented transient fence failure."""
    end = time.monotonic() + timeout
    last = None
    while time.monotonic() < end:
        try:
            body, dt = doh(qname, qtype)
            if isinstance(body, list) and body:
                return body, dt
            last = body
        except Exception as e:
            last = e
        time.sleep(.5)
    raise RuntimeError(('seed query did not converge', qname, last))


def wait_generation_stable(label, seconds=3, timeout=120):
    """Wait for the control/advertisement loop to settle before measurement."""
    end = time.monotonic() + timeout
    last = None
    stable_since = None
    while time.monotonic() < end:
        status = cli('debug', 'unified-policy', 'status', '--json')
        f = status.get('acceptedFence') or {}
        gen = (f.get('Generation'), f.get('AssignedDomainsEpoch'), f.get('PeerIdentityEpoch'))
        ok = (status.get('runtimeReady') and not status.get('degraded')
              and status.get('consumerFence') == status.get('acceptedFence'))
        if ok and gen == last:
            if stable_since is None:
                stable_since = time.monotonic()
            elif time.monotonic() - stable_since >= seconds:
                save(label + '-stable-status.json', status)
                return status
        else:
            stable_since = None
        last = gen
        time.sleep(.5)
    raise RuntimeError('policy generation did not settle: ' + label)


stats_lock = threading.Lock()
stats = {'ok': 0, 'servfail': 0, 'other': 0, 'lat': [], 'errors': {}}


def record_ok(dt):
    with stats_lock:
        stats['ok'] += 1
        stats['lat'].append(dt)


def record_failure(kind, err):
    with stats_lock:
        stats[kind] = stats.get(kind, 0) + 1
        stats['errors'][str(err)[:120]] = stats['errors'].get(str(err)[:120], 0) + 1
        with (root/'client-errors.jsonl').open('a') as f:f.write(json.dumps({'time':time.time(),'kind':kind,'error':repr(err)})+'\n')


def load_worker(wid, stop):
    n = 0
    while not stop.is_set():
        name = ('cold%d-%d.d%d.example.test' % (wid,n,wid % min(16,DOMAINS))) if COLD else NAMES[(wid * 97 + n) % len(NAMES)]
        n += 1
        try:
            body, dt = doh(name, 'A')
            if isinstance(body, list) and body:
                record_ok(dt)
            elif isinstance(body, dict) and 'RCodeServerFailure' in str(body.get('Error', '')):
                record_failure('servfail', body)
            else:
                record_failure('other', body)
        except Exception as e:  # socket/proxy/DNS failure
            record_failure('exception', e)
        time.sleep(max(0.0, (WORKERS / RATE) - 0.001))


sampler_stop = threading.Event()
samples = []


def sampler():
    start = metric_snapshot()
    baseline = start
    while not sampler_stop.is_set():
        row = {'t': time.time()}
        try:
            status = cli('debug', 'unified-policy', 'status', '--json')
            fence = status.get('acceptedFence') or {}
            row.update({'runtimeReady': status.get('runtimeReady'), 'degraded': status.get('degraded'),
                        'leaseCount': status.get('leaseCount'), 'untp': status.get('timeUncertain'),
                        'consumerReady': status.get('consumerFence') == status.get('acceptedFence'),
                        'ttlBlocked': status.get('ttlBlocked'),
                        'degradedCause': status.get('degradedCause'),
                        'generation': fence.get('Generation'), 'identity': fence.get('PeerIdentityEpoch'),
                        'currentRevision': status.get('currentRevision'),
                        'publishedRevision': status.get('publishedRevision')})
            row['metrics'] = metric_snapshot()
        except Exception as e:
            row['sample_error'] = repr(e)
        with stats_lock:
            row['client_stats']={k:v for k,v in stats.items() if k!='lat'}
        samples.append(row)
        save('scale-samples.json', {'baseline': baseline, 'samples': samples})
        if sampler_stop.wait(SAMPLE):
            return


try:
    assert DOMAINS >= 0 and ROUTES >= 0 and SECONDS >= 60
    assert os.readlink('/proc/self/ns/net') != os.readlink('/proc/1/ns/net')
    assert Path('/etc/resolv.conf').read_text() == 'nameserver 127.0.0.1\n'
    save('scope.json', {'netns': os.readlink('/proc/self/ns/net'), 'mountns': os.readlink('/proc/self/ns/mnt'),
                        'profile': {'domains_total': DOMAINS + 1, 'routes_total': ROUTES + 1,
                                    'seconds': SECONDS, 'rate': RATE, 'workers': WORKERS,
                                    'burst_every': BURST_EVERY, 'burst_n': BURST_N},
                        'unit_props': list(unit_props), 'http_connection_reuse': HTTP_REUSE})
    phase='startup'
    dns = DNSServer()
    save('policy.json', {'schema_version': 2, 'enabled': False})
    ctl = start([str(bin / 'control'), '--bind=127.0.0.1', '--appc-fixture',
                 '--appc-domains', str(DOMAINS), '--appc-routes', str(ROUTES),
                 '--dns-resolver=127.0.0.1:53'], 'control.log', stdout=subprocess.PIPE)
    assert select.select([ctl.stdout], [], [], 20)[0]
    info = json.loads(ctl.stdout.readline())
    save('control.json', info)
    daemon_svc = DaemonService()
    until(lambda: sock.exists(), 'daemon socket', 30)
    cli('up', '--login-server=' + info['controlURL'], '--accept-dns=false',
        '--advertise-connector', '--hostname=r3-scale-connector', '--timeout=40s')
    running()
    # Capture encrypted-overlay plaintext only in this synthetic private lab.
    start([str(bin / 'tailscale'), '--socket=' + str(sock), 'debug', 'capture',
           '-o', str(root / 'transport.pcap')], 'capture.log')
    # A second real daemon on the same test tailnet supplies the loopback SOCKS
    # client used to reach the connector's PeerAPI DoH endpoint.
    client_dir = root / 'client'
    client_dir.mkdir()
    client_sock = client_dir / 'tailscaled.sock'
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        socks_port = probe.getsockname()[1]
    client_binary = os.environ.get('R4_CLIENT_DAEMON',str(bin / 'tailscaled'))
    save('client-binary.json',{'path':client_binary,'sha256':hashlib.sha256(Path(client_binary).read_bytes()).hexdigest()})
    client_proc = start([client_binary, '--tun=userspace-networking',
                         '--state=' + str(client_dir / 'state.json'), '--socket=' + str(client_sock),
                         '--port=0', '--statedir=' + str(client_dir),
                         '--socks5-server=127.0.0.1:' + str(socks_port)], 'client.log',
                        dict(os.environ, TS_NO_LOGS_NO_SUPPORT='true', TS_ASSUME_NETWORK_UP_FOR_TEST='true'))
    until(lambda: client_sock.exists(), 'client socket', 30)
    command([str(bin / 'tailscale'), '--socket=' + str(client_sock), 'up',
             '--login-server=' + info['controlURL'], '--accept-dns=false',
             '--hostname=r3-scale-client', '--timeout=40s'])
    time.sleep(2)
    phase='ttl-scale-enable'
    # A TTL-only policy install must absorb the full 2421 control routes and 633
    # assigned roots before DNS is enabled.
    ttl = {'schema_version': 2, 'enabled': True, 'app_connector_ttl': {'enabled': True,'sweep_seconds':5}}
    sha_ttl = policy_apply(ttl, 'ttl-only')
    st = wait_status('ttl-only', False, timeout=300)
    plan_raw = cli('debug', 'appc-route-reset', '--source', 'r3-scale-probe')
    plan = plan_raw.get('clear_preview') if isinstance(plan_raw, dict) else None
    assert plan and len(plan.get('Roots') or []) >= DOMAINS and len(plan.get('Control') or []) >= ROUTES, \
        ('scale assignment missing', len(plan.get('Roots') or []), len(plan.get('Control') or []))
    save('ttl-scale.json', {'roots': len(plan['Roots']), 'control': len(plan['Control']),
                            'source_sha256': st.get('source_sha256')})

    if os.environ.get('R4_RESET') == '1':
        phase='reset-restart-regression'
        old_name='cleared.d0.example.test'
        doh_retry(old_name)
        wait_leases(1)
        old_ip='192.0.2.%d/32' % (int(hashlib.sha256(old_name.encode()).hexdigest()[:8],16)%250+1)
        policy_apply({'schema_version':2,'enabled':True,'dns_ipv4_only':{'enabled':True,'targets':TARGETS}},'reset-dns-only')
        until(lambda: cli('debug','unified-policy','status','--json').get('runtimeReady'), 'handoff ready', 90)
        cli('set','--advertise-routes=10.44.0.0/16','--advertise-exit-node=true')
        daemon_svc.terminate()
        daemon_svc.archive()
        daemon_svc=DaemonService()
        running()
        peerapi_addr=None
        policy_apply(ttl,'reset-reenable')
        wait_status('reset-reenable',False)
        # A returned lease must survive abrupt process death as well.
        fresh_name='fresh.d0.example.test'
        fresh_ip='192.0.2.%d/32' % (int(hashlib.sha256(fresh_name.encode()).hexdigest()[:8],16)%250+1)
        doh_retry(fresh_name)
        command(['systemctl','kill','--signal=SIGKILL',daemon_svc.unit])
        daemon_svc.archive()
        daemon_svc=DaemonService()
        running()
        wait_status('reset-second-restart',False)
        prefs=cli('debug','prefs')
        routes=prefs.get('AdvertiseRoutes') or []
        assert old_ip not in routes, ('cleared route returned',old_ip)
        assert fresh_ip in routes, ('acknowledged lease lost after SIGKILL',fresh_ip)
        assert {'0.0.0.0/0','::/0','10.44.0.0/16'} <= set(routes), routes
        peerapi_addr=None
        body,latency=doh('after-restart.d0.example.test')
        assert isinstance(body,list) and body,body
        # A genuine query may relearn the old address. It must become a normal
        # expiring lease, including after another DNS transaction is committed.
        doh(old_name)
        force_name='force-commit.d0.example.test'
        while ('192.0.2.%d/32' % (int(hashlib.sha256(force_name.encode()).hexdigest()[:8],16)%250+1)) == old_ip:
            force_name='x'+force_name
        doh(force_name)
        journals=[json.loads(base64.b64decode(value))['Payload'] for key,value in json.loads(state.read_text()).items() if key.endswith('||_appConnectorTTLV2')]
        assert len(journals)==1
        owner=journals[0]['Ledger']['Owners'][old_ip]
        assert owner.get('Auto',{}).get('appc-ttl') and not owner.get('LegacyUnknown'), owner
        save('reset-restart-evidence.json',{'old_route':old_ip,'surviving_lease':fresh_ip,'routes_before_relearning':routes,'restarts':2,'new_query_seconds':latency,'relearned_owner':owner,'next_commit_protection_absent':True})
        gates['off_clear_two_process_restarts']='PASS'
        save('result.json',{'result':'PASS','gates':gates})
        raise SystemExit(0)

    # Seed a residential-like lease count (124 at failure time) through the real
    # PeerAPI path before measuring. Seed every load name first so the measured
    # window sees a stable route set (no first-learned route churn).
    phase='seed-leases'
    seed_names = list(NAMES) + ['seed%d.d%d.example.test' % (i, i % len(TARGETS))
                                for i in range(max(0, SEED_LEASES - len(NAMES)))]
    for name in seed_names[:SEED_LEASES]:
        doh_retry(name, 'A')
    seeded = wait_leases(min(SEED_LEASES, len(NAMES))) if SEED_LEASES else cli('debug', 'unified-policy', 'status')
    save('seeded.json', {'requested': SEED_LEASES, 'leaseCount': seeded.get('leaseCount')})

    phase='dns4-enable'
    dns4 = {'schema_version': 2, 'enabled': True, 'app_connector_ttl': {'enabled': True,'sweep_seconds':5},
            'dns_ipv4_only': {'enabled': True, 'targets': TARGETS,'local_route_wait_ms':2000}}
    sha_dns4 = policy_apply(dns4, 'dns4')
    wait_status('dns4', True, timeout=180)
    wait_generation_stable('dns4', seconds=5, timeout=180)

    # Match production's explicit clock confirmation; without this the lease
    # collector deliberately freezes forever, regardless of elapsed DNS TTL.
    time_status=cli('debug','unified-policy','status','--json')
    payload=json.dumps({'confirm_time':True,'source':'r4-isolated-lab-clock',
        'expect_generation':time_status['acceptedFence']['Generation'],
        'expect_sha256':time_status['source_sha256']})
    command(['curl','-fsS','--unix-socket',str(sock),'-X','POST','-H','Content-Type: application/json',
             '--data',payload,'http://local-tailscaled.sock/localapi/v0/debug?action=unified-time-confirm'])
    until(lambda: cli('debug','unified-policy','status','--json').get('timeUncertain') is False,'clock confirmed')

    if os.environ.get('R6_DUALSTACK') == '1':
        phase='dualstack-filtered-answer-durable-routes'
        from concurrent.futures import ThreadPoolExecutor
        names=['dualstack%d.d0.example.test' % i for i in range(32)]
        def ipv6_route(name):
            h=int(hashlib.sha256(name.encode()).hexdigest()[:8],16)
            return '2001:db8::%x/128' % (h%65535+1)
        def query6(name):
            body,latency=doh(name,'AAAA')
            assert body is None or body==[], ('IPv6 leaked',name,body)
            return latency
        with ThreadPoolExecutor(max_workers=32) as pool:
            latencies=list(pool.map(query6,names))
        expected={ipv6_route(name) for name in names}
        routes=set(cli('debug','prefs').get('AdvertiseRoutes') or [])
        assert expected <= routes, ('missing IPv6 routes',expected-routes)
        command(['systemctl','kill','--signal=SIGKILL',daemon_svc.unit])
        daemon_svc.archive()
        daemon_svc=DaemonService()
        running()
        wait_status('dualstack-restart',True)
        peerapi_addr=None
        routes=set(cli('debug','prefs').get('AdvertiseRoutes') or [])
        assert expected <= routes, ('IPv6 routes lost on restart',expected-routes)
        journals=[json.loads(base64.b64decode(value))['Payload'] for key,value in json.loads(state.read_text()).items() if key.endswith('||_appConnectorTTLV2')]
        assert len(journals)==1
        for prefix in expected:
            owner=journals[0]['Ledger']['Owners'][prefix]
            assert owner.get('Auto',{}).get('appc-ttl') and not owner.get('LegacyUnknown'),owner
        query6('after-restart-v6.d0.example.test')
        save('dualstack-evidence.json',{'queries':len(names),'concurrency':32,'filtered_answers':True,'ipv6_routes':sorted(expected),'durable_ttl_owners':True,'survived_SIGKILL':True,'max_latency_seconds':max(latencies)})
        gates['dualstack_filter_and_durable_routes']='PASS'
        save('result.json',{'result':'PASS','gates':gates})
        raise SystemExit(0)

    phase='load-15min'
    # Load window: steady aggregate rate plus periodic cache-miss bursts.
    sampler_stop.clear()
    baseline = metric_snapshot()
    st = threading.Thread(target=sampler, daemon=True)
    st.start()
    load_stop = threading.Event()
    threads = [threading.Thread(target=load_worker, args=(i, load_stop), daemon=True) for i in range(WORKERS)]
    for th in threads:
        th.start()
    started = time.monotonic()
    last_burst = started
    while time.monotonic() - started < SECONDS:
        time.sleep(1)
        if time.monotonic() - last_burst >= BURST_EVERY:
            last_burst = time.monotonic()
            # Purpose-built one-shot burst: each thread exits after one query.
            def one(wid, ev):
                name = ('burst%d-%d.d%d.example.test' % (int(last_burst*1000),wid,wid % min(16,DOMAINS))) if COLD else NAMES[(wid * 31) % len(NAMES)]
                if COLD and wid % 4 == 0:
                    name='burstshared%d.d0.example.test' % int(last_burst*1000)
                try:
                    body, dt = doh(name, 'A')
                    if isinstance(body, list) and body:
                        record_ok(dt)
                    elif isinstance(body, dict) and 'RCodeServerFailure' in str(body.get('Error', '')):
                        record_failure('servfail', body)
                    else:
                        record_failure('other', body)
                except Exception as e:
                    record_failure('burst_exception', e)
            burst = [threading.Thread(target=one, args=(i, threading.Event()), daemon=True) for i in range(BURST_N)]
            for th in burst:
                th.start()
            for th in burst:
                th.join(timeout=10)
    load_stop.set()
    for th in threads:
        th.join(timeout=10)
    sampler_stop.set()
    st.join(timeout=15)
    end_metrics = metric_snapshot()
    end_status = cli('debug', 'unified-policy', 'status', '--json')
    save('scale-end-status.json', end_status)

    def delta(k):
        return end_metrics[k] - baseline.get(k, 0)

    degraded = [r for r in samples if r.get('sample_error') or r.get('degraded')
                or r.get('runtimeReady') is False or r.get('untp') is not False]
    with stats_lock:
        ok, servfail, other = stats['ok'], stats['servfail'], stats['other']
        exceptions = stats.get('exception',0) + stats.get('burst_exception',0)
        lat = sorted(stats['lat'])
        errors = dict(stats['errors'])
    n = max(1, len(lat))
    p50 = lat[int(n * .50) - 1] if lat else 0
    p95 = lat[int(n * .95) - 1] if lat else 0
    p99 = lat[int(n * .99) - 1] if lat else 0
    lease_series = [r.get('leaseCount') for r in samples if isinstance(r.get('leaseCount'), int)]
    lease_min = min(lease_series) if lease_series else 0
    lease_max = max(lease_series) if lease_series else 0
    acceptance = {
        'queue_deadline_delta': delta('unified_dns_queue_deadline'),
        'queue_full_delta': delta('unified_dns_queue_full'),
        'queue_stale_delta': delta('unified_dns_queue_stale'),
        'failure_delta': delta('unified_dns_failure'),
        'observe_error_delta': delta('unified_dns_observe_error'),
        'prewrite_stale_delta': delta('unified_dns_commit_prewrite_stale'),
        'storage_delta': delta('unified_dns_commit_storage'),
        'invalid_question_delta': delta('appc_lease_invalid_question_name'),
        'stale_capture_seen_delta': delta('unified_dns_stale_capture_seen'),
        'stale_capture_retry_delta': delta('unified_dns_stale_capture_retry'),
        'stale_capture_final_delta': delta('unified_dns_stale_capture_final'),
        'client_ok': ok, 'client_servfail': servfail, 'client_other': other, 'client_exceptions': exceptions,
        'latency_p50': p50, 'latency_p95': p95, 'latency_p99': p99,
        'samples': len(samples), 'degraded_samples': len(degraded),
        'degraded_ratio': (len(degraded) / len(samples)) if samples else 1.0,
        'lease_min': lease_min, 'lease_max': lease_max,
        'end_leaseCount': end_status.get('leaseCount'),
    }
    lease_stable = ((COLD or lease_min > 0) and acceptance['end_leaseCount'] >= max(1, int(lease_max * 0.9)))
    acceptance['lease_stable'] = lease_stable
    passed = (acceptance['queue_deadline_delta'] == 0 and acceptance['queue_full_delta'] == 0
              and acceptance['failure_delta'] == 0 and acceptance['client_servfail'] == 0
              and acceptance['client_other'] == 0 and exceptions == 0
              and acceptance['degraded_ratio'] <= 0.001 and len(samples) >= 60
              and lease_stable)
    save('scale-acceptance.json', acceptance)
    gates['scale_15min_1vcpu'] = 'PASS' if passed else 'FAIL'
    save('result.json', {'result': 'PASS' if passed else 'FAIL', 'gates': gates,
                         'acceptance': acceptance, 'errors': errors,
                         'scope': 'real Linux daemon in private netns; CPUQuota=100% MemoryMax=913M; '
                                  'one vCPU worth; synthetic control/DNS fixture; not production'})
    if not passed:
        raise RuntimeError(('scale acceptance failed', acceptance))
except Exception as e:
    save('failure.json' if (root/'result.json').exists() else 'result.json', {'result': 'FAIL' if 'gates' in globals() else 'BLOCKED',
                         'phase': globals().get('phase', 'startup'), 'gates': globals().get('gates', {}),
                         'error': repr(e)})
    raise
finally:
    for proc in reversed(processes):
        stop(proc)
        if isinstance(proc, DaemonService):
            proc.archive()
    if dns is not None:
        dns.close()
    for log in logs:
        log.close()
    commands.close()
