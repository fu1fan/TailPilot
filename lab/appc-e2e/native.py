#!/usr/bin/env python3
"""R33 real daemon gates in a run-owned systemd network/mount namespace.
Reuse CLI810's recording/CAS helpers, without executing its synthetic seeder.
"""
from pathlib import Path
source = Path(__file__).with_name('cli810.py').read_text()
exec(compile(source.split('\ntry:\n')[0].replace('r27-synthetic-control', 'r33-real-dns'), 'cli810-helpers', 'exec'))
import socket
import struct
import threading
from urllib.parse import urlsplit

retained = {'203.0.113.0/24', '198.51.100.0/24', '0.0.0.0/0', '::/0'}
learned = '192.0.2.77/32'
name = 'real.example.test'
dns4_name = 'dns4.example.test'
apex_name = 'example.test'
invalid_name = '_dmarc.dns4.example.test'
barrier = root/'barrier'
barrier.mkdir()
original_daemon = daemon
instrumented = False
tun_name = os.environ.get('R33_NATIVE_TUN', 'r33tun')

class DaemonService:
    serial=0
    def __init__(self):
        DaemonService.serial+=1
        self.unit=f'r33-daemon-{os.getpid()}-{DaemonService.serial}.service'
        self.returncode=None
        parent=os.environ['R33_PARENT_UNIT']
        argv=['systemd-run','--unit='+self.unit,'--property=Type=exec',
              '--property=PrivateNetwork=yes','--property=JoinsNamespaceOf='+parent,
              '--property=BindsTo='+parent,'--property=PartOf='+parent,
              '--property=PrivateTmp=yes','--property=ProtectSystem=strict',
              '--property=ReadWritePaths='+str(root),'--property=NoNewPrivileges=yes',
              '--property=BindReadOnlyPaths='+str(root.parent/'resolv.conf')+':/etc/resolv.conf',
              '--property=UMask=0077','--property=RuntimeMaxSec=1800',
              '/usr/bin/env','TS_UNIFIED_POLICY_FILE='+str(policy),'TS_NO_LOGS_NO_SUPPORT=true',
              'TS_ASSUME_NETWORK_UP_FOR_TEST=true','R33_BARRIER_DIR='+str(barrier),
              str(bin/('tailscaled-barrier' if instrumented else 'tailscaled')),
              '--tun='+tun_name,'--state='+str(state),'--socket='+str(sock),
              '--port=0','--statedir='+str(root/'daemon')]
        command(argv)
        self.pid=int(subprocess.check_output(['systemctl','show',self.unit,'-p','MainPID','--value']))
        assert self.pid>0
        save(self.unit+'.json',{'unit':self.unit,'pid':self.pid,'parent':parent,'binary':argv[-6]})
        processes.append(self)
    def poll(self):
        if self.returncode is not None: return self.returncode
        data=subprocess.check_output(['systemctl','show',self.unit,'-p','ActiveState','-p','ExecMainCode','-p','ExecMainStatus'],text=True)
        props=dict(line.split('=',1) for line in data.splitlines() if '=' in line)
        if props.get('ActiveState') in ('active','activating','deactivating'): return None
        status=int(props.get('ExecMainStatus','0'))
        self.returncode=-status if props.get('ExecMainCode')=='2' else status
        save(self.unit+'-exit.json',props)
        return self.returncode
    def terminate(self): subprocess.run(['systemctl','stop',self.unit],check=True,capture_output=True)
    def kill(self): subprocess.run(['systemctl','kill','--kill-whom=main','--signal=SIGKILL',self.unit],check=True,capture_output=True)
    def wait(self,timeout=10):
        until(lambda: self.poll() is not None,'service exit',timeout)
        return self.returncode
    def restart(self):
        old=self.pid
        command(['systemctl','restart',self.unit])
        self.pid=int(subprocess.check_output(['systemctl','show',self.unit,'-p','MainPID','--value']))
        assert self.pid>0 and self.pid!=old
        save(self.unit+'-restart.json',{'old_pid':old,'new_pid':self.pid})
    def archive(self):
        (root/(self.unit+'.log')).write_bytes(subprocess.check_output(['journalctl','-u',self.unit,'--no-pager']))
        subprocess.run(['systemctl','stop',self.unit],capture_output=True)
        subprocess.run(['systemctl','reset-failed',self.unit],capture_output=True)

def daemon(): return DaemonService()

def wait_socket(s, proc):
    for _ in range(200):
        if s.exists(): return
        assert proc.poll() is None, 'daemon exited'
        time.sleep(.1)
    raise RuntimeError('socket timeout')

def until(fn, label, timeout=30):
    end = time.monotonic()+timeout
    while True:
        value = fn()
        if value: return value
        if time.monotonic()>end: raise RuntimeError('timeout: '+label)
        time.sleep(.25)

def routes(): return set(cli('debug','prefs').get('AdvertiseRoutes') or [])

def kernel_snapshot(label, status=None):
    if tun_name=='userspace-networking': return
    status=status or running()
    addresses=command(['ip','-j','addr','show','dev',tun_name])
    kernel_routes=command(['ip','-j','route','show','table','all'])
    save(label+'-kernel.json',{'addresses':addresses,'routes':kernel_routes})
    local={a['local'] for link in addresses for a in link.get('addr_info',[])}
    assert set(status['TailscaleIPs'])<=local,(status['TailscaleIPs'],local)
    assert any(r.get('dev')==tun_name for r in kernel_routes),'no native TUN routes'
    return kernel_routes

def journal():
    store = json.loads(state.read_bytes())
    selected = cli('debug','unified-policy','status','--json')['acceptedFence']['ProfileID']
    raw = base64.b64decode(store['profile-'+selected+'||_appConnectorTTLV2']).decode()
    env = json.loads(raw)
    pos = raw.index(':',raw.index('"Payload"'))+1
    pos += len(raw[pos:])-len(raw[pos:].lstrip())
    data,end = json.JSONDecoder().raw_decode(raw[pos:])
    assert list(hashlib.sha256(raw[pos:pos+end].encode()).digest()) == env['SHA256'], 'journal checksum'
    return data

def policy_enabled(enabled, root_enabled=None):
    save('policy.json', {'schema_version':2, 'enabled':enabled if root_enabled is None else root_enabled,
                        'app_connector_ttl':{'enabled':enabled}})
    desired = hashlib.sha256(policy.read_bytes()).hexdigest()
    reviewed = until(lambda: cli('debug','unified-policy','preview','--json'), 'policy preview')
    assert reviewed['requested_sha256'] == desired, reviewed
    # The lifecycle worker also reloads the file on its own timer. A CLI reload
    # can therefore lose the CAS race; that is not a failure. Poll the actual
    # live source/readiness instead of interpreting a CAS rejection as success.
    end = time.monotonic()+20
    status = None
    while True:
        status = cli('debug','unified-policy','status','--json')
        if (status.get('source_sha256') == desired and status.get('runtimeReady')
                and not status.get('degraded')):
            break
        try:
            cli('debug','unified-policy','reload',
                '--expect-generation='+str(status['acceptedFence']['Generation']),
                '--expect-sha256='+desired)
        except RuntimeError:
            pass
        if time.monotonic() > end:
            raise RuntimeError('policy not applied: '+desired)
        time.sleep(.25)
    result = {'accepted': True, 'acceptedGeneration': status['acceptedFence']['Generation']}
    if enabled: takeover_ready('native-enabled')
    else:
        until(lambda: not cli('debug','unified-policy','status','--json')['enabledModules']['lease'], 'disabled')
    return result

class DNSServer:
    def __init__(self):
        self.sockets=[]
        for typ in (socket.SOCK_DGRAM, socket.SOCK_STREAM):
            s=socket.socket(socket.AF_INET,typ); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
            s.bind(('127.0.0.1',53)); self.sockets.append(s)
            if typ==socket.SOCK_STREAM: s.listen(10)
            threading.Thread(target=self.serve,args=(s,typ),daemon=True).start()
        self.lock=threading.Lock(); self.count=0
    def answer(self,q):
        i=12; labels=[]
        while q[i]:
            n=q[i]; labels.append(q[i+1:i+1+n].decode()); i+=n+1
        end=i+5; domain='.'.join(labels); qt=struct.unpack('!H',q[i+1:i+3])[0]
        addresses={(name,1):'192.0.2.77',(name,28):'2001:db8::77',
                   (dns4_name,1):'192.0.2.88',(dns4_name,28):'2001:db8::88',
                   (apex_name,1):'192.0.2.99',(apex_name,28):'2001:db8::99'}
        txts={(invalid_name,16):'v=DMARC1'}
        assert (domain,qt) in addresses or (domain,qt) in txts, (domain,qt)
        if (domain,qt) in txts:
            value=txts[(domain,qt)]; raw=value.encode()
            rdata=bytes([len(raw)])+raw; rtype_suffix=struct.pack('!HHIH',16,1,3600,len(rdata))
        else:
            ip=addresses[(domain,qt)]; value=ip
            if qt==28:
                rdata=socket.inet_pton(socket.AF_INET6,ip); rtype_suffix=struct.pack('!HHIH',28,1,3600,16)
            else:
                rdata=socket.inet_aton(ip); rtype_suffix=struct.pack('!HHIH',1,1,3600,4)
        response=q[:2]+struct.pack('!HHHHH',0x8180,1,1,0,0)+q[12:end]+b'\xc0\x0c'+rtype_suffix+rdata
        with self.lock:
            self.count+=1
            save(f'dns-{self.count:03d}.json', {'domain':domain,'qtype':qt,'value':value,
                 'query_hex':q.hex(),'response_hex':response.hex(),'time':time.time()})
        return response
    def serve(self,s,typ):
        while True:
            try:
                if typ==socket.SOCK_DGRAM:
                    q,addr=s.recvfrom(65535); s.sendto(self.answer(q),addr)
                else:
                    c,_=s.accept()
                    with c:
                        c.settimeout(10); size=struct.unpack('!H',recv(c,2))[0]
                        response=self.answer(recv(c,size)); c.sendall(struct.pack('!H',len(response))+response)
            except OSError: return
            except Exception as e:
                (root/'dns-error.txt').write_text(repr(e)); return
    def close(self):
        for s in self.sockets: s.close()

def recv(s,n):
    b=b''
    while len(b)<n:
        part=s.recv(n-len(b))
        if not part: raise RuntimeError('unexpected EOF')
        b+=part
    return b

def query(timeout=60):
    # Path/proxy after a write-point recovery is not instant: the client's SOCKS
    # connect or PeerAPI DoH can fail transiently while the tunnel converges.
    # Retry the whole observation; every acceptance remains exact.
    end=time.monotonic()+timeout; last=None
    while time.monotonic()<end:
        try:
            return _query_once()
        except (AssertionError, OSError) as e:
            last=e; time.sleep(.5)
    raise last

def _query_once():
    # TCP HTTP-over-WireGuard from a second real daemon via its loopback SOCKS5.
    status=running(); url=next(u for u in status['Self']['PeerAPIURL'] if urlsplit(u).hostname.count('.')==3)
    addr=urlsplit(url)
    before=dns.count
    with socket.create_connection(('127.0.0.1',socks_port),timeout=15) as c:
        c.sendall(b'\x05\x01\x00'); assert recv(c,2)==b'\x05\x00'
        c.sendall(b'\x05\x01\x00\x01'+socket.inet_aton(addr.hostname)+struct.pack('!H',addr.port))
        head=recv(c,4); assert head[:2]==b'\x05\x00',head
        recv(c,4 if head[3]==1 else 16); recv(c,2)
        c.sendall(f'GET /dns-query?q={name}&t=A HTTP/1.0\r\nHost: {addr.netloc}\r\n\r\n'.encode())
        response=b''
        while True:
            part=c.recv(65536)
            if not part: break
            response+=part
    (root/f'doh-{dns.count:03d}.txt').write_bytes(response)
    assert b'200 OK' in response.split(b'\r\n')[0], response
    assert dns.count>before, 'no real upstream DNS packet'
    until(lambda: learned in routes(), 'DNS route learned')
    return response

def doh(qname, qtype):
    """PeerAPI DoH GET in pretty mode returns a JSON list of answer IPs.

    A non-success RCode (including a managed SERVFAIL) is returned as an
    {"Error": ...} object so the gate can distinguish filtering from failure.
    """
    status=running(); url=next(u for u in status['Self']['PeerAPIURL'] if urlsplit(u).hostname.count('.')==3)
    addr=urlsplit(url)
    with socket.create_connection(('127.0.0.1',socks_port),timeout=15) as c:
        c.sendall(b'\x05\x01\x00'); assert recv(c,2)==b'\x05\x00'
        c.sendall(b'\x05\x01\x00\x01'+socket.inet_aton(addr.hostname)+struct.pack('!H',addr.port))
        head=recv(c,4); assert head[:2]==b'\x05\x00',head
        recv(c,4 if head[3]==1 else 16); recv(c,2)
        c.sendall(f'GET /dns-query?q={qname}&t={qtype} HTTP/1.0\r\nHost: {addr.netloc}\r\n\r\n'.encode())
        response=b''
        while True:
            part=c.recv(65536)
            if not part: break
            response+=part
    head,_,body=response.partition(b'\r\n\r\n')
    assert b'200 OK' in head.split(b'\r\n')[0], head
    save(f'doh-{qname}-{qtype}-{dns.count:03d}.txt', {'head':head.decode(errors='replace'),'body':body.decode(errors='replace')})
    return json.loads(body)

def doh_expect(qname, qtype, expected, label, timeout=15):
    """Retry a managed DoH query until it matches expected.

    A transient managed SERVFAIL during consumer-fence reconciliation is a
    documented, classified boundary: the old request must fail while the new
    fence installs. The gate must not treat that as a transform bug, but a
    failure that persists past the timeout is a real failure.
    """
    end=time.monotonic()+timeout; last=None; attempts=0
    while time.monotonic()<end:
        attempts+=1
        last=doh(qname,qtype)
        if last==expected:
            return {'attempts':attempts,'value':last}
        time.sleep(.25)
    raise AssertionError((label,'persistent mismatch',last,attempts))

def wait_routes(want, label, key=None, timeout=30):
    """Wait for the profile/route projection to converge after a switch.

    BackendState Running is published before the new profile's prefs/journal
    projection completes; a bare route assertion races that window. This is an
    observation wait, not a relaxed acceptance: the exact set must appear.
    """
    end=time.monotonic()+timeout; last=None
    while time.monotonic()<end:
        last=routes()
        if last==want and (key is None or running()['Self']['PublicKey']==key):
            return last
        time.sleep(.25)
    raise RuntimeError((label,sorted(last),sorted(want)))

def metric_value(name):
    for line in cli('debug','metrics').splitlines():
        fields=line.split()
        if len(fields)==2 and fields[0]==name:
            return int(fields[1])
    return 0

def policy_write(config, label):
    save(label+'-policy.json', config)
    (root/'policy.json').write_text(json.dumps(config))
    desired = hashlib.sha256((root/'policy.json').read_bytes()).hexdigest()
    reviewed = until(lambda: cli('debug','unified-policy','preview','--json'), label+' preview')
    assert reviewed['requested_sha256'] == desired, reviewed
    status = cli('debug','unified-policy','status','--json')
    try:
        return cli('debug','unified-policy','reload',
                   '--expect-generation='+str(status['acceptedFence']['Generation']),
                   '--expect-sha256='+desired)
    except RuntimeError:
        # The in-daemon file watcher may have won the CAS race; wait_policy
        # verifies the live state instead of treating this as success/failure.
        return {'accepted': False, 'deferred': 'watcher-or-cas' }

def wait_policy(config_sha, modules, label, timeout=45):
    deadline=time.monotonic()+timeout
    while time.monotonic()<deadline:
        status=cli('debug','unified-policy','status','--json')
        if (status.get('source_sha256')==config_sha and status.get('runtimeReady')
                and not status.get('degraded') and status.get('enabledModules')==modules
                and status.get('consumerFence')==status.get('acceptedFence')
                and status.get('ttlBlocked') is not True):
            save(label+'-status.json', status)
            return status
        time.sleep(.25)
    save(label+'-status.json', status)
    raise RuntimeError('policy not ready: '+label)

def reset():
    plan=settled_preview('appc-route-reset'); save('latest-reset-plan.json',plan)
    assert set(plan['Withdraw'] or [])=={learned},plan
    assert retained<=set(plan['Retain'])
    result=execute('appc-route-reset',plan); assert result['accepted'],result
    until(lambda: routes()==retained,'reset exact routes')

try:
    assert os.readlink('/proc/self/ns/net')!=os.readlink('/proc/1/ns/net')
    assert Path('/etc/resolv.conf').read_text()=='nameserver 127.0.0.1\n'
    save('isolation.json',{'netns':os.readlink('/proc/self/ns/net'),'host_netns':os.readlink('/proc/1/ns/net'),
                           'mountns':os.readlink('/proc/self/ns/mnt'),'resolv':Path('/etc/resolv.conf').read_text()})
    save('binaries.json',{n:hashlib.sha256((bin/n).read_bytes()).hexdigest() for n in ('tailscale','tailscaled','tailscaled-barrier','control')})
    dns=DNSServer()
    save('policy.json',{'schema_version':2,'enabled':False})
    c=start([str(bin/'control'),'--bind=127.0.0.1','--appc-fixture','--dns-resolver=127.0.0.1:53'],'control.log',stdout=subprocess.PIPE)
    assert select.select([c.stdout],[],[],10)[0]
    info=json.loads(c.stdout.readline()); save('control.json',info)
    d=daemon(); wait_socket(sock,d)
    cli('up','--login-server='+info['controlURL'],'--accept-dns=false','--advertise-connector','--hostname=r33-connector','--timeout=20s')
    before=running(); save('initial-identity.json',before)
    kernel_snapshot('initial',before)
    cli('set','--advertise-routes=203.0.113.0/24','--advertise-exit-node=true')
    client=root/'client'; client.mkdir(); client_sock=client/'tailscaled.sock'
    with socket.socket() as s: s.bind(('127.0.0.1',0)); socks_port=s.getsockname()[1]
    cp=start([str(bin/'tailscaled'),'--tun=userspace-networking','--state='+str(client/'state.json'),
              '--socket='+str(client_sock),'--port=0','--statedir='+str(client),
              '--socks5-server=127.0.0.1:'+str(socks_port)],'client.log',
             dict(os.environ,TS_NO_LOGS_NO_SUPPORT='true',TS_ASSUME_NETWORK_UP_FOR_TEST='true'))
    wait_socket(client_sock,cp)
    command([str(bin/'tailscale'),'--socket='+str(client_sock),'up','--login-server='+info['controlURL'],'--accept-dns=false','--hostname=r33-client','--timeout=20s'])
    time.sleep(3)
    save('assigned-netmap.json',cli('debug','netmap'))
    save('listeners.json',command(['ss','-lntup']))
    phase='legacy-real-DNS'
    query(); snapshot('legacy-dns')
    phase='adopt-real-DNS'
    enable_takeover()
    claim=[{'AssignedRoot':'*.example.test','Domain':name,'IP':'192.0.2.77'}]
    save('real-claims.json',claim)
    args=['--claims='+str(root/'real-claims.json')]
    plan=settled_preview('appc-route-adopt',*args); save('real-adopt-plan.json',plan)
    assert any(e['Eligible'] and e['Prefix']==learned for e in plan['Entries']),plan
    assert execute('appc-route-adopt',plan,*args)['accepted']
    snapshot('real-adopted')
    reset(); snapshot('real-reset')
    query(); settled_preview('appc-route-reset')
    until(lambda: journal()['Complete'],'DNS journal complete')
    snapshot('real-relearned')
    gates['real_DNS_relearn']='PASS'

    phase='focused-dns4'
    if os.environ.get('R33_FOCUS')=='dns4':
        # Focused verification mode for the DNS fix: the full profile/OS matrix
        # and the 12 write-point SIGKILL matrix are recorded as NOT_RUN here and
        # validated separately; every DNS gate below is exact.
        gates['native_OS_profile']='NOT_RUN_FOCUSED_MODE'
        gates['actual_daemon_six_cut']='NOT_RUN_FOCUSED_MODE'
        save('focus.json',{'mode':'dns4','skipped':['native_OS_profile','actual_daemon_six_cut']})
    else:
        phase='native-profile-OS'
        expected=retained|{learned}
        first_profile=cli('debug','unified-policy','status','--json')['acceptedFence']['ProfileID']
        first_key=running()['Self']['PublicKey']
        policy_enabled(False)
        until(lambda: journal().get('Handoff'),'handoff journal')
        assert routes()==expected
        snapshot('disabled-handoff'); kernel_snapshot('disabled-handoff')
        stop(d); assert d.poll()==0, d.returncode
        d=daemon(); running(); assert routes()==expected
        assert running()['Self']['PublicKey']==first_key
        policy_enabled(True); assert routes()==expected
        policy_enabled(False,root_enabled=True)
        until(lambda: journal().get('Handoff'),'TTL-only handoff')
        assert routes()==expected
        snapshot('ttl-only-disabled-handoff')
        policy_enabled(True); assert routes()==expected
        cli('down'); until(lambda: cli('status','--json')['BackendState']=='Stopped','down')
        cli('up'); running(); takeover_ready('after-up'); wait_routes(expected,'after-up')
        # Different loopback control URL creates a genuine second saved profile.
        c2=start([str(bin/'control'),'--bind=127.0.0.1','--appc-fixture','--dns-resolver=127.0.0.1:53'],'control2.log',stdout=subprocess.PIPE)
        assert select.select([c2.stdout],[],[],10)[0]
        info2=json.loads(c2.stdout.readline()); save('control2.json',info2)
        cli('login','--login-server='+info2['controlURL'],'--accept-dns=false','--advertise-connector','--hostname=r33-second','--timeout=20s')
        running(); takeover_ready('profile-two')
        second_profile=cli('debug','unified-policy','status','--json')['acceptedFence']['ProfileID']
        assert first_profile!=second_profile
        second_key=running()['Self']['PublicKey']; assert second_key!=first_key
        kernel_snapshot('profile-two')
        until(lambda: learned not in routes() and '203.0.113.0/24' not in routes(),'profile-two-empty')
        cli('switch',first_profile); running(); takeover_ready('return-profile-one')
        wait_routes(expected,'return-profile-one',key=first_key)
        policy_enabled(False)
        cli('switch',second_profile); running()
        until(lambda: learned not in routes() and '203.0.113.0/24' not in routes(),'profile-two-disabled')
        cli('switch',first_profile); running()
        wait_routes(expected,'profile-one-disabled',key=first_key)
        policy_enabled(True)
        d.restart(); running(); takeover_ready('profile-restart')
        wait_routes(expected,'profile-restart',key=first_key)
        kernel_snapshot('profile-restored')
        save('profile-matrix.json',{'first':first_profile,'second':second_profile,'first_key':first_key,'second_key':second_key,'routes':sorted(routes()),'cases':['all-off/handoff','graceful-stop/start','enable','ttl-only-off/handoff/on','down/up','enabled-profile-one/two/one','disabled-profile-one/two/one','systemctl-restart']})
        gates['native_OS_profile']='PASS'

        phase='actual-daemon-six-cut'
        stop(d); instrumented=True
        d=daemon(); running(); takeover_ready('barrier-binary-ready')
        # Handoff deliberately restores legacy ambiguity. Review and explicitly
        # adopt the actual persisted DNS provenance again before destructive tests.
        plan=settled_preview('appc-route-adopt',*args)
        save('post-handoff-adopt-plan.json',plan)
        assert any(e['Eligible'] and e['Prefix']==learned for e in (plan['Entries'] or [])),plan
        assert execute('appc-route-adopt',plan,*args)['accepted']
        query()
        cuts=[]
        suffixes=['||_appConnectorTTLV2','||_unifiedLeasesV1','||_routeInfo','||_unifiedRouteLedgerV1','profile-'+first_profile,'||_appConnectorTTLV2']
        for number in range(1,7):
            for after in (False,True):
                phase=f'write-{number}-after-{after}'
                case=root/phase; case.mkdir()
                plan=settled_preview('appc-route-reset'); assert set(plan['Withdraw'] or [])=={learned},plan
                save(phase+'/plan.json',plan)
                for file in ('trace.jsonl','reached.json'): (barrier/file).unlink(missing_ok=True)
                (barrier/'arm.json').write_text(json.dumps({'Cut':number,'After':after}))
                argv=[str(bin/'tailscale'),'--socket='+str(sock),'debug','appc-route-reset','--source=r33-real-dns','--execute',
                      '--expect-sha256='+plan['SnapshotHash'],'--expect-generation='+str(plan['Fence']['Generation']),
                      '--expect-source-id='+str(plan['SourceID'])]
                proc=start(argv,phase+'-cli.log')
                until(lambda: (barrier/'reached.json').exists(),'barrier '+phase)
                reached=json.loads((barrier/'reached.json').read_text())
                assert reached['pid']==d.pid and reached['write']==number and reached['after']==after,reached
                assert reached['key'].endswith(suffixes[number-1]),reached
                shutil.copyfile(state,case/'at-barrier.state')
                raw=base64.b64decode(json.loads(state.read_bytes())['profile-'+first_profile+'||_appConnectorTTLV2']).decode()
                env=json.loads(raw); pos=raw.index(':',raw.index('"Payload"'))+1
                pos+=len(raw[pos:])-len(raw[pos:].lstrip())
                at,end=json.JSONDecoder().raw_decode(raw[pos:])
                assert list(hashlib.sha256(raw[pos:pos+end].encode()).digest())==env['SHA256']
                assert at['Complete']==((number==1 and not after) or (number==6 and after)), (phase,at['Complete'])
                save(phase+'/at-barrier-journal.json',at)
                stop(d,kill=True); assert d.returncode==-9
                stop(proc)
                for file in ('trace.jsonl','reached.json'): shutil.copyfile(barrier/file,case/file)
                d=daemon(); recovered=running(); takeover_ready('recovery-'+phase)
                want=expected if number==1 and not after else retained
                assert routes()==want,(phase,routes(),want)
                assert recovered['Self']['PublicKey']==first_key
                kernel_snapshot(phase+'/recovered',recovered)
                j=journal(); assert j['Complete'] and not j['Handoff'],j
                save(phase+'/recovered-journal.json',j); snapshot(phase+'/recovered')
                save(phase+'/result.json',{'result':'PASS','SIGKILL':True,'identity':first_key,'routes':sorted(routes()),'complete':j['Complete']})
                cuts.append({'write':number,'after':after,'result':'PASS','key':reached['key']})
                query()
        save('six-cut.json',cuts); gates['actual_daemon_six_cut']='PASS'

    phase='dns-ipv4-only'
    # Baseline: TTL-only policy above; the target name resolves AAAA through the
    # real DNSServer upstream before the IPv4-only transform is enabled.
    baseline_aaaa=doh_expect(dns4_name,'AAAA',['2001:db8::88'],'dns4-baseline-aaaa')
    dns4=dict(schema_version=2,enabled=True,app_connector_ttl={'enabled':True},
              dns_ipv4_only={'enabled':True,'targets':['*.example.test']})
    result=policy_write(dns4,'dns4-enable')
    sha=hashlib.sha256((root/'policy.json').read_bytes()).hexdigest()
    wait_policy(sha,{'root':True,'lease':True,'auto_ipv6':False,'dns_ipv4_only':True,'path_policy':False},'dns4-enable')
    a=doh_expect(dns4_name,'A',['192.0.2.88'],'dns4-transform-a')
    # A filtered AAAA is RCodeSuccess with no answers; pretty JSON encodes the
    # empty []string as null.
    aaaa=doh_expect(dns4_name,'AAAA',None,'dns4-transform-aaaa')
    # The apex is not matched by ''*.example.test'' (wildcards exclude the apex),
    # so it keeps both families: only explicit targets change.
    other_aaaa=doh_expect(apex_name,'AAAA',['2001:db8::99'],'dns4-nontarget-aaaa')
    gates['dns_ipv4_only_transform']='PASS'
    save('dns4-transform.json',{'a':a,'aaaa':aaaa,'aaaa_encoding':'pretty-mode null means NODATA','non_target_aaaa':other_aaaa,'source_sha256':sha})

    phase='dns-invalid-name'
    # A _dmarc-style QNAME under an assigned root is a legitimate client query
    # but not a policy-managed name (service labels are outside the LDH A-label
    # grammar). Before the R2b fix, ParseLeaseDNS rejected the question name and
    # processUnifiedDNS converted that into a managed SERVFAIL.
    before_invalid=metric_value('appc_lease_invalid_question_name')
    before_failure=metric_value('unified_dns_failure')
    txt=doh_expect(invalid_name,'TXT',['v=DMARC1'],'dns-invalid-name-txt')
    after_invalid=metric_value('appc_lease_invalid_question_name')
    after_failure=metric_value('unified_dns_failure')
    assert after_invalid>before_invalid,(before_invalid,after_invalid)
    assert after_failure==before_failure,(before_failure,after_failure)
    doh_expect(dns4_name,'A',['192.0.2.88'],'dns-invalid-name-valid-a')
    status=cli('debug','unified-policy','status','--json')
    assert not status['degraded'] and status['runtimeReady'],status
    save('dns-invalid-name.json',{'txt':txt,'invalid_name_metric_before':before_invalid,
         'invalid_name_metric_after':after_invalid,'failure_before':before_failure,
         'failure_after':after_failure})
    gates['dns_invalid_name_unmanaged']='PASS'

    phase='dns-fence-churn'
    churn=[]
    for i in range(6):
        # Each reload publishes a new generation; toggling an unrelated knob
        # guarantees a distinct file hash without changing DNS semantics.
        c=dict(dns4); c['reload_seconds']=2 if i%2==0 else 3
        policy_write(c,f'churn-{i}')
        sha_churn=hashlib.sha256((root/'policy.json').read_bytes()).hexdigest()
        wait_policy(sha_churn,{'root':True,'lease':True,'auto_ipv6':False,'dns_ipv4_only':True,'path_policy':False},f'churn-{i}')
        sent=0; transient=0; ok=0
        for _ in range(6):
            sent+=1
            r=doh(dns4_name,'A')
            if r==['192.0.2.88']: ok+=1
            elif isinstance(r,dict) and 'Error' in r: transient+=1
            else: raise RuntimeError(('unexpected DNS answer',r))
        assert ok>=5,(i,ok,transient)
        churn.append({'iteration':i,'sent':sent,'ok':ok,'transient':transient})
    status=cli('debug','unified-policy','status','--json')
    assert not status['degraded'] and status['runtimeReady'],status
    assert status.get('consumerFence')==status.get('acceptedFence'),status
    assert status.get('ttlBlocked') is not True,status
    save('dns-fence-churn.json',churn)
    gates['dns_fence_churn_recovery']='PASS'

    phase='restart-time-confirm'
    d.restart(); running()
    sha_restart=hashlib.sha256((root/'policy.json').read_bytes()).hexdigest()
    after=wait_policy(sha_restart,{'root':True,'lease':True,'auto_ipv6':False,'dns_ipv4_only':True,'path_policy':False},'dns4-restart')
    a2=doh_expect(dns4_name,'A',['192.0.2.88'],'dns4-restart-a')
    aaaa2=doh_expect(dns4_name,'AAAA',None,'dns4-restart-aaaa')
    uncertainty=after.get('timeUncertain')
    save('dns4-restart-uncertainty.json',{'timeUncertain':uncertainty,
         'note':'lab restarts do not jump wall time; production must use the documented LocalAPI unified-time-confirm when timeUncertain is true'})
    gates['dns_restart_readback']='PASS'

    save('result.json',{'result':'PASS','gates':gates,'dns_packets':dns.count,
         'tun':tun_name,'scope':'actual Linux daemon systemd units, private network, native TUN address/routes; no external forwarding or production control plane proof'})
except Exception as e:
    save('result.json',{'result':'PARTIAL' if gates else 'BLOCKED','phase':phase,'gates':gates,'error':repr(e)})
    raise
finally:
    for proc in reversed(processes):
        stop(proc)
        if isinstance(proc,DaemonService): proc.archive()
    if 'dns' in globals(): dns.close()
    for log in logs: log.close()
    commands.close()
