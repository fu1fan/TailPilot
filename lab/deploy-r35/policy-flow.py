#!/usr/bin/env python3
"""Actual batch enable/disable/restart/reverse in the isolated R35 VM only."""
from run import *
P=OUT/(os.environ.get('R35_UPGRADE','upgrade')+'-plan.json');p=read(P)
OUT=OUT/(p['deploymentID']+'-flow');OUT.mkdir(exist_ok=True)
D=Path('/var/lib/tailscale-unified-deploy')/p['deploymentID']
cli=Path('/usr/local/lib/tailscale-unified')/p['releaseID']/'tailscale'
policy=cli.with_name('policy.json')

def status():return json.loads(run([cli,'debug','unified-policy','status','--json']))
def ready(wanted):
    end=time.monotonic()+50
    while time.monotonic()<end:
        s=status()
        if s.get('runtimeReady') and bool(s['enabledModules'].get('lease'))==wanted:
            if not wanted and s.get('applied'):return s
            if wanted:
                r=json.loads(run([cli,'debug','appc-route-adopt','--source','r35-readiness']))['clear_preview']
                if r['Fence']==s['acceptedFence'] and r['SourceID']>0:return s
        time.sleep(.5)
    raise RuntimeError('policy not ready')
def snapshot(label):
    s=ready('enabled' in label)
    prefs=json.loads(run([cli,'debug','prefs']))
    ident=json.loads(run([cli,'status','--json']))
    value=dict(stableID=ident['Self']['ID'],routes=sorted(prefs.get('AdvertiseRoutes',[])),
               prefsSHA256=hashlib.sha256(json.dumps(prefs,sort_keys=True).encode()).hexdigest(),
               stateSHA256=digest(p['native']['stateFiles'][0]),policy=s,
               pid=run(['systemctl','show','tailscaled','-p','MainPID','--value']).strip())
    save(OUT/(label+'.json'),value);return value

def approval(batch,action):
    target=OUT/'target.json'
    save(target,dict(machine='idcfast',host=p['host'],stableID=p['stableID'],oobHost='127.0.0.1',releaseSHA256=p['releaseSHA256']))
    proof=dict(deploymentID=p['deploymentID'],host=p['host'],approvedPlanSHA256=digest(P),expiresUnix=int(time.time())+3600,
               serialWindowExclusive=True,excludePeers=p['excludePeers'],excludeDomains=p['excludeDomains'],
               targetSHA256=digest(target),prodActions=[batch+':'+action],oobSHA256=p['oobSHA256'],releaseSHA256=p['releaseSHA256'],
               windowStartUnix=int(time.time())-1,windowEndUnix=int(time.time())+3600)
    args=['python3',ROOT/'deploy/prod/batch.py',batch,'--action',action,'--execute','--target',target,'--plan',P,
          '--plan-sha256',digest(P),'--release-sha256',p['releaseSHA256'],'--oob-sha256',p['oobSHA256']]
    return proof,args

def change(enable,operation,wait_result=True):
    batch,action=('20-takeover','enable') if enable else ('90-rollback','disable')
    config=OUT/(operation+'.json')
    save(config,dict(schema_version=2,machine='idcfast',enabled=enable,app_connector_ttl={'enabled':enable}))
    s=ready(not enable);before=digest(policy)
    proof,args=approval(batch,action)
    proof['policy']=dict(operation=operation,beforeSHA256=before,generation=s['acceptedFence']['Generation'],configurationSHA256=digest(config))
    af=OUT/(operation+'-approval.json');save(af,proof)
    run(args+['--approval',af,'--configuration',config,'--operation',operation,'--expect-sha256',before,
              '--expect-generation',str(s['acceptedFence']['Generation'])])
    if wait_result:
        wait(D/'policy-intent.json','complete');ready(enable)

if __name__=='__main__':
    action=sys.argv[1]
    if action=='cycle':
        before=snapshot('alloff-before')
        change(True,'enable-1');on=snapshot('enabled')
        run(['systemctl','restart','tailscaled']);restarted=snapshot('enabled-restart')
        change(False,'disable-1');off=snapshot('disabled')
        run(['systemctl','restart','tailscaled']);last=snapshot('disabled-restart')
        for value in (on,restarted,off,last):
            assert value['stableID']==before['stableID'] and value['routes']==before['routes'] and value['prefsSHA256']==before['prefsSHA256']
        save(OUT/'policy-cycle-result.json',dict(passed=True,stableID=before['stableID'],routes=before['routes'],scope='real VM batch/systemd; unchanged prefs/routes'))
    elif action=='failure':
        before=snapshot('failure-before')
        unit='unified-'+p['deploymentID']+'-policy'
        for enable,operation in ((True,'enable-recovery2'),(False,'disable-recovery2')):
            before_hash=digest(policy)
            override=Path('/run/systemd/system')/(unit+'.service.d')/'99-r35-failure.conf'
            override.parent.mkdir(parents=True,exist_ok=True)
            injected='[Service]\nExecStart=\nExecStart=/usr/bin/false\n'
            assert not override.exists();override.write_text(injected)
            run(['systemctl','daemon-reload'])
            try:
                change(enable,operation,False)
                deadline=time.monotonic()+10
                while time.monotonic()<deadline:
                    if run(['systemctl','show',unit+'.service','-p','Result','--value']).strip()=='exit-code':break
                    time.sleep(.2)
                else:raise AssertionError('worker failure not observed')
                intent=read(D/'policy-intent.json')
                assert intent['phase']=='pending' and digest(policy)==before_hash
                save(OUT/(operation+'-at-failure.json'),intent)
                run(['systemctl','stop',unit+'.timer'])
                run(['systemctl','restart','tailscaled'])
                ready(not enable)
                assert digest(policy)==before_hash
            finally:
                assert override.read_text()==injected;override.unlink()
                run(['systemctl','daemon-reload'])
            run(['systemctl','start',unit+'.timer'])
            run(['systemctl','start','--no-block',unit+'.service'])
            wait(D/'policy-intent.json','complete');ready(enable)
            after=snapshot(('enabled' if enable else 'disabled')+'-after-failure')
            assert after['stableID']==before['stableID'] and after['routes']==before['routes']
            assert after['prefsSHA256']==before['prefsSHA256']
        save(OUT/'failure-result.json',dict(passed=True,directions=['enable','disable'],kind='real systemd worker exit-code failure, durable pending, daemon restart, automatic timer recovery',
                                         stableID=before['stableID'],routes=before['routes']))
    elif action=='reverse':
        before=snapshot('before-reverse');s=status()
        proof,args=approval('90-rollback','reverse')
        proof['reverse']=dict(configurationSHA256=digest(policy),generation=s['acceptedFence']['Generation'],dropinSHA256=digest('/etc/systemd/system/tailscaled.service.d/90-unified-transaction.conf'))
        af=OUT/'reverse-approval.json';save(af,proof);run(args+['--approval',af])
        assert read(D/'journal.json')['phase']=='rolled-back'
        old=p['native']['cli'];s=json.loads(run([old,'debug','unified-policy','status','--json']))
        assert s['applied'] and s['runtimeReady'] and not any(s['enabledModules'].values())
        ident=json.loads(run([old,'status','--json']));prefs=json.loads(run([old,'debug','prefs']))
        assert ident['Self']['ID']==before['stableID'] and sorted(prefs['AdvertiseRoutes'])==before['routes']
        save(OUT/'reverse-result.json',dict(passed=True,stableID=ident['Self']['ID'],routes=sorted(prefs['AdvertiseRoutes']),policy=s))
