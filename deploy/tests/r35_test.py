#!/usr/bin/env python3
"""R35 failure/CAS regression coverage; fake commands, not native acceptance."""
import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import native
import plan
import policy
import native_test as nt


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.fixture=nt.NativeTests(); self.fixture.setUp(); self.addCleanup(self.fixture.doCleanups)
        self.fixture.ready_fixture(); self.t=self.fixture.t
        self.t.install(self.t.drop, (self.t.d/'candidate.conf').read_bytes())
        self.t.h.ctl('start', native.UNIT)
        self.t.write('committed')
        self.before=plan.digest(self.t.stage/'policy.json')
        self.candidate=self.t.d/'enable.json'
        plan.atomic(self.candidate,dict(schema_version=2,machine='idcfast',enabled=True,app_connector_ttl={'enabled':True}))
        self.desired=plan.digest(self.candidate)
        self.proof=dict(operation='enable-1',beforeSHA256=self.before,generation=4,configurationSHA256=self.desired)
        self.consumer=patch.object(policy,'consumer_ready',return_value=True);self.consumer.start();self.addCleanup(self.consumer.stop)
        self.private=patch.object(native,'private');self.private.start();self.addCleanup(self.private.stop)
        self.statuspatch=patch.object(policy,'status',side_effect=self.status);self.statuspatch.start();self.addCleanup(self.statuspatch.stop)
    def status(self,t):
        h=plan.digest(t.stage/'policy.json');on=h==self.desired
        return dict(schemaValid=True,runtimeReady=True,applied=True,source_sha256=h,
                    acceptedFence=dict(Generation=5 if on else 4,ProfileID='p',AssignedDomainsEpoch=1,PeerIdentityEpoch=1),
                    enabledModules=dict(root=on,lease=on))
    def start(self):policy.start(self.t,self.candidate,'enable-1',self.before,4,self.proof)
    def test_durable_rollforward_preserves_state_and_prefs(self):
        state=self.t.h.path(self.t.n['stateFiles'][0]); before=state.read_bytes()
        self.start()
        self.assertEqual(plan.digest(self.t.stage/'policy.json'),self.before)
        policy.recover(self.t)
        self.assertEqual(plan.read(self.t.d/'policy-intent.json')['phase'],'complete')
        self.assertEqual(plan.digest(self.t.stage/'policy.json'),self.desired)
        self.assertEqual(state.read_bytes(),before)
        policy.recover(self.t)
    def test_restart_after_file_publication_finishes(self):
        self.start();self.t.install(self.t.stage/'policy.json',self.candidate.read_bytes())
        self.t.h.boot='boot-b';policy.recover(self.t)
        self.assertEqual(plan.read(self.t.d/'policy-intent.json')['phase'],'complete')
    def test_failure_leaves_intent_for_retry(self):
        self.start()
        with patch.object(self.t,'install',side_effect=OSError('cut')):
            with self.assertRaises(OSError):policy.recover(self.t)
        self.assertEqual(plan.read(self.t.d/'policy-intent.json')['phase'],'pending')
        policy.recover(self.t)
    def test_foreign_file_is_not_overwritten(self):
        self.start();self.t.install(self.t.stage/'policy.json',b'foreign')
        with self.assertRaisesRegex(ValueError,'foreign policy'):policy.recover(self.t)
        self.assertEqual((self.t.stage/'policy.json').read_bytes(),b'foreign')
    def test_candidate_tamper_refused(self):
        self.start();(self.t.d/'policy-enable-1/candidate.json').write_text('{}')
        with self.assertRaisesRegex(ValueError,'candidate drift'):policy.recover(self.t)
    def test_bad_approval_or_cas_has_no_intent(self):
        for field in ('generation','configurationSHA256','beforeSHA256'):
            proof=dict(self.proof);proof[field]='bad'
            with self.assertRaises(ValueError):policy.start(self.t,self.candidate,'enable-1',self.before,4,proof)
        with self.assertRaises(ValueError):policy.start(self.t,self.candidate,'enable-1',self.before,3,self.proof)
        self.assertFalse((self.t.d/'policy-intent.json').exists())
    def test_pending_operation_cannot_be_replaced(self):
        self.start()
        proof=dict(self.proof,operation='enable-2')
        with self.assertRaisesRegex(ValueError,'pending'):policy.start(self.t,self.candidate,'enable-2',self.before,4,proof)
    def test_superseded_release_refused(self):
        self.t.drop.write_text('new release')
        with self.assertRaisesRegex(ValueError,'no longer installed'):self.start()
    def test_profile_change_refused(self):
        self.start()
        s=self.status(self.t);s['acceptedFence']['ProfileID']='other'
        with patch.object(policy,'status',return_value=s):
            with self.assertRaisesRegex(ValueError,'profile changed'):policy.recover(self.t)
    def test_disable_pending_survives_daemon_restart_with_ttl_applied_false(self):
        plan.atomic(self.t.stage/'policy.json',dict(schema_version=2,machine='idcfast',enabled=True,app_connector_ttl={'enabled':True}))
        self.before=plan.digest(self.t.stage/'policy.json')
        plan.atomic(self.candidate,dict(schema_version=2,machine='idcfast',enabled=False))
        self.desired=plan.digest(self.candidate)
        self.proof.update(beforeSHA256=self.before,configurationSHA256=self.desired)
        def ttl_status(t):
            h=plan.digest(t.stage/'policy.json');on=h==self.before
            return dict(schemaValid=True,runtimeReady=True,applied=not on,source_sha256=h,
                        acceptedFence=dict(Generation=4,ProfileID='p',AssignedDomainsEpoch=1,PeerIdentityEpoch=1),
                        enabledModules=dict(root=on,lease=on))
        with patch.object(policy,'status',side_effect=ttl_status):
            self.start();self.t.h.boot='new-boot';policy.recover(self.t)
        self.assertEqual(plan.read(self.t.d/'policy-intent.json')['phase'],'complete')

    def test_ttl_uses_consumer_fence_not_broad_applied_bit(self):
        self.consumer.stop()
        s=self.status(self.t);s.update(applied=False,source_sha256=self.desired,enabledModules=dict(root=True,lease=True))
        preview=dict(Fence=s['acceptedFence'],SourceID=7)
        with patch.object(self.t,'cli',return_value=json.dumps({'clear_preview':preview})):
            self.assertTrue(policy.active(self.t,s,self.desired,True))
        preview['Fence']=dict(preview['Fence'],Generation=99)
        with patch.object(self.t,'cli',return_value=json.dumps({'clear_preview':preview})):
            self.assertFalse(policy.active(self.t,s,self.desired,True))
        s.update(enabledModules=dict(root=False,lease=False))
        self.assertFalse(policy.active(self.t,s,self.desired,False))

    def test_reverse_refuses_active_or_pending_policy(self):
        self.start()
        with self.assertRaisesRegex(ValueError,'handoff still pending'):self.t.reverse()
    def test_config_rejects_v1_unrelated_and_non_alloff_disable(self):
        for c,on in [({'schema_version':1,'machine':'idcfast','enabled':False},False),
                     ({'schema_version':2,'machine':'idcfast','enabled':True,'app_connector_ttl':{'enabled':True},'auto_ipv6':{'enabled':True}},True),
                     ({'schema_version':2,'machine':'idcfast','enabled':True},False)]:
            with self.assertRaises(ValueError):policy.validate_config(c,on)


class LayoutTests(unittest.TestCase):
    def test_custom_contract_requires_new_release_and_predecessor(self):
        root=Path(__file__).resolve().parents[1]
        p=plan.read(root/'plan.example.json');p['native']=plan.read(root/'native-contract.example.json')
        n=p['native'];n.update(previousDeployment='old-commit',daemon='/usr/local/lib/tailscale-unified/old/tailscaled',cli='/usr/local/lib/tailscale-unified/old/tailscale')
        p['originalExecStart']='ExecStart='+n['daemon']+' --state=/state --socket=/sock'
        plan.validate(p)
        for field,value in [('previousDeployment',p['deploymentID']),('daemon','/tmp/tailscaled'),('cli','/usr/bin/tailscale')]:
            old=n[field];n[field]=value
            with self.assertRaises(ValueError):plan.validate(p)
            n[field]=old
    def test_restore_dropin_is_idempotent_and_fenced(self):
        f=nt.NativeTests();f.setUp();self.addCleanup(f.doCleanups);t=f.t
        t.drop.parent.mkdir(parents=True,exist_ok=True);t.drop.write_text('old')
        t.p['expectedBefore']={str('/etc/systemd/system/tailscaled.service.d/90-unified-transaction.conf'):plan.digest(t.drop)}
        t.snapshot('readable');t.drop.write_text('new');new=plan.digest(t.drop)
        t.restore_layout_file(t.drop,new);self.assertEqual(t.drop.read_text(),'old')
        t.restore_layout_file(t.drop,new)
        t.drop.write_text('foreign')
        with self.assertRaisesRegex(ValueError,'foreign layout'):t.restore_layout_file(t.drop,new)

class CompatibilityTests(unittest.TestCase):
    def fixture(self, enabled=False):
        import base64
        import compatibility as c
        config=dict(schema_version=2,machine='idcfast',enabled=enabled,app_connector_ttl={'enabled':enabled})
        record=dict(SchemaVersion=1,Fence={'ProfileID':'p','Generation':9},Config=config,Hash=c.sha(c.encode(config)),SourceHash='a'*64)
        values={'profile||_unifiedPolicyV1':c.encode(record),'identity':b'private fixture key',
                'prefs':b'{"AdvertiseRoutes":["0.0.0.0/0","::/0","203.0.113.0/24"]}',
                'profile||_routeInfo':b'opaque current routes',
                'profile||_unifiedRouteLedgerV1':b'{"unknown":["192.0.2.1/32"],"shared":["192.0.2.2/32"]}'}
        return c.encode({k:base64.b64encode(v).decode() for k,v in values.items()})
    def test_migration_preserves_every_other_value_and_generation(self):
        import base64
        import compatibility as c
        raw=self.fixture();after,changes=c.migrate(raw)
        self.assertEqual(len(changes),1)
        before=c.decode(raw);result=c.decode(after)
        self.assertEqual(set(before),set(result))
        for k in before:
            if k.endswith('_unifiedPolicyV1'):continue
            self.assertEqual(before[k],result[k])
        r=c.decode(base64.b64decode(result['profile||_unifiedPolicyV1']))
        self.assertEqual(r['Config']['schema_version'],1)
        self.assertNotIn('app_connector_ttl',r['Config']);self.assertFalse(r['Config']['lease']['enabled'])
        self.assertEqual(r['Fence']['Generation'],9)
        self.assertEqual(c.migrate(after),(after,[]))
    def test_enabled_lkg_refused(self):
        import compatibility as c
        with self.assertRaises(ValueError):c.migrate(self.fixture(True))
    def test_handoff_must_be_complete(self):
        import base64
        import compatibility as c
        for complete,handoff in [(False,True),(True,False)]:
            state=c.decode(self.fixture());payload=c.encode(dict(Schema=2,Complete=complete,Handoff=handoff))
            env={'Payload':c.decode(payload),'SHA256':list(hashlib.sha256(payload).digest())}
            state['profile||_appConnectorTTLV2']=base64.b64encode(c.encode(env)).decode()
            with self.assertRaisesRegex(ValueError,'handoff'):c.migrate(c.encode(state))
    def test_raw_checksum_and_duplicate_keys_refused(self):
        import base64
        import compatibility as c
        state=c.decode(self.fixture());record=c.decode(base64.b64decode(state['profile||_unifiedPolicyV1']))
        record['Hash']='0'*64;state['profile||_unifiedPolicyV1']=base64.b64encode(c.encode(record)).decode()
        with self.assertRaisesRegex(ValueError,'checksum'):c.migrate(c.encode(state))
        with self.assertRaises(ValueError):c.migrate(b'{"x":"a","x":"b"}')


if __name__=='__main__':unittest.main()
