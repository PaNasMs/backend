import datetime as dt
import importlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).parents[1]/'management'))
import system_updates as u
from common import Rejected

class Updates(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        for obj,name,value in [(u,'ROOT',self.root),(u,'CONFIG',self.root/'config.json'),(u,'installed',lambda:{'panasms-prototype':'0.2.5'}),(u.time,'sleep',lambda _:None)]:
            p=patch.object(obj,name,value);p.start();self.addCleanup(p.stop)
        u.save('state.json',{'id':'test','phase':'queued','operation':'install','version':'0.2.6'})
    def test_channel_and_compatibility(self):
        with self.assertRaises(Rejected):u.settings({'channel':'other','mode':'auto','hour':3})
        self.assertTrue(u.constraints('0.2.6~dev.123','>=0.2.0,<0.3.0'))
        self.assertFalse(u.constraints('0.3.0','>=0.2.0,<0.3.0'))
        self.assertTrue(u.greater('0.2.6~dev.123','0.2.5'))
        self.assertFalse(u.greater('0.2.5','0.2.6~dev.123'))
    def test_dependency_replacement_and_removal_blocked(self):
        for text in ('Inst libc6 [2.1] (2.2 repo)','Remv samba [1.0]'):
            with patch.object(u,'run',return_value=text),self.assertRaises(Rejected):u.apt_plan(['/a.deb'])
        with patch.object(u,'run',return_value='Inst panasms-prototype [0.2.5] (0.2.6 local)\nInst new-dependency (1.0 repo)'):u.apt_plan(['/a.deb'])
    def transaction(self, failure=False):
        events=[];version=['0.2.5']
        def run(args,**kw):
            if args[0]=='apt-get' and '--download-only' not in args:
                events.append('install');version[0]='0.2.6'
            return ''
        def health():
            events.append('health')
            if failure:raise Rejected('health failed')
        patches={
            'check':lambda:{'releases':[{'version':'0.2.6','rollbackCompatible':True}]},
            'download':lambda e:['/new.deb'], 'preflight':lambda *a,**k:events.append('preflight'),
            'apt_plan':lambda p:events.append('apt-plan'), 'services':lambda:['core'],
            'stop':lambda p:events.append('stop'), 'backup':lambda p:events.append('backup'),
            'start':lambda p:events.append('start'), 'healthy':health,
            'restore':lambda:events.append('restore'), 'run':run,
            'installed':lambda:{'panasms-prototype':version[0]},
        }
        with patch.multiple(u,**patches):u.work()
        return events
    def test_success_orders_backup_before_install(self):
        events=self.transaction()
        self.assertLess(events.index('stop'),events.index('backup'))
        self.assertLess(events.index('backup'),events.index('install'))
        self.assertEqual(u.read('state.json',{})['phase'],'complete')
        self.assertNotIn('restore',events)
    def test_failed_health_rolls_back_without_retrying_update(self):
        events=self.transaction(True)
        self.assertEqual(events.count('restore'),1)
        self.assertEqual(u.read('state.json',{})['phase'],'rolled-back')
    def test_failed_manual_restore_keeps_recovery_required(self):
        u.save('state.json',{'id':'test','phase':'queued','operation':'rollback','version':'0.2.5'})
        with patch.object(u,'restore',side_effect=Rejected('restore failed')):u.work()
        self.assertEqual(u.read('state.json',{})['phase'],'recovery-required')
        self.assertTrue(u.changing())

    def test_power_loss_recovery_only_restores_after_mutation(self):
        for phase in ('queued','backing-up','installing','verifying','rolling-back'):
            u.save('state.json',{'id':'test','phase':phase})
            with patch.object(u,'restore') as restore:u.recover()
            self.assertEqual(restore.called,phase in ('installing','verifying','rolling-back'))
    def test_tampered_and_expired_signed_catalog_are_rejected(self):
        home=self.root/'gpg';home.mkdir(mode=0o700)
        def gpg(*a):return subprocess.check_output(['gpg','--batch','--homedir',str(home),*a],stderr=subprocess.DEVNULL)
        gpg('--passphrase','','--quick-generate-key','Test Updates','ed25519','sign','0')
        key=self.root/'key.gpg';key.write_bytes(gpg('--export'))
        catalog=self.root/'signed.json'
        def sign(expires):
            catalog.write_text(json.dumps({'schemaVersion':1,'channel':'stable','generatedAt':dt.datetime.now(dt.timezone.utc).isoformat(),'expiresAt':expires.isoformat(),'releases':[]}))
            gpg('--yes','--armor','--detach-sign',str(catalog))
            return catalog.read_bytes(),catalog.with_suffix('.json.asc').read_bytes()
        raw,sig=sign(dt.datetime.now(dt.timezone.utc)+dt.timedelta(days=1))
        with patch.object(u,'KEY',key),patch.object(u,'fetch',side_effect=[raw,sig]):u.check()
        with patch.object(u,'KEY',key),patch.object(u,'fetch',side_effect=[raw+b' ',sig]),self.assertRaises(Rejected):u.check()
        raw,sig=sign(dt.datetime.now(dt.timezone.utc)-dt.timedelta(days=1))
        with patch.object(u,'KEY',key),patch.object(u,'fetch',side_effect=[raw,sig]),self.assertRaisesRegex(Rejected,'expired'):u.check()
