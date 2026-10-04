import datetime as dt
import fcntl
import os
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
        (self.root/'maintenance.lock').touch()
        guard=patch.object(u,'MAINTENANCE',self.root/'maintenance.lock');guard.start();self.addCleanup(guard.stop)
        for obj,name,value in [(u,'ROOT',self.root),(u,'CONFIG',self.root/'config.json'),(u,'installed',lambda:{'panasms-prototype':'0.2.5'}),(u.time,'sleep',lambda _:None)]:
            p=patch.object(obj,name,value);p.start();self.addCleanup(p.stop)
        u.save('state.json',{'id':'test','phase':'queued','operation':'install','version':'0.2.6'})
    def test_maintenance_excludes_active_operation_and_new_submissions(self):
        with u.MAINTENANCE.open() as operation:
            fcntl.flock(operation, fcntl.LOCK_SH | fcntl.LOCK_NB)
            with self.assertRaisesRegex(Rejected, 'Active requests'):
                with u.maintenance():pass
        with u.maintenance():
            self.assertEqual(os.environ.get('PANASMS_MAINTENANCE'), '1')
            with u.MAINTENANCE.open() as operation:
                with self.assertRaises(BlockingIOError):fcntl.flock(operation,fcntl.LOCK_SH|fcntl.LOCK_NB)
        self.assertNotIn('PANASMS_MAINTENANCE',os.environ)

    def test_supported_os_requires_explicit_distribution_version_and_arch(self):
        for distro, version, arch, expected in [('debian','13','amd64',True), ('raspbian','13','arm64',True), ('ubuntu','24.04','amd64',True), ('ubuntu','24.04','arm64',False), ('ubuntu','22.04','amd64',False), ('other','13','amd64',False)]:
            with self.subTest(distro=distro,version=version,arch=arch):
                self.assertEqual(u.supported_os(f'ID={distro}\nVERSION_ID="{version}"\n',arch), expected)

    def test_channel_and_compatibility(self):
        with self.assertRaises(Rejected):u.settings({'channel':'other','mode':'auto','hour':3})
        self.assertTrue(u.constraints('0.2.6~dev.123','>=0.2.0,<0.3.0'))
        self.assertFalse(u.constraints('0.3.0','>=0.2.0,<0.3.0'))
        self.assertTrue(u.greater('0.2.6~dev.123','0.2.5'))
        self.assertFalse(u.greater('0.2.5','0.2.6~dev.123'))
    def test_dependency_replacement_and_removal_blocked(self):
        for text in ('Inst libc6 [2.1] (2.2 repo)','Remv samba [1.0]'):
            with patch.object(u,'run',return_value=text),self.assertRaises(Rejected):u.apt_plan(['/a.deb'])
        with patch.object(u,'run',return_value='Inst panasms-prototype [0.2.5] (0.2.6 local)\nInst new-dependency (1.0 repo)'),self.assertRaises(Rejected):u.apt_plan(['/a.deb'])
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
        u.save('backup.json',{'version':'0.2.5'})
        with patch.object(u,'preflight'), patch.object(u,'restore',side_effect=Rejected('restore failed')):u.work()
        self.assertEqual(u.read('state.json',{})['phase'],'recovery-required')
        self.assertTrue(u.changing())

    def test_power_loss_recovery_only_restores_after_mutation(self):
        u.save('backup.json',{'units':['core','agent']})
        u.save('active-units.json',['core','agent'])
        for phase in ('queued','backing-up','installing','verifying','rolling-back'):
            u.save('state.json',{'id':'test','phase':phase})
            with patch.object(u,'restore') as restore, patch.object(u,'start') as start:u.recover()
            self.assertEqual(restore.called,phase in ('installing','verifying','rolling-back'))
            start.assert_called_once_with(['core','agent'],boot=True)

    def test_boot_restart_does_not_wait_for_units_ordered_after_recovery(self):
        with patch.object(u,'run') as run:u.start(['core','agent'],boot=True)
        self.assertEqual(run.call_args_list[-1].args[0],['systemctl','start','--no-block','core','agent'])

    def test_boot_restart_failure_remains_actionable(self):
        u.save('state.json',{'id':'test','phase':'verifying'})
        u.save('backup.json',{'units':['core']})
        with patch.object(u,'restore'), patch.object(u,'start',side_effect=Rejected('cannot queue services')):
            with self.assertRaisesRegex(Rejected,'cannot queue services'):u.recover()
        self.assertEqual(u.read('state.json',{})['phase'],'recovery-required')
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
