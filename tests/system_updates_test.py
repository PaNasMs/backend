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

    def test_terminal_stop_releases_shared_lock_before_maintenance(self):
        with u.MAINTENANCE.open() as terminal:
            fcntl.flock(terminal,fcntl.LOCK_SH|fcntl.LOCK_NB)
            def stop(units):
                self.assertEqual(units,['panasms-module-terminal.service'])
                fcntl.flock(terminal,fcntl.LOCK_UN)
            with patch.object(u,'stop',side_effect=stop):
                u.stop_terminals(['core','panasms-module-terminal.service'])
            with u.maintenance(drain=True):
                with u.MAINTENANCE.open() as new_request:
                    with self.assertRaises(BlockingIOError):
                        fcntl.flock(new_request,fcntl.LOCK_SH|fcntl.LOCK_NB)

    def test_other_active_work_still_blocks_and_terminal_service_is_restored(self):
        with u.MAINTENANCE.open() as operation:
            fcntl.flock(operation,fcntl.LOCK_SH|fcntl.LOCK_NB)
            events=self.transaction()
        self.assertEqual(u.read('state.json',{})['phase'],'failed')
        self.assertIn('terminal-stop',events)
        self.assertIn(('start',['core','panasms-module-terminal.service']),events)
        self.assertNotIn('backup',events)
        self.assertNotIn('install',events)

    def test_manual_rollback_stops_terminals_before_restore(self):
        u.save('state.json',{'id':'test','phase':'queued','operation':'rollback'})
        u.save('backup.json',{'version':'0.2.5'})
        events=[]
        with patch.object(u,'preflight'), patch.object(u,'module_idle'), patch.object(u,'services',return_value=['core','panasms-module-terminal.service']), patch.object(u,'stop',side_effect=lambda units:events.append(('stop',units))), patch.object(u,'restore',side_effect=lambda:events.append(('restore',None))):
            u.work()
        self.assertEqual(events,[('stop',['panasms-module-terminal.service']),('restore',None)])
        self.assertEqual(u.read('state.json',{})['phase'],'rolled-back')

    def test_install_plan_reports_module_blocker_before_submission(self):
        current={'available':True,'candidate':{'version':'0.2.6'},'installed':{}}
        with patch.object(u,'busy',return_value=False), patch.object(u,'query',return_value=current), patch.object(u,'preflight'), patch.object(u,'module_idle',side_effect=Rejected('Wait for active module tasks: cloud-sync')) as idle:
            with self.assertRaisesRegex(Rejected,'cloud-sync'):
                u.plan('system.update.install',{})
            idle.assert_called_once_with(skip_terminal=True)

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
    def test_apt_plan_upgrades_installed_cooling_but_never_installs_it(self):
        both='Inst panasms-cooling [0.2.5] (0.2.6 local) [arm64]\nInst panasms-prototype [0.2.5] (0.2.6 local) [arm64]'
        with patch.object(u,'installed',return_value={'panasms-prototype':'0.2.5','panasms-cooling':'0.2.5'}),patch.object(u,'run',return_value=both):u.apt_plan(['/a.deb','/b.deb'])
        with patch.object(u,'run',return_value=both),self.assertRaisesRegex(Rejected,'panasms-cooling'):u.apt_plan(['/a.deb','/b.deb'])
    def release(self, *names, version='0.2.6'):
        return {'version':version,'packages':{'arm64':[{'name':n,'file':f'{n}_{version}_arm64.deb','size':3,'sha256':__import__('hashlib').sha256(b'deb').hexdigest(),'url':u.BASE+n} for n in names]}}
    def download(self, entry, current):
        fields={'Package':None,'Version':entry['version'],'Architecture':'arm64'}
        def run(args,**kw):
            if args[0]=='dpkg':return 'arm64\n'
            return Path(args[2]).name.split('_')[0] if args[3]=='Package' else fields[args[3]]
        with patch.object(u,'installed',return_value=current),patch.object(u,'run',side_effect=run),patch.object(u,'fetch',return_value=b'deb') as fetch:
            return u.download(entry),fetch
    def test_download_includes_installed_cooling_package(self):
        paths,fetch=self.download(self.release('panasms-cooling','panasms-prototype'),{'panasms-prototype':'0.2.5','panasms-cooling':'0.2.4'})
        self.assertEqual(sorted(paths),['panasms-cooling','panasms-prototype'])
        self.assertEqual(fetch.call_count,2)
        self.assertEqual(sorted(u.read('downloaded.json',{})['paths']),sorted(paths.values()))
    def test_download_skips_cooling_that_is_not_installed(self):
        paths,fetch=self.download(self.release('panasms-cooling','panasms-prototype'),{'panasms-prototype':'0.2.5'})
        self.assertEqual(list(paths),['panasms-prototype'])
        self.assertEqual(fetch.call_count,1)
    def test_download_rejects_unrelated_or_duplicate_packages(self):
        for names in (('panasms-prototype','samba'),('panasms-prototype','panasms-prototype')):
            with self.subTest(names=names),self.assertRaises(Rejected):self.download(self.release(*names),{'panasms-prototype':'0.2.5'})
    def test_installed_reports_cooling_with_core(self):
        def query(args,**kw):
            versions={'panasms-prototype':'0.2.5','panasms-cooling':'0.2.4'}
            return subprocess.CompletedProcess(args,0,'installed '+versions[args[-1]])
        with patch.object(u.subprocess,'run',side_effect=query):
            self.assertEqual(importlib.reload(u).installed(),{'panasms-prototype':'0.2.5','panasms-cooling':'0.2.4'})
    def transaction(self, failure=False, cooling=None):
        events=[];version=['0.2.5'];cooling_version=['0.2.5']
        def run(args,**kw):
            if args[0]=='apt-get' and '--download-only' not in args:
                events.append('install');version[0]='0.2.6'
                if cooling!='stale':cooling_version[0]='0.2.6'
            return ''
        def health():
            events.append('health')
            if failure:raise Rejected('health failed')
        patches={
            'check':lambda:{'releases':[{'version':'0.2.6','rollbackCompatible':True}]},
            'download':lambda e:{'panasms-prototype':'/new.deb',**({'panasms-cooling':'/cooling.deb'} if cooling else {})}, 'preflight':lambda *a,**k:events.append('preflight'),
            'apt_plan':lambda p:events.append('apt-plan'), 'services':lambda:['core','panasms-module-terminal.service'],
            'stop':lambda p:events.append('terminal-stop' if p==['panasms-module-terminal.service'] else ('stop',p)), 'backup':lambda p:events.append(('backup',p)),
            'start':lambda p:events.append(('start',p)), 'healthy':health,
            'restore':lambda:events.append('restore'), 'run':run,
            'installed':lambda:{'panasms-prototype':version[0],**({'panasms-cooling':cooling_version[0]} if cooling else {})},
            'active':lambda unit:bool(cooling) and (cooling!='inactive' or 'install' not in events),
        }
        with patch.multiple(u,**patches):u.work()
        return events
    def test_success_orders_backup_before_install(self):
        events=self.transaction()
        units=['core','panasms-module-terminal.service']
        self.assertLess(events.index('terminal-stop'),events.index(('stop',units)))
        self.assertIn('panasms-module-terminal.service',u.read('active-units.json',[]))
        self.assertLess(events.index(('stop',units)),events.index(('backup',units)))
        self.assertLess(events.index(('backup',units)),events.index('install'))
        self.assertEqual(u.read('state.json',{})['phase'],'complete')
        self.assertNotIn('restore',events)
    def test_cooling_upgrades_with_core_without_being_stopped(self):
        events=self.transaction(cooling='active')
        units=['core','panasms-module-terminal.service'];keep=units+['panasms-cooling.service']
        self.assertIn(('stop',units),events)
        self.assertIn(('backup',keep),events)
        self.assertIn(('start',keep),events)
        self.assertEqual(u.read('active-units.json',[]),keep)
        self.assertEqual(u.read('state.json',{})['phase'],'complete')
        self.assertNotIn('restore',events)
    def test_cooling_version_or_service_failure_rolls_back(self):
        for cooling in ('stale','inactive'):
            with self.subTest(cooling=cooling):
                u.save('state.json',{'id':'test','phase':'queued','operation':'install','version':'0.2.6'})
                events=self.transaction(cooling=cooling)
                self.assertEqual(events.count('restore'),1)
                state=u.read('state.json',{})
                self.assertEqual(state['phase'],'rolled-back')
                self.assertIn('Installed version' if cooling=='stale' else 'panasms-cooling.service',state['error'])
    def test_backup_repacks_every_installed_package(self):
        u.save('state.json',{'id':'a'*32,'phase':'backing-up','version':'0.2.6'})
        current={'panasms-prototype':'0.2.5','panasms-cooling':'0.2.5'}
        def run(args,cwd=None,**kw):
            if args[0]=='dpkg-repack':(Path(cwd)/f'{args[1]}_0.2.5_arm64.deb').write_bytes(b'deb')
            return ''
        with patch.object(u,'installed',return_value=current),patch.object(u,'run',side_effect=run):u.backup(['core','panasms-cooling.service'])
        backup=u.read('backup.json',{})
        self.assertEqual(sorted(Path(p).name.split('_')[0] for p in backup['packages']),['panasms-cooling','panasms-prototype'])
        self.assertEqual((backup['version'],backup['toVersion'],backup['units']),('0.2.5','0.2.6',['core','panasms-cooling.service']))
    def test_failed_health_rolls_back_without_retrying_update(self):
        events=self.transaction(True)
        self.assertEqual(events.count('restore'),1)
        self.assertEqual(u.read('state.json',{})['phase'],'rolled-back')
    def test_failed_manual_restore_keeps_recovery_required(self):
        u.save('state.json',{'id':'test','phase':'queued','operation':'rollback','version':'0.2.5'})
        u.save('backup.json',{'version':'0.2.5'})
        with patch.object(u,'preflight'), patch.object(u,'services',return_value=[]), patch.object(u,'restore',side_effect=Rejected('restore failed')):u.work()
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
