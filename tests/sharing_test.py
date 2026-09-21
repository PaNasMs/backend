import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'management'))
import sharing
from common import Rejected

class SharingTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        for key in ('STATE','SMB','EXPORTS','JOURNAL','LOCK'):
            p=patch.object(sharing,key,Path(self.tmp.name)/key);p.start();self.addCleanup(p.stop)
        def atomic(p,s,mode=0o600): p.write_text(s)
        p=patch.object(sharing,'atomic',side_effect=atomic);p.start();self.addCleanup(p.stop)
        p=patch.object(sharing,'validate_config');p.start();self.addCleanup(p.stop)
        self.share={'name':'Media','path':'/srv/data/media','smb':True,'nfs':True,'readers':['alice'],'writers':['@family'],'clients':['192.168.1.0/24'],'readOnly':False,'mountpoint':'/srv/data','volume':'uuid'}
    def test_protocols_and_permissions(self):
        smb,nfs=sharing.config([self.share])
        self.assertIn('read only = yes',smb);self.assertIn('write list = @family',smb)
        self.assertIn('root preexec close = yes',smb)
        self.assertIn('root_squash,mountpoint=/srv/data',nfs)
        self.assertNotIn('no_root_squash',nfs)
    def test_disable_protocols(self):
        s={**self.share,'smb':False,'nfs':False}
        self.assertEqual(sharing.config([s]),(sharing.HEADER,sharing.HEADER))
    def test_transaction_success(self):
        state={'shares':[self.share],'accounts':{}}
        with patch.object(sharing,'reload_services'):sharing.apply(state)
        self.assertEqual(sharing.read(),state);self.assertFalse(sharing.JOURNAL.exists())
    def test_failed_reload_rolls_back(self):
        before={'shares':[],'accounts':{}}
        sharing.STATE.write_text(sharing.json.dumps(before))
        with patch.object(sharing,'reload_services',side_effect=[Rejected('failed'),None]):
            with self.assertRaises(Rejected):sharing.apply({'shares':[self.share],'accounts':{}})
        self.assertEqual(sharing.read(),before);self.assertFalse(sharing.JOURNAL.exists())
    def test_failed_rollback_keeps_journal(self):
        with patch.object(sharing,'reload_services',side_effect=Rejected('failed')):
            with self.assertRaisesRegex(Rejected,'rollback needs recovery'):sharing.apply({'shares':[self.share],'accounts':{}})
        self.assertTrue(sharing.JOURNAL.exists())
    def test_external_edits_detected(self):
        sharing.SMB.write_text('outside edit')
        self.assertTrue(sharing.drift({'shares':[]}))
        with self.assertRaisesRegex(Rejected,'outside'):sharing.plan('share.remove',{'target':'Media'})
    def test_pending_recovery_blocks_writes(self):
        sharing.JOURNAL.write_text('{}')
        with self.assertRaisesRegex(Rejected,'recovery'):sharing.plan('share.save',{})
    def test_config_injection_rejected(self):
        for n in ['global','Homes','name\npath=/','foo]','bad space','%u']:
            with self.subTest(n=n),self.assertRaises(Rejected):sharing.normalize({'name':n})
    def test_password_not_written_to_state(self):
        u=sharing.pwd.getpwuid(sharing.os.getuid())
        sharing.STATE.write_text(sharing.json.dumps({'shares':[],'accounts':{u.pw_name:{'uid':u.pw_uid,'enabled':True}}}))
        with patch.object(sharing,'command'),patch.object(sharing.account_policy,'entry',return_value={}),patch.object(sharing.account_policy,'shadow',return_value={}),patch.object(sharing,'password_revision',return_value='digest'):
            sharing.sync_password(u.pw_name,'test-only-secret')
        self.assertNotIn('test-only-secret',sharing.STATE.read_text())
        self.assertEqual(sharing.read()['accounts'][u.pw_name]['status'],'ready')
    def test_failed_sync_is_visible(self):
        u=sharing.pwd.getpwuid(sharing.os.getuid())
        sharing.STATE.write_text(sharing.json.dumps({'shares':[],'accounts':{u.pw_name:{'uid':u.pw_uid,'enabled':True}}}))
        with patch.object(sharing,'command',side_effect=Rejected('failed')),patch.object(sharing.account_policy,'entry',return_value={}),patch.object(sharing.account_policy,'shadow',return_value={}),patch.object(sharing,'password_revision',return_value='digest'):
            with self.assertRaises(Rejected):sharing.sync_password(u.pw_name,'test-only-secret')
        self.assertEqual(sharing.read()['accounts'][u.pw_name]['status'],'error')
    def test_joint_publication_disables_oplocks(self):
        self.assertIn('oplocks = no',sharing.config([self.share])[0])
        self.assertNotIn('oplocks = no',sharing.config([{**self.share,'nfs':False}])[0])
    def test_external_password_change_revokes_old_smb_password(self):
        u=sharing.pwd.getpwuid(sharing.os.getuid())
        sharing.STATE.write_text(sharing.json.dumps({'shares':[],'accounts':{u.pw_name:{'uid':u.pw_uid,'enabled':True,'status':'ready','passwordRevision':'old'}}}))
        with patch.object(sharing,'disable') as disable,patch.object(sharing.account_policy,'entry',return_value={}),patch.object(sharing.account_policy,'shadow',return_value={'passwordStatus':'set'}),patch.object(sharing,'password_revision',return_value='new'):
            sharing.reconcile()
        disable.assert_called_once_with(u.pw_name)
        self.assertEqual(sharing.read()['accounts'][u.pw_name]['status'],'pending')
    def test_external_account_lock_revokes_smb(self):
        u=sharing.pwd.getpwuid(sharing.os.getuid())
        sharing.STATE.write_text(sharing.json.dumps({'shares':[],'accounts':{u.pw_name:{'uid':u.pw_uid,'enabled':True,'status':'ready'}}}))
        with patch.object(sharing,'disable') as disable,patch.object(sharing.account_policy,'entry',return_value={}),patch.object(sharing.account_policy,'shadow',return_value={'passwordStatus':'locked'}):
            sharing.reconcile()
        disable.assert_called_once_with(u.pw_name)
        self.assertEqual(sharing.read()['accounts'][u.pw_name]['status'],'disabled')
    def test_reused_account_does_not_receive_password(self):
        u=sharing.pwd.getpwuid(sharing.os.getuid())
        sharing.STATE.write_text(sharing.json.dumps({'shares':[],'accounts':{u.pw_name:{'uid':u.pw_uid+1,'enabled':True}}}))
        with patch.object(sharing,'command') as cmd:sharing.sync_password(u.pw_name,'test-only-secret')
        cmd.assert_not_called()

if __name__=='__main__':unittest.main()
