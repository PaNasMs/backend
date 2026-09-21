import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'management'))
import accounts
import account_policy
import account_sessions
from common import Rejected

class AccountsTest(unittest.TestCase):
    def test_policy_revoke_and_uid_reuse(self):
        with tempfile.TemporaryDirectory() as d, patch.object(account_policy, 'PATH', Path(d)/'accounts.json'), patch.object(account_policy, 'atomic', side_effect=lambda path,text,mode: path.write_text(text)):
            user=SimpleNamespace(pw_name='alice',pw_uid=1200)
            first=account_policy.save(user, {'panel':True}, revoke=True)
            second=account_policy.save(user, {'panel':False}, revoke=True)
            self.assertNotEqual(first['epoch'],second['epoch'])
            self.assertFalse(second['panel'])
            user.pw_uid=1300
            self.assertEqual(account_policy.entry(user),{})
    def test_last_admin_and_self_protection(self):
        alice=SimpleNamespace(pw_name='alice')
        bob=SimpleNamespace(pw_name='bob')
        with patch.object(accounts,'admins',return_value=[alice]):
            with self.assertRaisesRegex(Rejected,'last available'):accounts.protect_admin(alice,'bob',True)
            with self.assertRaisesRegex(Rejected,'own panel'):accounts.protect_admin(alice,'alice',True)
        with patch.object(accounts,'admins',return_value=[alice,bob]):accounts.protect_admin(alice,'bob',True)
    def test_ambiguous_and_service_accounts_protected(self):
        with patch.object(accounts,'bounds',return_value=(1000,60000)), patch.object(accounts,'local',return_value=False):
            with self.assertRaises(Rejected):accounts.normal(SimpleNamespace(pw_uid=1000,pw_name='ambiguous'))
        with patch.object(accounts,'bounds',return_value=(1000,60000)),patch.object(accounts,'local',return_value=True):
            with self.assertRaises(Rejected):accounts.normal(SimpleNamespace(pw_uid=0,pw_name='root'))
    def test_primary_sudo_counts_as_admin(self):
        alice=SimpleNamespace(pw_name='alice',pw_uid=1200,pw_gid=27)
        with patch.object(accounts.pwd,'getpwall',return_value=[alice]),patch.object(accounts.grp,'getgrnam',return_value=SimpleNamespace(gr_gid=27,gr_mem=[])),patch.object(accounts,'normal'),patch.object(account_policy,'entry',return_value={}),patch.object(account_policy,'shadow',return_value={'passwordStatus':'set','expiryDay':-1}):
            self.assertEqual(accounts.admins(),[alice])
    def test_session_termination_is_scoped(self):
        with patch.object(account_sessions,'sessions',side_effect=[[{'id':'one','state':'active'},{'id':'two','state':'active'}],[]]),patch.object(account_sessions,'command') as command:
            account_sessions.terminate('alice','two')
            command.assert_called_once_with(['loginctl','terminate-session','two'],timeout=10)
    def test_password_inactivity(self):
        today=(account_policy.datetime.date.today()-account_policy.datetime.date(1970,1,1)).days
        self.assertTrue(account_policy.password_inactive({'lastChange':today-10,'maxDays':5,'inactiveDays':1}))
        self.assertFalse(account_policy.password_inactive({'lastChange':0,'maxDays':5,'inactiveDays':1}))
        self.assertFalse(account_policy.password_inactive({'lastChange':today-10,'maxDays':5,'inactiveDays':-1}))

    def test_expiry_validation(self):
        self.assertEqual(account_policy.expiry(''),-1)
        with self.assertRaises(Rejected):account_policy.expiry('not a date')

if __name__=='__main__': unittest.main()
