from pathlib import Path
import sys
import unittest
from unittest.mock import patch
from types import SimpleNamespace
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'management'))
import host
import main
from common import Rejected

class PowerTest(unittest.TestCase):
    def test_no_shutdown_during_plan(self):
        with patch.object(host, 'command') as command:
            for action in ('system.poweroff', 'system.reboot'):
                plan = host.plan(action, {})
                self.assertEqual(plan['confirmation'], 'NAS')
                self.assertTrue(plan['fingerprint'])
            command.assert_not_called()

    def test_graceful_delayed_systemd_shutdown(self):
        for action in ('poweroff', 'reboot'):
            with patch.object(host, 'command') as command:
                host.execute('system.' + action, {})
                args = command.call_args.args[0]
                self.assertEqual(args[-3:], ['/usr/bin/systemctl', '--no-block', action])
                self.assertIn('--on-active=5s', args)
                self.assertNotIn('--force', args)

    def test_regular_user_cannot_execute_power_action(self):
        with patch.object(main.pwd, 'getpwnam', return_value=SimpleNamespace(pw_uid=1001, pw_gid=1001)), patch.object(main.grp, 'getgrnam', return_value=SimpleNamespace(gr_gid=27)), patch.object(main.os, 'getgrouplist', return_value=[1001]), patch.object(host, 'command') as command:
            with self.assertRaises(Rejected):
                main.dispatch('execute', 'ordinary', {'action': 'system.poweroff', 'params': {}})
            command.assert_not_called()

    def test_confirmation_is_required(self):
        with patch.object(main.pwd, 'getpwnam', return_value=SimpleNamespace(pw_uid=1000, pw_gid=1000)), patch.object(main.grp, 'getgrnam', return_value=SimpleNamespace(gr_gid=27)), patch.object(main.os, 'getgrouplist', return_value=[1000,27]), patch.object(main.module_manager, 'load_operations', return_value=[]), patch.object(host, 'command') as command:
            plan = host.plan('system.poweroff', {})
            with self.assertRaises(Rejected):
                main.dispatch('execute', 'admin', {'action': 'system.poweroff', 'params': {}, 'fingerprint': plan['fingerprint'], 'confirmation': 'wrong'})
            command.assert_not_called()
