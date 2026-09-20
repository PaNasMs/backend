from pathlib import Path
from types import SimpleNamespace
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'management'))
import network as n
w = n.wifi


class WifiValidation(unittest.TestCase):
    def test_security_classification_does_not_treat_wep_or_enterprise_as_open(self):
        for flags, expected in [(0x100, 'wpa2'), (0x500, 'wpa3'), (0x200, 'enterprise'), (0x800, 'owe'), (0x2000, 'enterprise')]:
            self.assertEqual(w.security({'RsnFlags': flags, 'Flags': 1}), expected)
        self.assertEqual(w.security({'Flags': 1}), 'unsupported')
        self.assertEqual(w.security({}), 'open')

    def test_hidden_ssid_byte_limit_and_password(self):
        base = {'ssid': 'test', 'security': 'wpa2', 'password': 'abcdefgh'}
        self.assertEqual(w.selection(None, '/', {}, base)['ssid'], b'test')
        for updates in ({'ssid': ''}, {'ssid': 'я' * 17}, {'password': '1234567'}, {'password': 'x' * 64}, {'security': 'enterprise'}, {'ssid': 'a\x00b'}):
            with self.subTest(updates=updates), self.assertRaises(n.Rejected):
                w.selection(None, '/', {}, {**base, **updates})
        self.assertEqual(w.selection(None, '/', {}, {**base, 'password': 'a' * 64})['password'], 'a' * 64)

    def test_access_point_must_belong_to_device_and_match_ssid(self):
        rows = [{'id': '/ap/1', 'ssidHex': b'test'.hex(), 'security': 'wpa2'}]
        with patch.object(w, 'points', return_value=rows):
            for params in ({'accessPoint': '/ap/2', 'ssidHex': b'test'.hex()}, {'accessPoint': '/ap/1', 'ssidHex': b'evil'.hex()}):
                with self.assertRaises(n.Rejected):
                    w.selection(None, '/device/1', {}, params)

    def test_recovery_ignores_stale_timer_and_confirmed_change(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(n, 'STATE_DIR', Path(temp)/'run'), patch.object(w, 'RECOVERY', Path(temp)/'durable'/'pending.json'):
            with n.locked():
                w.remember({'id': 'new', 'status': 'pending'})
            with patch.object(w, 'rollback') as rollback:
                w.recover('old')
                rollback.assert_not_called()
            with n.locked():
                w.remember({'id': 'new', 'status': 'confirmed'})
            with patch.object(w, 'rollback') as rollback:
                w.recover('new')
                rollback.assert_not_called()
            self.assertEqual(w.RECOVERY.stat().st_mode & 0o777, 0o600)

    def test_hardware_block_prevents_enable(self):
        adapter = Mock()
        with patch.object(n, 'current', return_value=None), patch.object(w, 'device', return_value=('/', {'ActiveConnection': '/'})), patch.object(w, 'radio', return_value={'enabled': False, 'hardwareEnabled': False}):
            with self.assertRaisesRegex(n.Rejected, 'hardware'):
                w.plan(adapter, 'network.wifi.radio', {'interface': 'wlan0', 'enabled': True}, 'admin')

    def test_failed_operation_restores_and_does_not_store_passphrase(self):
        adapter = Mock()
        adapter.manager.CheckpointCreate.return_value = '/checkpoint/1'
        adapter.manager.AddAndActivateConnection2.side_effect = RuntimeError('driver failure')
        states = []
        with patch.object(w, 'plan'), patch.object(w, 'device', return_value=('/device/1', {})), patch.object(w, 'selection', return_value={'password':'private-passphrase'}), patch.object(w, 'radio', return_value={'enabled':True}), patch.object(w, 'remember', side_effect=lambda value: states.append(dict(value))), patch.object(w, 'arm'), patch.object(w, 'disarm'), patch.object(w, 'new_settings'), patch.object(w, 'rollback') as rollback:
            with self.assertRaisesRegex(n.Rejected, 'previous settings were restored'):
                w.execute(adapter, 'network.wifi.connect', {'interface':'wlan0'}, 'admin')
            rollback.assert_called_once()
        self.assertNotIn('private-passphrase', str(states))


class AdapterSwitches(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.config = patch.object(w, 'CONFIG', Path(self.temp.name))
        self.config.start()
        self.addCleanup(self.config.stop)
        self.calls = []
        self.enabled = True
        self.devices = {name: {'DeviceType': 2, 'Interface': name, 'Managed': True, 'State': 30,
                               'ActiveConnection': '/'} for name in ('wlan0', 'wlan1')}
        self.adapter = SimpleNamespace(devices=lambda: list(self.devices), device=lambda name: (name, self.devices[name]),
            dbus=SimpleNamespace(Boolean=bool, DBusException=RuntimeError), manager=SimpleNamespace(Reload=lambda flags: None),
            properties=self.properties, interface=lambda path, _: SimpleNamespace(Set=lambda ns, key, value: self.set(path, key, value)))

    def properties(self, path, interface):
        if path == n.NM_PATH: return {'WirelessEnabled': self.enabled, 'WirelessHardwareEnabled': True}
        if interface.endswith('Wireless'): return {'PermHwAddress': '00:11:22:33:44:0' + path[-1]}
        return self.devices[path]

    def set(self, path, key, value):
        self.calls.append((path, key, value))
        if path == n.NM_PATH: self.enabled = value
        else:
            self.devices[path][key] = value
            self.devices[path]['State'] = 30 if value else 10

    def test_disable_only_target_and_persist_permanent_mac(self):
        with patch.object(w, 'command') as command:
            w.configure(self.adapter, 'wlan0', False)
        self.assertEqual(self.calls, [('wlan0', 'Managed', False)])
        command.assert_called_once_with(['ip', 'link', 'set', 'dev', 'wlan0', 'down'], timeout=10)
        self.assertTrue(w.disabled(self.adapter, 'wlan0'))
        self.assertFalse(w.disabled(self.adapter, 'wlan1'))
        self.assertIn('match-device=mac:00:11:22:33:44:00', w.policy_file(self.adapter, 'wlan0')[0].read_text())
        self.assertFalse(w.adapter_radio(self.adapter, 'wlan0')['enabled'])
        self.assertTrue(w.adapter_radio(self.adapter, 'wlan1')['enabled'])

    def test_enable_from_legacy_global_off_preserves_other_adapter(self):
        self.enabled = False
        before = w.snapshot(self.adapter)
        with patch.object(w, 'command'):
            w.enable(self.adapter, 'wlan0')
            self.assertTrue(w.adapter_radio(self.adapter, 'wlan0')['enabled'])
            self.assertFalse(w.adapter_radio(self.adapter, 'wlan1')['enabled'])
            w.restore_radios(self.adapter, before)
        self.assertEqual(w.snapshot(self.adapter), before)

    def test_enable_disabled_adapter_without_touching_other_adapter(self):
        with patch.object(w, 'command'):
            w.configure(self.adapter, 'wlan0', False)
            self.calls.clear()
            w.enable(self.adapter, 'wlan0')
        self.assertEqual(self.calls, [('wlan0', 'Managed', True)])
        self.assertFalse(w.disabled(self.adapter, 'wlan0'))

    def test_rollback_restores_disabled_policy(self):
        with patch.object(w, 'command'):
            w.configure(self.adapter, 'wlan1', False)
            before = w.snapshot(self.adapter)
            w.enable(self.adapter, 'wlan1')
            w.restore_radios(self.adapter, before)
        self.assertEqual(w.snapshot(self.adapter), before)

    def test_radio_is_allowed_when_another_adapter_is_sharing(self):
        group = {'enabled': True, 'source': 'eth0', 'outputs': ['wlan1']}
        with patch.object(n, 'current', return_value=None), patch.object(n.sharing, 'load', return_value=[group]):
            result = w.plan(self.adapter, 'network.wifi.radio', {'interface': 'wlan0', 'enabled': False}, 'admin')
        self.assertEqual(result['target'], 'wlan0')


if __name__ == '__main__':
    unittest.main()
