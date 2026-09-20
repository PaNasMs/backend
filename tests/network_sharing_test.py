from pathlib import Path
import sys
import unittest
from unittest.mock import patch, Mock
from contextlib import ExitStack
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'management'))
import network_sharing as s

class SharingTests(unittest.TestCase):
    def test_explicit_channel_must_be_permitted_for_selected_band(self):
        self.assertEqual(s.selected_channel({}, [36, 44]), 36)
        self.assertEqual(s.selected_channel({'channel': 44}, [36, 44]), 44)
        for value in (34, 1, -1, True, '36'):
            with self.subTest(value=value), self.assertRaises(s.Rejected):
                s.selected_channel({'channel': value}, [36, 44])

    def test_wifi_edit_changes_only_selected_ap_parameters(self):
        old = {'id': 'group', 'source': 'eth0', 'outputs': ['wlan0', 'wlan1'], 'enabled': False,
               'wifi': {'wlan0': {'ssid': 'first', 'band': 'a', 'channel': 36}, 'wlan1': {'ssid': 'second', 'band': 'bg', 'channel': 1}}}
        params = {'interface': 'wlan0', 'wifi': {'ssid': 'new', 'band': 'a', 'channel': 44, 'password': ''}, 'source': 'evil'}
        result = s.wifi_params(params, old)
        self.assertEqual(result['source'], 'eth0')
        self.assertEqual(result['wifi']['wlan1'], old['wifi']['wlan1'])
        self.assertEqual(result['wifi']['wlan0']['ssid'], 'new')
        self.assertEqual(old['wifi']['wlan0']['ssid'], 'first')
        self.assertFalse(result['enabled'])
        with self.assertRaises(s.Rejected): s.wifi_params({**params, 'interface': 'eth0'}, old)

    def test_editing_stopped_access_point_does_not_start_sharing(self):
        old = {'id': 'group', 'name': 'Test', 'source': 'eth0', 'outputs': ['wlan0'], 'enabled': False,
               'profiles': {}, 'wifi': {'wlan0': {'ssid': 'first', 'band': 'a', 'channel': 36}}}
        adapter = Mock()
        adapter.device.return_value = ('/device', {'DeviceType': 1})
        with patch.object(s, 'plan'), patch.object(s, 'load', return_value=[old]), patch.object(s, 'review', return_value=(old, [])), patch.object(s, 'original', return_value={}), patch.object(s.n.wifi, 'snapshot', return_value={}), patch.object(s, 'remember'), patch.object(s, 'command'), patch.object(s, 'build', return_value={**old, 'enabled': True}), patch.object(s, 'profiles', return_value={}), patch.object(s, 'store') as store, patch.object(s, 'activate') as activate:
            s.execute(adapter, 'network.share.wifi', {'id': 'group', 'interface': 'wlan0', 'wifi': {'ssid': 'changed'}}, 'admin')
        activate.assert_not_called()
        self.assertFalse(store.call_args.args[0][0]['enabled'])

    def test_ap_channels_exclude_nonprimary_forbidden_and_radar(self):
        info = """* 2484 MHz [14] (20 dBm)
* 2412 MHz [1] (20 dBm)
* 5170 MHz [34] (20 dBm)
* 5180 MHz [36] (20 dBm)
* 5190 MHz [38] (20 dBm)
* 5200 MHz [40] (disabled)
* 5220 MHz [44] (no IR)
* 5260 MHz [52] (radar detection)
* 5745 MHz [149] (20 dBm)
* 5975 MHz [5] (20 dBm)"""
        self.assertEqual(s.ap_channels(info), {'bg': [1], 'a': [36, 149]})

    def test_subnets_avoid_existing_routes_and_groups(self):
        with patch.object(s, 'json_command', return_value=[{'dst':'10.42.0.0/16'}, {'dst':'default'}]):
            self.assertEqual(s.choose_subnet([{'subnet':'10.43.0.0/24'}]), '10.44.0.0/24')

    def test_reject_duplicate_and_source_destinations(self):
        for outputs in ([], ['eth0'], ['eth1', 'eth1']):
            with self.subTest(outputs=outputs), self.assertRaises(s.Rejected):
                s.review(None, {'source':'eth0', 'outputs':outputs})

    def test_never_share_an_interface_across_groups(self):
        with patch.object(s, 'load', return_value=[{'id':'existing','source':'eth0','outputs':['eth1']}]), self.assertRaises(s.Rejected):
            s.review(None, {'source':'wlan0','outputs':['eth1']})

    def test_saved_subnet_ignores_own_bridge_but_rejects_new_overlap(self):
        class Adapter:
            def device(self, name):
                return name, {'Managed': True, 'DeviceType': 1, 'State': 100, 'ActiveConnection': '/'}
        old = {'id': 'group', 'name': 'Test', 'source': 'eth0', 'outputs': ['eth1'],
               'mode': 'nat', 'enabled': True, 'autostart': True, 'wifi': {},
               'bridge': 'osbrtest', 'subnet': '10.42.0.0/24', 'identities': {'eth0':'eth0','eth1':'eth1'}}
        for dev, allowed in [('osbrtest', True), ('eth2', False)]:
            with self.subTest(dev=dev), patch.object(s, 'load', return_value=[old]), patch.object(s, 'matches_adapter', return_value=True), patch.object(s, 'profiles', return_value={}), patch.object(s, 'capabilities', side_effect=lambda a,name,p: {'identity':name,'phy':''}), patch.object(s.shutil, 'which', return_value='/bin/tool'), patch.object(s, 'json_command', side_effect=lambda args: [{'dst':'10.42.0.0/24','dev':dev}] if 'route' in args else []):
                if allowed:
                    self.assertEqual(s.review(Adapter(), old, old)[0]['mode'], 'nat')
                else:
                    with self.assertRaises(s.Rejected): s.review(Adapter(), old, old)

    def test_routing_has_terminal_unreachable_and_explicit_uplink(self):
        commands=[]
        route_calls=iter([[], [{'dst':'192.0.2.0/24', 'dev':'wlan0'}, {'dst':'default','gateway':'192.0.2.1','dev':'wlan0'}], []])
        with patch.object(s, 'json_command', side_effect=lambda args:next(route_calls)), patch.object(s, 'command', side_effect=lambda args, **kw:commands.append(args)):
            s.routing({'mode':'nat','slot':3,'bridge':'osbrtest','source':'wlan0'})
        self.assertIn(['ip','-4','route','replace','unreachable','default','metric','42760','table','28003'], commands)
        self.assertIn(['ip','-4','rule','add','priority','18003','iif','osbrtest','lookup','28003'], commands)
        self.assertTrue(any('via' in c and '192.0.2.1' in c and 'wlan0' in c for c in commands))

    def test_rule_collision_fails_closed(self):
        with patch.object(s, 'json_command', return_value=[{'priority':18000,'table':999,'iif':'other'}]), self.assertRaises(s.Rejected):
            s.routing({'mode':'nat','slot':0,'bridge':'osbrtest','source':'wlan0'})

class ActivationTests(unittest.TestCase):
    def run_wait(self, bridge_ready, wifi_ready, failure=None):
        elapsed = [0.0]
        class Adapter:
            def device(self, name):
                state = 120 if name == failure else 100 if elapsed[0] >= (bridge_ready if name == 'osbrtest' else wifi_ready) else 70
                return name, {'State': state}
        def sleep(seconds): elapsed[0] += seconds
        with patch.object(s.time, 'monotonic', side_effect=lambda: elapsed[0]), patch.object(s.time, 'sleep', side_effect=sleep):
            s.wait_active(Adapter(), {'bridge': 'osbrtest', 'outputs': ['wlan0', 'wlan1'], 'wifi': {'wlan0': {}, 'wlan1': {}}})
        return elapsed[0]

    def test_bridge_stp_then_dhcp_can_exceed_old_thirty_second_limit(self):
        self.assertEqual(self.run_wait(76, 4), 76)

    def test_waits_for_both_access_points(self):
        self.assertEqual(self.run_wait(1, 8), 8)

    def test_bridge_timeout_identifies_waiting_component(self):
        with self.assertRaisesRegex(s.Rejected, 'bridge osbrtest to obtain network settings'):
            self.run_wait(100, 2)

    def test_wifi_timeout_identifies_waiting_interfaces(self):
        with self.assertRaisesRegex(s.Rejected, 'access points wlan0, wlan1'):
            self.run_wait(1, 100)

    def test_disconnected_access_point_fails_early_after_startup_grace(self):
        class Adapter:
            def device(self, name): return name, {'State': 100 if name == 'br' else 30}
        elapsed = [0.0]
        def sleep(seconds): elapsed[0] += seconds
        with patch.object(s.time, 'monotonic', side_effect=lambda: elapsed[0]), patch.object(s.time, 'sleep', side_effect=sleep):
            with self.assertRaisesRegex(s.Rejected, 'failed for wlan0'):
                s.wait_active(Adapter(), {'bridge': 'br', 'outputs': ['wlan0'], 'wifi': {'wlan0': {}}})
        self.assertEqual(elapsed[0], 5)

    def test_failed_bridge_does_not_wait_until_timeout(self):
        with self.assertRaisesRegex(s.Rejected, 'failed for osbrtest'):
            self.run_wait(1, 1, 'osbrtest')


class PortLifecycleTests(unittest.TestCase):
    def group(self):
        return {'id': 'group', 'source': 'eth0', 'outputs': ['wlan0', 'wlan1'], 'mode': 'bridge',
                'bridge': 'bridge', 'enabled': True, 'wifi': {'wlan0': {}, 'wlan1': {}},
                'profiles': {'bridge': 'bridge-id', 'eth0': 'source-id', 'wlan0': 'ap0', 'wlan1': 'ap1'},
                'identities': {'eth0': 'source', 'wlan0': 'usb0', 'wlan1': 'usb1'},
                'previous': {'eth0': 'original', 'wlan0': None, 'wlan1': None}}

    def adapter(self):
        a = Mock()
        a.dbus.DBusException = type('DBusError', (Exception,), {})
        a.device.side_effect = lambda name: (name, {'State': 100, 'DeviceType': 2 if name.startswith('wlan') else 1, 'Managed': True, 'ActiveConnection': '/'})
        a.properties.side_effect = lambda path, iface: {'ActiveConnections': ['bridge-id', 'source-id', 'ap0']} if path == s.n.NM_PATH else {'Uuid': path}
        return a

    def test_removal_only_drops_selected_port_and_its_configuration(self):
        old = self.group()
        new = s.without_port(old, 'wlan1')
        self.assertEqual(new['outputs'], ['wlan0'])
        for key in ('wifi', 'profiles', 'identities', 'previous'):
            self.assertNotIn('wlan1', new[key])
            self.assertIn('wlan1', old[key])
        self.assertEqual(new['profiles']['bridge'], old['profiles']['bridge'])
        with self.assertRaises(s.Rejected): s.without_port(old, 'eth0')

    def test_returned_adapter_only_activates_its_own_profile(self):
        a = self.adapter()
        saved = {v: ('profile-' + v, {}) for v in self.group()['profiles'].values()}
        with patch.object(s, 'profiles', return_value=saved), patch.object(s, 'matches_adapter', return_value=True), patch.object(s.n.wifi, 'disabled', return_value=False), patch.object(s.n.wifi, 'adapter_radio', return_value={'enabled': True, 'hardwareEnabled': True}):
            s.activate(a, self.group(), allow_missing=True)
        a.manager.ActivateConnection.assert_called_once_with('profile-ap1', 'wlan1', '/')

    def test_missing_disabled_or_replaced_adapter_does_not_restart_peers(self):
        for reason in ('missing', 'disabled', 'replaced'):
            with self.subTest(reason=reason):
                a = self.adapter()
                if reason == 'missing':
                    original = a.device.side_effect
                    def device(name):
                        if name == 'wlan1': raise a.dbus.DBusException()
                        return original(name)
                    a.device.side_effect = device
                saved = {v: ('profile-' + v, {}) for v in self.group()['profiles'].values()}
                with patch.object(s, 'profiles', return_value=saved), patch.object(s, 'matches_adapter', side_effect=lambda adapter,g,name,saved: reason != 'replaced' or name != 'wlan1'), patch.object(s.n.wifi, 'disabled', side_effect=lambda adapter,name: reason == 'disabled' and name == 'wlan1'), patch.object(s.n.wifi, 'adapter_radio', return_value={'enabled': True, 'hardwareEnabled': True}):
                    s.activate(a, self.group(), allow_missing=True)
                a.manager.ActivateConnection.assert_not_called()

    def test_identity_uses_saved_mac_not_usb_socket(self):
        a = self.adapter()
        a.properties.return_value = {'PermHwAddress': 'aa:bb:cc:dd:ee:ff'}
        a.properties.side_effect = None
        saved = {'ap1': ('profile', {'connection': {'type': '802-11-wireless'}, '802-11-wireless': {'mac-address': bytes.fromhex('aabbccddeeff')}})}
        self.assertTrue(s.matches_adapter(a, self.group(), 'wlan1', saved))
        a.properties.return_value = {'PermHwAddress': '00:11:22:33:44:55'}
        self.assertFalse(s.matches_adapter(a, self.group(), 'wlan1', saved))

    def test_absent_port_can_be_removed_without_device_commands(self):
        a = self.adapter()
        a.device.side_effect = a.dbus.DBusException()
        with patch.object(s, 'command') as command, patch.object(s, 'restore') as restore:
            s.detach_port(a, self.group(), 'wlan1')
        command.assert_not_called()
        restore.assert_not_called()

    def test_detach_ap_switches_to_managed_and_restores_original_connection(self):
        a = self.adapter()
        with patch.object(s, 'matches_adapter', return_value=True), patch.object(s, 'profiles', return_value={}), patch.object(s.n.wifi, 'disabled', return_value=False), patch.object(s, 'command') as command, patch.object(s, 'restore') as restore:
            s.detach_port(a, self.group(), 'wlan1')
        self.assertIn((['iw', 'dev', 'wlan1', 'set', 'type', 'managed'],), [c.args for c in command.call_args_list])
        restore.assert_called_once_with(a, {'wlan1': None})

    def test_remove_disconnected_port_does_not_reactivate_whole_group(self):
        a = self.adapter()
        old = self.group()
        with ExitStack() as stack:
            for name in ('plan', 'remember', 'command', 'store', 'detach_port', 'confirm'):
                stack.enter_context(patch.object(s, name))
            stack.enter_context(patch.object(s, 'load', return_value=[old]))
            stack.enter_context(patch.object(s, 'original', return_value={}))
            stack.enter_context(patch.object(s, 'profiles', return_value={}))
            stack.enter_context(patch.object(s.n.wifi, 'snapshot', return_value={}))
            activate = stack.enter_context(patch.object(s, 'activate'))
            deactivate = stack.enter_context(patch.object(s, 'deactivate'))
            result = s.execute(a, 'network.share.remove-port', {'id': 'group', 'interface': 'wlan1'}, 'admin')
            activate.assert_not_called()
            deactivate.assert_not_called()
            self.assertEqual(result['message'], 'Sharing recipient removed')

if __name__ == '__main__': unittest.main()
