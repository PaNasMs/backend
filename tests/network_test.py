from pathlib import Path
import copy
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'management'))
import network as n


class NetworkValidation(unittest.TestCase):
    def setUp(self):
        self.config = {key: {'method': 'auto', 'addresses': [], 'dns': [], 'gateway': '',
                            'ignoreAutoDns': False, 'neverDefault': False, 'metric': -1, 'routes': []}
                       for key in ('ipv4', 'ipv6')}
        self.config['mtu'] = 0

    def test_static_address_requires_family_and_prefix(self):
        self.config['ipv4']['method'] = 'manual'
        for values in ([], ['192.0.2.1'], ['::1/64'], ['224.0.0.1/24']):
            self.config['ipv4']['addresses'] = values
            with self.subTest(values=values), self.assertRaises(n.Rejected):
                n.validate(self.config)
        self.config['ipv4']['addresses'] = ['192.0.2.1/24']
        self.assertEqual(n.validate(self.config), self.config)

    def test_invalid_routes_rejected(self):
        for value in (None, 123, 'bad', '192.0.2.3/24', '::/0', '192.0.2.0'):
            self.config['ipv4']['routes'] = [{'destination': value, 'gateway': '', 'metric': -1}]
            with self.subTest(value=value), self.assertRaises(n.Rejected):
                n.validate(self.config)

    def test_local_only_cannot_install_default_route(self):
        self.config['ipv4']['neverDefault'] = True
        self.config['ipv4']['routes'] = [{'destination': '0.0.0.0/0', 'gateway': '192.0.2.1'}]
        with self.assertRaises(n.Rejected):
            n.validate(self.config)

    def test_ipv6_mtu_and_disabled_protocols(self):
        self.config['mtu'] = 1200
        with self.assertRaises(n.Rejected):
            n.validate(self.config)
        self.config['ipv6']['method'] = 'disabled'
        self.assertEqual(n.validate(self.config)['mtu'], 1200)
        self.config['ipv4']['method'] = 'disabled'
        with self.assertRaises(n.Rejected):
            n.validate(self.config)

    def test_advanced_attributes_are_readonly(self):
        for section, data in [('address-data', {'address': '192.0.2.1', 'prefix': 24, 'label': 'alias'}),
                              ('route-data', {'dest': '192.0.2.0', 'prefix': 24, 'table': 50})]:
            self.assertFalse(n.editable({'ipv4': {section: [data]}}))

    def test_fingerprint_detects_external_change_but_not_timestamp(self):
        settings = {'connection': {'uuid': 'test', 'timestamp': 1}, 'ipv4': {'method': 'auto'}}
        original = n.signature(settings)
        settings['connection']['timestamp'] = 2
        self.assertEqual(original, n.signature(settings))
        settings['ipv4']['method'] = 'disabled'
        self.assertNotEqual(original, n.signature(settings))

    def test_dns_rejects_command_injection_and_wrong_family(self):
        for value in ['192.0.2.1;reboot', '::1', '0.0.0.0']:
            self.config['ipv4']['dns'] = [value]
            with self.assertRaises(n.Rejected):
                n.validate(self.config)


if __name__ == '__main__':
    unittest.main()
