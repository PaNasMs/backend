from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'management'))
import network as n


class NetworkValidation(unittest.TestCase):

    def test_system_interfaces_use_kernel_topology_not_only_names(self):
        for name in ('lo', 'docker0', 'br-0123456789ab', 'veth1234'):
            self.assertTrue(n.system_interface(name))
        for resolved, wireless, expected in (
            ('/sys/devices/virtual/net/custom-bridge', False, True),
            ('/sys/devices/virtual/net/wlan0', True, False),
            ('/sys/devices/pci0000:00/virtio0/net/ens18', False, False),
            ('/sys/devices/platform/usb/net/enx123', False, False),
        ):
            with self.subTest(resolved=resolved), patch.object(Path, 'resolve', return_value=Path(resolved)), patch.object(Path, 'exists', return_value=wireless):
                self.assertEqual(n.system_interface('custom-name'), expected)


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


if __name__ == '__main__':
    unittest.main()
