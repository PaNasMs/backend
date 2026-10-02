from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'management'))
import common
import module_manager

class ReviewClosureTest(unittest.TestCase):
    def test_nested_secrets_do_not_enter_plan_fingerprint(self):
        a={'wifi': {'wlan0': {'ssid': 'home', 'password': 'one'}}, 'accounts': [{'clientSecret': 'one'}]}
        b={'wifi': {'wlan0': {'ssid': 'home', 'password': 'two'}}, 'accounts': [{'clientSecret': 'two'}]}
        self.assertEqual(common.fingerprint('share', a, {}), common.fingerprint('share', b, {}))
        b['wifi']['wlan0']['ssid']='changed'
        self.assertNotEqual(common.fingerprint('share', a, {}), common.fingerprint('share', b, {}))

    def test_module_compatibility_uses_package_version(self):
        expected=(Path(__file__).resolve().parents[1] / 'VERSION').read_text().strip()
        self.assertEqual(module_manager.CORE, expected)
        self.assertTrue(module_manager.satisfies(module_manager.CORE, '>=' + expected))
