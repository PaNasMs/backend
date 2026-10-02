from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'management'))
import common

class ReviewClosureTest(unittest.TestCase):
    def test_nested_secrets_do_not_enter_plan_fingerprint(self):
        a={'wifi': {'wlan0': {'ssid': 'home', 'password': 'one'}}, 'accounts': [{'clientSecret': 'one'}]}
        b={'wifi': {'wlan0': {'ssid': 'home', 'password': 'two'}}, 'accounts': [{'clientSecret': 'two'}]}
        self.assertEqual(common.fingerprint('share', a, {}), common.fingerprint('share', b, {}))
        b['wifi']['wlan0']['ssid']='changed'
        self.assertNotEqual(common.fingerprint('share', a, {}), common.fingerprint('share', b, {}))
