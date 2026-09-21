import sys
from pathlib import Path
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'management'))
import folder_locations as locations
from common import Rejected


class FolderLocationsTest(unittest.TestCase):
    def state(self, *, number='9:127', fstype='ext4', options='rw', persistent=True, removable=False):
        return ([{'target': '/', 'fstype': 'ext4', 'options': 'rw', 'maj:min': '179:2'},
                 {'target': '/srv/data', 'fstype': fstype, 'options': options, 'maj:min': number}],
                [{'target': '/srv/data', 'options': 'defaults' if persistent else 'noauto'}],
                {'179:2', '9:127'}, {number} if removable else set())

    def test_permanent_local_raid_and_system_home_are_allowed(self):
        self.assertEqual(locations.home_volume(Path('/srv/data/homes'), self.state())['target'], '/srv/data')
        self.assertEqual(locations.home_volume(Path('/home'), self.state())['target'], '/')

    def test_usb_readonly_network_unmounted_and_nonpersistent_are_rejected(self):
        for state in (self.state(removable=True), self.state(options='ro'), self.state(fstype='nfs'), self.state(persistent=False), self.state(number='8:123')):
            with self.subTest(state=state), self.assertRaises(Rejected):
                locations.home_volume(Path('/srv/data/homes'), state)
        with self.assertRaisesRegex(Rejected, 'unavailable'):
            locations.home_volume(Path('/srv/missing/homes'), self.state())

    def test_usb_and_removable_ancestry_including_one_raid_member(self):
        responses = [ {'filesystems': []}, {'filesystems': []}, {'blockdevices': [
            {'name': 'sda', 'maj:min': '8:0', 'type': 'disk', 'rm': False, 'tran': 'sata', 'children': [
                {'name': 'md0', 'maj:min': '9:0', 'type': 'raid1'}]},
            {'name': 'sdb', 'maj:min': '8:16', 'type': 'disk', 'rm': False, 'tran': 'usb', 'children': [
                {'name': 'sdb1', 'maj:min': '8:17', 'type': 'part', 'children': [
                    {'name': 'md0', 'maj:min': '9:0', 'type': 'raid1'}]}]},
            {'name': 'mmcblk1', 'maj:min': '179:8', 'type': 'disk', 'rm': True, 'children': [
                {'name': 'mmcblk1p1', 'maj:min': '179:9', 'type': 'part'}]},
        ]} ]
        with patch.object(locations, 'json_command', side_effect=responses):
            _, _, local, removable = locations.inventory()
        self.assertIn('8:0', local)
        self.assertNotIn('8:0', removable)
        self.assertTrue({'8:16', '8:17', '9:0', '179:8', '179:9'} <= removable)

    def test_nested_network_mount_cannot_inherit_parent_raid_permission(self):
        state = self.state()
        state[0].append({'target': '/srv/data/remote', 'fstype': 'cifs', 'options': 'rw', 'maj:min': '0:77'})
        with self.assertRaisesRegex(Rejected, 'local Linux'):
            locations.home_volume(Path('/srv/data/remote/homes'), state)
        self.assertEqual(locations.home_volume(Path('/srv/data/remote-other'), state)['target'], '/srv/data')

    def test_missing_parent_is_rejected_before_copy(self):
        with self.assertRaisesRegex(Rejected, 'parent folder'):
            locations.destination(Path('/nonexistent-home-policy-test/homes'))

if __name__ == '__main__':
    unittest.main()
