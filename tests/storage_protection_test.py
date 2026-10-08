from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'management'))
import storage
from common import Rejected


class DiskProtectionTest(unittest.TestCase):
    def setUp(self):
        self.inv = {
            '/dev/test': {'kname': 'test', 'type': 'disk', 'mountpoints': [], 'size': 256 * 1048576},
            '/dev/test1': {'kname': 'test1', 'type': 'part', 'parent': '/dev/test', 'mountpoints': []},
        }

    @staticmethod
    def holders(path):
        return iter([Path('/sys/class/block/md127')]) if 'test1' in str(path) else iter([])

    def test_partition_holder_blocks_disk_operations(self):
        for action in ('disk.prepare', 'partition.delete', 'partition.resize'):
            with self.subTest(action=action), patch.object(storage, 'inventory', return_value=self.inv), patch.object(storage, 'protected'), patch.object(Path, 'iterdir', self.holders):
                with self.assertRaisesRegex(Rejected, '/dev/test1.*md127'):
                    storage.plan(action, {'target': '/dev/test' if action in ('disk.prepare','partition.create') else '/dev/test1'})

    def test_execute_rechecks_dependencies_before_writing(self):
        for action in ('disk.prepare',):
            with self.subTest(action=action), patch.object(storage, 'inventory', return_value=self.inv), patch.object(storage, 'protected'), patch.object(Path, 'iterdir', self.holders), patch.object(storage, 'command') as command:
                with self.assertRaises(Rejected):
                    storage.execute_unlocked(action, {'target': '/dev/test'})
                command.assert_not_called()

    def test_layered_descendant_rejected_even_without_holder(self):
        for kind in ('crypt','lvm','raid5'):
            self.inv['/dev/test1']['type'] = kind
            with self.subTest(kind=kind), patch.object(Path, 'iterdir', return_value=iter([])):
                with self.assertRaisesRegex(Rejected, 'another storage layer'):
                    storage.unused('/dev/test', self.inv, True)

    def test_missing_sysfs_fails_closed(self):
        with patch.object(Path, 'iterdir', side_effect=FileNotFoundError):
            with self.assertRaisesRegex(Rejected, 'verify storage dependencies'):
                storage.unused('/dev/test', self.inv, True)

    def test_unused_array_itself_can_be_partitioned(self):
        self.inv = {'/dev/test': {'kname':'test','type':'raid5','mountpoints':[]}}
        with patch.object(Path, 'iterdir', return_value=iter([])):
            storage.unused('/dev/test', self.inv, True)

    def test_existing_table_read_error_never_creates_gpt(self):
        for failure in (Rejected('I/O error'), ValueError('bad json'), OSError('device gone')):
            with self.subTest(error=failure), patch.object(storage,'inventory',return_value=self.inv), patch.object(storage,'protected'), patch.object(storage,'unused'), patch.object(storage,'layout_available'), patch.object(storage,'json_command',return_value={'signatures':[{'type':'gpt'}]}), patch.object(storage,'table',side_effect=failure), patch.object(storage,'command') as command:
                with self.assertRaises(Rejected):
                    storage.execute_unlocked('partition.create',{'target':'/dev/test','startMiB':1,'endMiB':20})
                command.assert_not_called()

    def test_failed_probe_never_creates_gpt(self):
        with patch.object(storage,'json_command',side_effect=Rejected('I/O error')), patch.object(storage,'command') as command:
            with self.assertRaises(Rejected): storage.partition_layout('/dev/test',self.inv)
            command.assert_not_called()

    def test_missing_table_with_kernel_partitions_is_rejected(self):
        with patch.object(storage,'json_command',return_value={'signatures':[]}):
            with self.assertRaisesRegex(Rejected,'inconsistent'): storage.partition_layout('/dev/test',self.inv)

    def test_non_partition_signatures_are_not_overwritten(self):
        for kind in ('ext4','crypto_LUKS','linux_raid_member','LVM2_member','mac'):
            with self.subTest(kind=kind),patch.object(storage,'json_command',return_value={'signatures':[{'type':kind}]}):
                with self.assertRaisesRegex(Rejected,'Existing signatures'): storage.partition_layout('/dev/test',self.inv)

    def test_only_blank_device_gets_new_gpt(self):
        inv={'/dev/test':self.inv['/dev/test']}
        for label in (None, 'gpt', 'dos'):
            layout={'label':label or 'gpt','partitions':[]}
            after={**layout,'partitions':[{'node':'/dev/test1','start':2048,'size':38912}]}
            with self.subTest(label=label), patch.object(storage,'inventory',return_value=inv), patch.object(storage,'plan'), patch.object(storage,'verify_kernel_partition'), patch.object(storage,'checked_layout',return_value=layout if label else None), patch.object(storage,'table',side_effect=[layout,after] if label is None else [after]), patch.object(storage,'command') as command:
                storage.execute_unlocked('partition.create',{'target':'/dev/test','startMiB':1,'endMiB':20})
                labels=[c for c in command.call_args_list if 'mklabel' in c.args[0]]
                self.assertEqual(len(labels), int(label is None))
                self.assertTrue(any(c.args[0] == ['partx','--add','--nr','1','/dev/test'] for c in command.call_args_list))

    def test_layout_ignores_mounted_or_active_sibling_partitions(self):
        self.inv['/dev/test1']['mountpoints'] = ['/']
        with patch.object(storage,'protected'), patch.object(Path,'iterdir',self.holders):
            storage.layout_available('/dev/test',self.inv)

    def test_layout_rejects_active_whole_device(self):
        with patch.object(storage,'protected'), patch.object(Path,'iterdir',return_value=iter([Path('md127')])):
            with self.assertRaisesRegex(Rejected,'storage layer'):
                storage.layout_available('/dev/test',self.inv)

    def test_layout_rejects_stale_kernel_geometry(self):
        self.inv['/dev/test1']['size'] = 1024
        layout={'label':'gpt','partitions':[{'node':'/dev/test1','start':2048,'size':100}]}
        with patch.object(storage,'layout_available'), patch.object(storage,'partition_layout',return_value=layout), patch.object(Path,'read_text',return_value='2048'):
            with self.assertRaisesRegex(Rejected,'inconsistent'):
                storage.checked_layout('/dev/test',self.inv)

    def test_plan_warns_and_fingerprints_partition_table(self):
        inv={'/dev/test':self.inv['/dev/test']}
        params={'target':'/dev/test','startMiB':1,'endMiB':20}
        with patch.object(storage,'inventory',return_value=inv),patch.object(storage,'protected'),patch.object(storage,'unused'), patch.object(storage,'layout_available'),patch.object(Path,'read_text',return_value=''),patch.object(storage,'partition_layout',return_value=None):
            blank=storage.plan('partition.create',params)
        self.assertTrue(any('GPT' in x for x in blank['details']))
        with patch.object(storage,'inventory',return_value=inv),patch.object(storage,'protected'),patch.object(storage,'unused'), patch.object(storage,'layout_available'),patch.object(Path,'read_text',return_value=''),patch.object(storage,'partition_layout',return_value={'label':'gpt','id':'changed'}):
            existing=storage.plan('partition.create',params)
        self.assertNotEqual(blank['fingerprint'],existing['fingerprint'])

    def test_kernel_confirmation_rejects_missing_or_wrong_geometry(self):
        part={'node':'/dev/test1','start':2048,'size':4096}
        with patch.object(Path,'read_text',side_effect=['2048','4000']):
            with self.assertRaisesRegex(Rejected,'kernel has not confirmed'):
                storage.verify_kernel_partition(part,512)
        with patch.object(Path,'read_text',side_effect=FileNotFoundError):
            with self.assertRaises(Rejected): storage.verify_kernel_partition(part,512)
        with patch.object(Path,'read_text',side_effect=['2048','4096']):
            storage.verify_kernel_partition(part,512)

    def test_overlapping_atari_signature_requires_existing_dos_table(self):
        signatures=[{'type':'dos','offset':'0x1fe'},{'type':'atari','offset':'0x1d2'}]
        layout={'label':'dos','partitions':[{'node':'/dev/test1'}]}
        with patch.object(storage,'json_command',return_value={'signatures':signatures}), patch.object(storage,'table',return_value=layout):
            self.assertEqual(storage.partition_layout('/dev/test', self.inv), layout)
            with self.assertRaises(Rejected):
                storage.partition_layout('/dev/test', {'/dev/test':self.inv['/dev/test']})
        for label in ('gpt', 'atari'):
            with patch.object(storage,'json_command',return_value={'signatures':signatures}), patch.object(storage,'table',return_value={**layout,'label':label}):
                with self.assertRaises(Rejected): storage.partition_layout('/dev/test', self.inv)
        signatures[1]['offset']='0x200'
        with patch.object(storage,'json_command',return_value={'signatures':signatures}):
            with self.assertRaises(Rejected): storage.partition_layout('/dev/test', self.inv)
