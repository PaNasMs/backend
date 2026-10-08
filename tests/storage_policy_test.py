import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'management'))
import storage
import common
from types import SimpleNamespace
import storage_luks
import storage_reshape
import json
from common import Rejected


class Policies(unittest.TestCase):
    def test_remove_rejects_storage_containers_and_rechecks_execution(self):
        for kind in ('linux_raid_member', 'crypto_LUKS', 'LVM2_member', 'swap', ''):
            with self.subTest(kind=kind), patch.object(storage, 'protected'), patch.object(storage, 'unused'), patch.object(storage, 'inventory', return_value={'/dev/test': {'fstype': kind}}), patch.object(storage, 'command') as command:
                with self.assertRaises(Rejected):
                    storage.execute_unlocked('filesystem.remove', {'target': '/dev/test'})
                command.assert_not_called()

    def test_fstab_replaces_unavailable_managed_volume_at_same_mountpoint(self):
        old = 'UUID=old /srv/data ext4 rw,nofail,x-systemd.device-timeout=30s 0 0'
        new = 'UUID=new /srv/data ext4 rw,nofail,x-systemd.device-timeout=30s 0 0'
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'fstab'
            path.write_text('# keep\nUUID=root / ext4 defaults 0 1\n' + old + '\n')
            with patch.object(storage, 'Path', return_value=path), patch.object(storage, 'atomic', side_effect=lambda p, text, mode: p.write_text(text)), patch.object(storage, 'command'), patch.object(storage.subprocess, 'run', return_value=SimpleNamespace(returncode=2, stdout='')):
                storage.fstab_change('new', new)
                result = path.read_text()
                self.assertIn('# PaNasMs: superseded unavailable volume: ' + old, result)
                self.assertIn('UUID=root / ext4 defaults 0 1', result)
                self.assertEqual([r for r in result.splitlines() if not r.startswith('#') and '/srv/data' in r], [new])
                storage.fstab_change('new', new)
                self.assertEqual(path.read_text(), result)

    def test_fstab_preserves_available_or_unmanaged_conflicting_volume(self):
        for options, code in [('defaults', 2), ('x-systemd.device-timeout=30s', 0), ('x-systemd.device-timeout=30s', 4)]:
            with self.subTest(options=options, code=code), tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / 'fstab'
                original = f'UUID=old /srv/data ext4 {options} 0 0\n'
                path.write_text(original)
                with patch.object(storage, 'Path', return_value=path), patch.object(storage, 'command'), patch.object(storage.subprocess, 'run', return_value=SimpleNamespace(returncode=code, stdout='')):
                    with self.assertRaises(Rejected):
                        storage.fstab_change('new', 'UUID=new /srv/data ext4 defaults 0 0')
                self.assertEqual(path.read_text(), original)

    def test_parity_conversion_resume_rejects_missing_original_member(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(storage_reshape, 'ROOT', Path(tmp) / 'recovery'):
            storage_reshape.ROOT.mkdir()
            md = Path(tmp) / 'md'
            md.mkdir()
            uuid = '01234567:89abcdef:01234567:89abcdef'
            (md / 'uuid').write_text(uuid)
            (md / 'degraded').write_text('1')
            storage_reshape.backup_path(uuid).with_suffix('.json').write_text(json.dumps({'uuid': uuid, 'members': 4, 'sourceCount': 3}))
            for i in range(4):
                entry = md / f'dev-loop{i}'
                entry.mkdir()
                (entry / 'slot').write_text(str(i))
                (entry / 'state').write_text('in_sync' if i < 3 else 'spare')
                (entry / 'block').mkdir()
            self.assertTrue(storage_reshape.safe_to_resume(md))
            (md / 'dev-loop1/state').write_text('faulty')
            self.assertFalse(storage_reshape.safe_to_resume(md))
            (md / 'dev-loop1/state').write_text('in_sync')
            (md / 'dev-loop1/block').rmdir()
            self.assertFalse(storage_reshape.safe_to_resume(md))

    def test_command_failures_explain_capacity_readonly_and_io(self):
        for error, expected in [('No space left on device', 'full'), ('Read-only file system', 'read-only'), ('Input/output error', 'disconnected')]:
            with self.subTest(error=error), patch.object(common.subprocess, 'run', return_value=SimpleNamespace(returncode=1, stdout='', stderr=error + ' SECRET')):
                with self.assertRaises(Rejected) as caught:
                    common.command(['test-command'])
                self.assertIn(expected, str(caught.exception))
                self.assertNotIn('SECRET', str(caught.exception))

    def test_user_home_blocks_unmount_even_without_open_files(self):
        account = SimpleNamespace(pw_name='alice', pw_dir='/srv/test/home/alice')
        with patch.object(storage, 'mount_targets', return_value={'/srv/test'}), patch.object(storage, 'nfs_exports', return_value=[]), patch.object(storage, 'mounted_rows', return_value=[('/dev/test', '/srv/test')]), patch.object(storage.pwd, 'getpwall', return_value=[account]), patch.object(storage.subprocess, 'run', return_value=SimpleNamespace(returncode=1, stdout='', stderr='')):
            with self.assertRaises(Rejected) as caught:
                storage.mount_blockers('/dev/test', {})
            self.assertIn('alice', str(caught.exception))
            self.assertIn('Move these homes', str(caught.exception))

    def test_mount_policies_and_legacy_clients(self):
        self.assertEqual(storage.mount_policy({'automount': True}), 'boot')
        self.assertEqual(storage.mount_policy({}), 'manual')
        self.assertIn('noauto', storage.mount_options({'mountPolicy': 'manual'}))
        self.assertNotIn('noauto', storage.mount_options({'mountPolicy': 'boot'}))
        self.assertIn('x-systemd.automount', storage.mount_options({'mountPolicy': 'on-demand'}))
        self.assertIn('x-systemd.idle-timeout=10min', storage.mount_options({'mountPolicy': 'on-demand'}))
        with self.assertRaises(Rejected):
            storage.mount_policy({'mountPolicy': 'sometimes'})

    def test_crypttab_preserves_unmanaged_entries_and_rejects_collision(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(storage_luks, 'CRYPTTAB', Path(tmp) / 'crypttab'):
            path = storage_luks.CRYPTTAB
            path.write_text('# custom\nother UUID=other none luks\n')
            original = path.read_text()
            self.assertTrue(storage_luks.crypttab('test', 'data').startswith(original))
            with self.assertRaises(Rejected):
                storage_luks.crypttab('test', 'other')
            with self.assertRaises(Rejected):
                storage_luks.crypttab('other', 'data')
            path.write_text(storage_luks.crypttab('test', 'data'))
            self.assertEqual(storage_luks.crypttab('test'), original)

    def test_key_revocation_requires_other_slot_password(self):
        with patch.object(storage_luks, 'verify', side_effect=Rejected('wrong password')) as verify:
            with self.assertRaises(Rejected):
                storage_luks.authorize_other_slot('/dev/test', 'secret', [0, 1, 2], 1)
            self.assertEqual([c.args[2] for c in verify.call_args_list], [0, 2])

    def test_symlink_header_folder_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'link').symlink_to(root, target_is_directory=True)
            with self.assertRaises(Rejected):
                storage_luks.header_path({'folder': str(root / 'link')}, 'uuid')

if __name__ == '__main__':
    unittest.main()
