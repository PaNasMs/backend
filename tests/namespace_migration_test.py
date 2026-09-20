import importlib.util
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location(
    "namespace_migration", Path(__file__).resolve().parents[1] / "scripts/migrate-ostojaos.py"
)
migration = importlib.util.module_from_spec(spec)
spec.loader.exec_module(migration)


class NamespaceMigrationTest(unittest.TestCase):
    def test_removal_hook_is_backed_up_without_network_cleanup(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            backup = root / 'backup'
            backup.mkdir()
            hook = root / 'ostojaos-prototype.prerm'
            original = b'#!/bin/sh\nsystemctl stop NetworkManager\n'
            hook.write_bytes(original)
            hook.chmod(0o755)
            migration.disable_cleanup('ostojaos', backup, root)
            self.assertEqual((backup / hook.name).read_bytes(), original)
            self.assertEqual((backup / hook.name).stat().st_mode & 0o777, 0o755)
            import subprocess
            subprocess.run(['sh', str(hook), 'remove'], check=True)

    def test_state_move_preserves_owner_permissions_and_payload(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source, target = root / 'ostojaos', root / 'panasms'
            source.mkdir(mode=0o700)
            data = source / 'credentials'
            data.write_bytes(b'opaque credential with ostojaos in its value')
            data.chmod(0o600)
            before = data.stat()
            migration.move(source, target)
            after = (target / data.name).stat()
            self.assertEqual((after.st_uid, after.st_gid, after.st_mode),
                             (before.st_uid, before.st_gid, before.st_mode))
            self.assertEqual((target / data.name).read_bytes(), b'opaque credential with ostojaos in its value')
            with self.assertRaises(RuntimeError):
                migration.move(target, target)
