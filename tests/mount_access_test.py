import os, sys, tempfile, unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "management"))
import storage


class MountAccessTest(unittest.TestCase):
    def test_portable_filesystem_owner_and_parent_permissions(self):
        with tempfile.TemporaryDirectory() as tmp:
            point = Path(tmp) / "usb" / "volume"
            previous = os.umask(0o007)
            try:
                with (
                    patch.object(
                        storage, "inventory", return_value={"/dev/test": {"uuid": "test", "fstype": "vfat"}}
                    ),
                    patch.object(storage, "mountpoint", return_value=point),
                    patch.object(storage, "fstab_change"),
                    patch.object(storage, "command") as command,
                    patch.object(
                        storage.pwd, "getpwnam", return_value=SimpleNamespace(pw_uid=1000, pw_gid=1000)
                    ),
                ):
                    storage.execute_unlocked(
                        "mount.attach", {"target": "/dev/test", "point": str(point)}, "test"
                    )
                    options = next(c.args[0][2] for c in command.call_args_list if c.args[0][0] == "mount")
                    self.assertIn("uid=1000,gid=1000,fmask=0177,dmask=0077", options)
                    self.assertEqual(point.parent.stat().st_mode & 0o777, 0o755)
            finally:
                os.umask(previous)


if __name__ == "__main__":
    unittest.main()
