import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "management"))
import storage


class CreateArray(unittest.TestCase):
    def test_new_array_is_cleared_of_signatures_left_by_a_deleted_array(self):
        with tempfile.TemporaryDirectory() as folder:
            conf = Path(folder) / "mdadm.conf"
            conf.write_text("")
            calls = []

            def command(argv, **kwargs):
                calls.append(argv)
                return "ARRAY /dev/md/data UUID=1\n"

            redirect = lambda *parts: conf if parts == ("/etc/mdadm/mdadm.conf",) else Path(*parts)
            with patch.object(storage, "inventory", return_value={}), \
                 patch.object(storage, "device", side_effect=lambda value, inv: value), \
                 patch.object(storage, "command", side_effect=command), \
                 patch.object(storage, "Path", side_effect=redirect), \
                 patch.object(storage, "atomic", side_effect=lambda path, text, mode: path.write_text(text)):
                storage.execute_unlocked(
                    "raid.create", {"name": "data", "level": "1", "members": ["/dev/sdb", "/dev/sdc"]}
                )
            names = [argv[0] + (" --create" if "--create" in argv else "") for argv in calls]
            self.assertEqual(names[:3], ["mdadm --create", "udevadm", "wipefs"])
            self.assertEqual(calls[2], ["wipefs", "--all", "--", "/dev/md/data"])
            self.assertIn("ARRAY /dev/md/data", conf.read_text())

    def test_growth_capacity_uses_kibibyte_component_size(self):
        # Three 16 GiB members in RAID5 hold about 32 GiB; a fourth makes it about 48 GiB.
        growth = {"raid_disks": "3", "level": "raid5", "component_size": "16759808"}
        self.assertEqual(storage.growth_capacity(growth), (32734, 49101))
        growth = {"raid_disks": "4", "level": "raid6", "component_size": "16759808"}
        self.assertEqual(storage.growth_capacity(growth), (32734, 49101))


if __name__ == "__main__":
    unittest.main()
