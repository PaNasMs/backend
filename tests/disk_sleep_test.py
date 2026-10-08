from pathlib import Path
import sys, tempfile, unittest, json
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "management"))
import disk_sleep, storage
from common import Rejected


class DiskSleepTest(unittest.TestCase):
    def test_busy_partition_member(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "sda/sda1").mkdir(parents=True)
            (root / "sda/sda1/partition").touch()
            (root / "sda1/holders/md0").mkdir(parents=True)
            (root / "md0/md").mkdir(parents=True)
            (root / "md0/md/sync_action").write_text("reshape")
            self.assertEqual(disk_sleep.busy_arrays("sda", root), ["md0"])
            (root / "md0/md/sync_action").write_text("idle")
            self.assertEqual(disk_sleep.busy_arrays("sda", root), [])

    def test_bridge_delegates_policy_to_go(self):
        with patch.object(disk_sleep, "command", return_value='{}') as command:
            disk_sleep.validate(10)
            self.assertEqual(command.call_args.args[0][-2:], ["disk-sleep", "validate"])
            disk_sleep.save(10)
            self.assertEqual(command.call_args.args[0][-2:], ["disk-sleep", "save"])
            self.assertEqual(disk_sleep.query(), {})
            self.assertEqual(command.call_args.args[0][-2:], ["disk-sleep", "query"])


if __name__ == "__main__":
    unittest.main()
