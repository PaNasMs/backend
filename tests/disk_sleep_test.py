from pathlib import Path
import sys, tempfile, unittest, json
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "management"))
import disk_sleep, storage
from common import Rejected


class DiskSleepTest(unittest.TestCase):
    def test_timer_encoding(self):
        for minutes, value in [(0, 0), (5, 60), (20, 240), (30, 241), (60, 242), (300, 250)]:
            self.assertEqual(disk_sleep.timer_value(minutes), value)
        for value in [-1, 1, 25, True, "30", 301]:
            with self.assertRaises(Rejected):
                disk_sleep.timer_value(value)

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

    def test_apply_idle_once_busy_deferred(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = Path(tmp) / "config"
            state = Path(tmp) / "state"
            cfg.write_text('{"minutes":30}')
            inv = {"/dev/test": {"kname": "test", "serial": "serial"}}
            real_read = Path.read_text

            def read(p, *a, **kw):
                return "8:0" if str(p) == "/sys/class/block/test/dev" else real_read(p, *a, **kw)

            with (
                patch.object(disk_sleep, "CONFIG", cfg),
                patch.object(disk_sleep, "STATE", state),
                patch.object(storage, "inventory", return_value=inv),
                patch.object(disk_sleep, "check_disk"),
                patch.object(disk_sleep, "busy_arrays", return_value=["md0"]) as busy,
                patch.object(disk_sleep, "command") as command,
                patch.object(Path, "read_text", read),
            ):
                disk_sleep.apply()
                command.assert_not_called()
                self.assertEqual(json.loads(state.read_text())["serial:8:0"]["status"], "busy")
                busy.return_value = []
                disk_sleep.apply()
                command.assert_called_once_with(["hdparm", "-S", "241", "/dev/test"])
                disk_sleep.apply()
                self.assertEqual(command.call_count, 1)
                cfg.write_text('{"minutes":0}')
                busy.return_value = ["md0"]
                disk_sleep.apply()
                self.assertEqual(command.call_args.args[0], ["hdparm", "-S", "0", "/dev/test"])

    def test_unsupported_media_rejected(self):
        for row in [
            {"type": "disk", "tran": "sata", "rota": False, "serial": "s"},
            {"type": "disk", "tran": "usb", "rota": True, "serial": "s"},
        ]:
            with self.assertRaises(Rejected):
                disk_sleep.check_disk("/dev/test", {"/dev/test": row})


if __name__ == "__main__":
    unittest.main()
