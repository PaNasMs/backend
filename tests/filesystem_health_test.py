import sys
sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[2] / "modules/files/backend"))
import sys, unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "management"))
import storage
import filesystem_health as health


class RecoveryTest(unittest.TestCase):
    def setUp(self):
        self.inv = {"/dev/test": {"fstype": "vfat", "uuid": "test", "ro": False}}
        self.p = {"target": "/dev/test", "point": "/mnt/test", "mode": "auto"}
        self.patches = [
            patch.object(storage, "inventory", return_value=self.inv),
            patch.object(storage, "mounted_rows", return_value=[]),
            patch.object(storage, "unused"),
            patch.object(storage, "mount_blockers"),
            patch.object(storage, "command"),
            patch.object(storage, "execute_unlocked"),
            patch.object(health, "repair_available", return_value=True),
            patch.object(health, "mounted_read_only", return_value=False),
            patch.object(health, "check", return_value=(False, "Errors found")),
            patch.object(health, "save_state"),
        ]
        self.mocks = [p.start() for p in self.patches]
        self.addCleanup(lambda: [p.stop() for p in reversed(self.patches)])

    def run_open(self):
        return storage.open_filesystem("/dev/test", self.p, "pasha", self.inv)

    def test_errors_require_choice_and_no_mount(self):
        self.assertTrue(self.run_open()["needsChoice"])
        self.mocks[5].assert_not_called()
        self.mocks[8].assert_called_once_with("/dev/test", "vfat", repair=False)

    def test_readonly_bypasses_repair(self):
        self.p["mode"] = "readonly"
        self.assertEqual(self.run_open()["point"], "/mnt/test")
        self.mocks[8].assert_not_called()
        self.assertTrue(self.mocks[5].call_args.args[1]["readOnly"])

    def test_repair_unmounts_then_checks_and_mounts(self):
        self.p["mode"] = "repair"
        self.mocks[1].return_value = [("/dev/test", "/mnt/test")]
        self.mocks[8].return_value = (True, "")
        events = []
        self.mocks[4].side_effect = lambda args: events.append(args[0])
        self.mocks[8].side_effect = lambda *a, **kw: (events.append("repair") or (True, ""))
        self.mocks[5].side_effect = lambda *a: events.append("mount")
        self.assertEqual(self.run_open()["point"], "/mnt/test")
        self.assertEqual(events, ["umount", "repair", "mount"])

    def test_discovery_repair_keeps_volume_unmounted(self):
        self.p["mode"] = "repair-only"
        self.mocks[8].return_value = (True, "")
        self.assertTrue(self.run_open()["repaired"])
        self.mocks[5].assert_not_called()

    def test_failed_repair_does_not_mount(self):
        self.p["mode"] = "repair"
        self.assertTrue(self.run_open()["needsChoice"])
        self.mocks[5].assert_not_called()

    def test_busy_volume_is_not_unmounted_or_repaired(self):
        self.p["mode"] = "repair"
        self.mocks[3].side_effect = storage.Rejected("Том занят: test (PID 42)")
        with self.assertRaisesRegex(storage.Rejected, "PID 42"):
            self.run_open()
        self.mocks[4].assert_not_called()
        self.mocks[8].assert_not_called()

    def test_already_readonly_requires_choice(self):
        self.mocks[1].return_value = [("/dev/test", "/mnt/test")]
        self.mocks[7].return_value = True
        self.assertTrue(self.run_open()["needsChoice"])
        self.mocks[8].assert_not_called()

    def test_unavailable_checker_disables_repair(self):
        self.mocks[6].return_value = False
        self.assertFalse(self.run_open()["repairAvailable"])
        self.mocks[5].assert_not_called()


class CheckerTest(unittest.TestCase):
    def test_repair_requires_clean_second_pass(self):
        with (
            patch.object(health, "repair_available", return_value=True),
            patch.object(
                health.subprocess,
                "run",
                side_effect=[SimpleNamespace(returncode=1), SimpleNamespace(returncode=4)],
            ) as run,
        ):
            self.assertFalse(health.check("/dev/test", "ext4", True)[0])
            self.assertEqual(run.call_args_list[0].args[0], ["e2fsck", "-p", "/dev/test"])
            self.assertEqual(run.call_args_list[1].args[0], ["e2fsck", "-f", "-n", "/dev/test"])

    def test_fat_no_modify_flag(self):
        with (
            patch.object(health, "repair_available", return_value=True),
            patch.object(health.subprocess, "run", return_value=SimpleNamespace(returncode=1)) as run,
        ):
            self.assertFalse(health.check("/dev/test", "vfat")[0])
            self.assertEqual(run.call_args.args[0], ["fsck.fat", "-n", "/dev/test"])


class DiscoveryTest(unittest.TestCase):
    def test_detection_is_readonly_and_skips_mounted_volumes(self):
        from contextlib import nullcontext

        with (
            patch.object(health, "device_lock", return_value=nullcontext()),
            patch.object(
                storage,
                "inventory",
                return_value={"/dev/sde1": {"tran": "usb", "fstype": "vfat", "ro": False}},
            ),
            patch.object(storage, "protected"),
            patch.object(storage, "unused"),
            patch.object(storage, "mounted_rows", return_value=[]),
            patch.object(health, "cached", return_value=None),
            patch.object(health, "repair_available", return_value=True),
            patch.object(health, "save_state") as save,
            patch.object(health, "check", return_value=(False, "FAT errors")) as check,
            patch.object(health.subprocess, "run"),
        ):
            health.inspect_added("sde1")
            check.assert_called_once_with("/dev/sde1", "vfat")
            self.assertEqual(save.call_args.args, ("/dev/sde1", "errors", "FAT errors", True))
        with (
            patch.object(health, "device_lock", return_value=nullcontext()),
            patch.object(storage, "inventory", return_value={"/dev/sde1": {"tran": "usb", "fstype": "vfat"}}),
            patch.object(storage, "protected"),
            patch.object(storage, "mounted_rows", return_value=[("/dev/sde1", "/mnt/test")]),
            patch.object(health, "check") as check,
        ):
            health.inspect_added("sde1")
            check.assert_not_called()


if __name__ == "__main__":
    unittest.main()
