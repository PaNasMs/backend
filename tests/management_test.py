import importlib
from pathlib import Path
import sys
import tempfile
import unittest
import subprocess
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "management"))
import storage, accounts, host
from common import Rejected


class StorageSafety(unittest.TestCase):
    def test_saved_smart_schedule(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            serial = "test-disk"
            self.assertIsNone(storage.smart_schedule(serial, root))
            unit = "ostojaos-smart-" + storage.hashlib.sha256(serial.encode()).hexdigest()[:16]
            (root / (unit + ".timer")).write_text("[Timer]\nOnCalendar=Sun *-*-* 03:00:00\n")
            (root / (unit + ".service")).write_text(
                "[Service]\nExecStart=/usr/sbin/smartctl -t long /dev/disk/by-id/ata-test\n"
            )
            self.assertEqual(storage.smart_schedule(serial, root), {"test": "long", "weekday": 6, "hour": 3})
            (root / (unit + ".timer")).write_text("OnCalendar=invalid\n")
            self.assertIsNone(storage.smart_schedule(serial, root))

    def test_media_metadata_without_smart_probes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sd = root / "mmcblk0"
            (sd / "device").mkdir(parents=True)
            (sd / "ro").write_text("0")
            (sd / "device/type").write_text("SD")
            (sd / "device/name").write_text("EE4S5")
            (sd / "device/date").write_text("04/2024")
            info = storage.media_info({"kname": "mmcblk0", "tran": "mmc"}, root)
            self.assertEqual(info["kind"], "sd")
            self.assertEqual(info["manufactured"], "04/2024")
            self.assertFalse(info["readOnly"])
            usb = root / "sde"
            (usb / "device").mkdir(parents=True)
            (usb / "removable").write_text("1")
            (usb / "ro").write_text("1")
            for key, value in {
                "idVendor": "090c",
                "idProduct": "2000",
                "speed": "480",
                "version": "2.00",
                "product": "Flash Disk",
            }.items():
                (usb / "device" / key).write_text(value)
            info = storage.media_info({"kname": "sde", "tran": "usb", "model": "Flash Disk"}, root)
            self.assertEqual(info["kind"], "usb-flash")
            self.assertEqual(info["linkMbps"], "480")
            self.assertTrue(info["readOnly"])
            (usb / "device/product").write_text("SanDisk 3.2Gen1")
            self.assertEqual(
                storage.media_info({"kname": "sde", "tran": "usb", "model": "SanDisk 3.2Gen1"}, root)["kind"],
                "usb-flash",
            )
            (usb / "removable").write_text("0")
            (usb / "device/product").write_text("External SSD")
            self.assertEqual(
                storage.media_info({"kname": "sde", "tran": "usb", "model": "External SSD"}, root)["kind"],
                "usb",
            )

    def test_mount_rejects_occupied_default_point(self):
        inv = {
            "/dev/test1": {
                "type": "part",
                "parent": None,
                "mountpoints": [],
                "ro": False,
                "fstype": "ext4",
                "uuid": "test-uuid",
            }
        }
        with tempfile.TemporaryDirectory() as tmp:
            point = Path(tmp) / "test-uuid"
            params = {"target": "/dev/test1", "point": str(point), "automount": False}
            with (
                patch.object(storage, "inventory", return_value=inv),
                patch.object(storage, "device", return_value="/dev/test1"),
                patch.object(storage, "mountpoint", return_value=point),
            ):
                with patch.object(storage, "mount_targets", return_value={str(point)}):
                    with self.assertRaisesRegex(Rejected, "used by another volume"):
                        storage.plan("mount.attach", params)
                with patch.object(storage, "mount_targets", return_value=set()):
                    self.assertIn(str(point), storage.plan("mount.attach", params)["details"])

    def test_growth_preconditions(self):
        with tempfile.TemporaryDirectory() as tmp:
            md = Path(tmp)
            values = {
                "level": "raid5",
                "raid_disks": "3",
                "degraded": "0",
                "sync_action": "idle",
                "reshape_position": "none",
                "metadata_version": "1.2",
                "component_size": "1024",
            }
            for key, value in values.items():
                (md / key).write_text(value)
            for i in range(3):
                member = md / ("dev-loop" + str(i))
                member.mkdir()
                (member / "state").write_text("in_sync")
                (member / "slot").write_text(str(i))
            self.assertEqual(storage.growth_state(md)["raid_disks"], "3")
            for key, bad in [
                ("level", "raid0"),
                ("metadata_version", "external:imsm"),
                ("degraded", "1"),
                ("sync_action", "recover"),
                ("reshape_position", "100"),
            ]:
                (md / key).write_text(bad)
                with self.assertRaises(Rejected):
                    storage.growth_state(md)
                (md / key).write_text(values[key])
            (md / "dev-loop2/state").write_text("spare")
            with self.assertRaises(Rejected):
                storage.growth_state(md)

    def test_raid_names(self):
        for value in ("Storage", "RAID0", "1data", "nas-data", "_array"):
            self.assertEqual(storage.raid_name(value), value)
        for value in ("", "../disk", "a/b", "-array", "with space", "Массив", "a" * 32):
            with self.assertRaises(Rejected):
                storage.raid_name(value)

    def test_raid0_plan_and_raid5_minimum(self):
        inv = {
            p: {
                "path": p,
                "kname": Path(p).name,
                "type": "loop",
                "size": 256 * 1048576,
                "parent": None,
                "mountpoints": [],
                "ro": False,
            }
            for p in ("/dev/loop90", "/dev/loop91")
        }
        with (
            patch.object(storage, "inventory", return_value=inv),
            patch.object(storage, "protected"),
            patch.object(storage, "unused"),
        ):
            plan = storage.plan("raid.create", {"name": "Test_RAID0", "level": "0", "members": list(inv)})
            self.assertTrue(any("a disk failure" in detail for detail in plan["details"]))
            with self.assertRaisesRegex(Rejected, "Not enough members"):
                storage.plan("raid.create", {"name": "Test_RAID5", "level": "5", "members": list(inv)})

    def test_raid_candidates_exclude_unsafe_and_small_devices(self):
        inv = {
            path: {"path": path, "kname": Path(path).name, "type": kind, "size": size, "fstype": fs}
            for path, kind, size, fs in [
                ("/dev/mdtest", "raid1", 100, None),
                ("/dev/member", "disk", 100, "linux_raid_member"),
                ("/dev/small", "disk", 50, None),
                ("/dev/system", "part", 100, None),
                ("/dev/busy", "disk", 100, None),
                ("/dev/free", "disk", 100, None),
                ("/dev/formatted", "disk", 100, "ext4"),
            ]
        }

        def protected(path, _):
            if path == "/dev/system":
                raise Rejected("system")

        def unused(path, _):
            if path == "/dev/busy":
                raise Rejected("busy")

        with (
            patch.object(storage, "inventory", return_value=inv),
            patch.object(storage.Path, "is_dir", return_value=True),
            patch.object(storage.Path, "iterdir", return_value=iter([Path("/dev/member")])),
            patch.object(storage, "protected", side_effect=protected),
            patch.object(storage, "unused", side_effect=unused),
        ):
            result = storage.query("raid-candidates", "/dev/mdtest")
        self.assertEqual([d["path"] for d in result["devices"]], ["/dev/free"])

    def test_mount_error_lists_all_blockers_and_remedies(self):
        inv = {"/dev/md1": {"mountpoints": ["/srv/data"], "parent": None}}
        with (
            patch.object(storage, "mount_targets", return_value={"/srv/data", "/srv/data/nested"}),
            patch.object(storage, "nfs_exports", return_value=["/srv/data/shared"]),
            patch.object(storage, "process_label", return_value="bash (PID 123, пользователь pasha)"),
            patch.object(
                storage.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "123", "")
            ),
        ):
            with self.assertRaises(Rejected) as result:
                storage.mount_blockers("/dev/md1", inv)
            message = str(result.exception)
            for detail in (
                "/srv/data",
                "bash",
                "PID 123",
                "pasha",
                "/srv/data/nested",
                "/srv/data/shared",
                "Unmount",
                "Remove",
                "has not started",
            ):
                self.assertIn(detail, message)

    def test_free_mount_passes_and_failed_probe_is_not_free(self):
        inv = {"/dev/md1": {"mountpoints": ["/srv/data"], "parent": None}}
        with (
            patch.object(storage, "mount_targets", return_value={"/srv/data"}),
            patch.object(storage, "nfs_exports", return_value=[]),
            patch.object(storage.subprocess, "run") as run,
        ):
            run.return_value = subprocess.CompletedProcess([], 1, "", "")
            storage.mount_blockers("/dev/md1", inv)
            run.return_value = subprocess.CompletedProcess([], 1, "", "Permission denied")
            with self.assertRaisesRegex(Rejected, "Could not check"):
                storage.mount_blockers("/dev/md1", inv)

    def test_md_uuid_formats_match_and_other_arrays_survive(self):
        target = "ARRAY /dev/md/test UUID=160a1d5a:7403709f:a5c1d3fc:012db5cb"
        other = "ARRAY /dev/md/storage UUID=c645ae9f:e44fbe7a:5a5c53b9:a7244d40"
        result = storage.without_array(target + "\n" + other + "\n", "160a1d5a-7403-709f-a5c1-d3fc012db5cb")
        self.assertEqual(result, other + "\n")

    def setUp(self):
        self.inv = {
            "/dev/system": {"type": "disk", "parent": None, "mountpoints": [], "ro": False},
            "/dev/system1": {"type": "part", "parent": "/dev/system", "mountpoints": ["/"], "ro": False},
            "/dev/data": {"type": "disk", "parent": None, "mountpoints": [], "ro": False},
        }

    def test_system_disk_and_siblings_protected(self):
        for dev in ("/dev/system", "/dev/system1"):
            with self.assertRaises(Rejected):
                storage.protected(dev, self.inv)
        storage.protected("/dev/data", self.inv)

    def test_mounted_and_layered_device_rejected(self):
        with self.assertRaises(Rejected):
            storage.unused("/dev/system", self.inv)
        self.inv["/dev/data"]["mountpoints"] = ["/srv/data"]
        with self.assertRaises(Rejected):
            storage.unused("/dev/data", self.inv)

    def test_mount_paths_cannot_escape(self):
        for path in ("/", "/boot", "/etc", "/srv/../etc", "/srv/hello\nworld"):
            with self.assertRaises(Rejected):
                storage.mountpoint(path)

    def test_duplicate_raid_members_rejected(self):
        with patch.object(storage, "inventory", return_value=self.inv):
            with self.assertRaises(Rejected):
                storage.plan(
                    "raid.create", {"name": "test", "level": "1", "members": ["/dev/data", "/dev/data"]}
                )

    def test_unsupported_action(self):
        with self.assertRaises(Rejected):
            storage.plan("shell.execute", {})

    def test_missing_device_rejected(self):
        with self.assertRaises(Rejected):
            storage.device("/dev/missing", self.inv)

    def test_service_core_protected(self):
        for unit in ("ostojaos-core.service", "ssh.service", "../../root.service", "dbus.service"):
            with self.assertRaises(Rejected):
                host.service(unit)

    def test_system_account_protected(self):
        import pwd

        with self.assertRaises(Rejected):
            accounts.normal(pwd.getpwnam("root"))

    def test_stale_plan_never_executes(self):
        import main

        with (
            patch.object(main.os, "getgrouplist", return_value=[main.grp.getgrnam("sudo").gr_gid]),
            patch.object(main.pwd, "getpwnam") as user,
            patch.object(storage, "plan", return_value={"fingerprint": "fresh", "confirmation": "disk"}),
            patch.object(storage, "execute") as execute,
        ):
            user.return_value.pw_uid = 1000
            with self.assertRaises(Rejected):
                main.dispatch(
                    "execute",
                    "test",
                    {"action": "raid.delete", "params": {}, "fingerprint": "stale", "confirmation": "disk"},
                )
            execute.assert_not_called()

    def test_confirmation_never_skipped(self):
        import main

        with (
            patch.object(main.os, "getgrouplist", return_value=[main.grp.getgrnam("sudo").gr_gid]),
            patch.object(main.pwd, "getpwnam") as user,
            patch.object(storage, "plan", return_value={"fingerprint": "fresh", "confirmation": "disk"}),
            patch.object(storage, "execute") as execute,
        ):
            user.return_value.pw_uid = 1000
            with self.assertRaises(Rejected):
                main.dispatch(
                    "execute",
                    "test",
                    {"action": "raid.delete", "params": {}, "fingerprint": "fresh", "confirmation": "other"},
                )
            execute.assert_not_called()


if __name__ == "__main__":
    unittest.main()
