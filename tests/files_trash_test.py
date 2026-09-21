import sys
sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[2] / "modules/files/backend"))
import os, sys, tempfile, unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "management"))
import files


class FilesTrashTest(unittest.TestCase):
    def test_maximum_utf8_name_and_duplicate_names_restore(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            name = "я" * 125 + "a.pdf"
            target = root / name
            self.assertEqual(len(os.fsencode(name)), 255)
            with patch.object(files, "roots", return_value=[tmp, "/"]), patch.object(files, "drop"):
                paths = []
                for content in ("first", "second"):
                    target.write_text(content)
                    result = files.execute("file.trash", {"target": str(target)}, "test")
                    saved = Path(result["path"])
                    self.assertFalse(target.exists())
                    self.assertEqual(saved.name, name)
                    self.assertEqual(saved.read_text(), content)
                    paths.append(saved)
                self.assertNotEqual(*paths)
                files.execute("file.restore", {"target": str(paths[0]), "destination": str(target)}, "test")
                self.assertEqual(target.read_text(), "first")
                self.assertEqual(paths[1].read_text(), "second")

    def test_combined_trash_lists_original_names_from_all_roots(self):
        with tempfile.TemporaryDirectory() as tmp:
            roots = [str(Path(tmp) / "home"), str(Path(tmp) / "disk")]
            for root in roots:
                Path(root).mkdir()
            with (
                patch.object(files, "roots", return_value=roots),
                patch.object(files, "drop"),
                patch.object(files, "identity") as identity,
            ):
                identity.return_value.pw_dir = roots[0]
                paths = []
                for root in roots:
                    target = Path(root) / "same.txt"
                    target.write_text(root)
                    paths.append(files.execute("file.trash", {"target": str(target)}, "test")["path"])
                legacy = Path(roots[0]) / (".panasms-trash-" + str(os.getuid())) / "123-old.txt"
                legacy.write_text("legacy")
                listing = files.query("test", "trash:")
                self.assertEqual([p["name"] for p in listing["places"] if p["kind"] == "trash"], ["Trash"])
                self.assertEqual(
                    sorted(e["name"] for e in listing["entries"]), ["old.txt", "same.txt", "same.txt"]
                )
                self.assertTrue(set(paths).issubset({e["path"] for e in listing["entries"]}))


class FilesPlacesTest(unittest.TestCase):
    def test_missing_block_device_is_not_a_place_but_network_mount_remains(self):
        rows = [
            {"target": "/mnt/usb/gone", "source": "/dev/sde1", "fstype": "vfat", "maj:min": "8:65"},
            {"target": "/mnt/live", "source": "/dev/sdf1", "fstype": "vfat", "maj:min": "8:81"},
            {"target": "/mnt/network", "source": "server:/share", "fstype": "nfs", "maj:min": "0:42"},
        ]
        with (
            patch.object(files, "identity") as user,
            patch.object(files, "json_command", return_value={"filesystems": rows}),
            patch.object(Path, "exists", lambda p: str(p) == "/sys/dev/block/8:81"),
        ):
            user.return_value.pw_dir = "/home/test"
            self.assertEqual(set(files.roots("test")), {"/", "/home/test", "/mnt/live", "/mnt/network"})

    def test_mount_name_uses_disk_model_and_distinguishes_partitions(self):
        device = {
            "name": "sde",
            "model": " USB DISK ",
            "children": [{"name": "sde1", "mountpoints": ["/mnt/usb/1234-5678"]}],
        }
        with patch.object(files, "json_command", return_value={"blockdevices": [device]}):
            self.assertEqual(files.mount_names()["/mnt/usb/1234-5678"], "USB DISK")
            device["children"].append({"name": "sde2", "label": "Photos", "mountpoints": ["/mnt/photos"]})
            self.assertEqual(files.mount_names()["/mnt/usb/1234-5678"], "USB DISK · sde1")
            self.assertEqual(files.mount_names()["/mnt/photos"], "USB DISK · Photos")

    def test_raid_name_overrides_member_model_and_is_inherited_by_partitions(self):
        raid = {"name": "md127", "path": "/dev/md127", "type": "raid5", "mountpoints": ["/srv/array"],
                "children": [{"name": "md127p1", "type": "part", "mountpoints": ["/srv/data"]}]}
        disks = [{"name": "sda", "model": "First disk", "children": [raid]},
                 {"name": "sdb", "model": "Second disk", "children": [raid]}]
        with tempfile.TemporaryDirectory() as tmp:
            alias = Path(tmp) / "storage"
            alias.symlink_to("/dev/md127")
            with patch.object(Path, "glob", return_value=[alias]), patch.object(files, "json_command", return_value={"blockdevices": disks}):
                self.assertEqual(files.mount_names(), {"/srv/array": "storage", "/srv/data": "storage"})
            with patch.object(Path, "glob", return_value=[]), patch.object(files, "json_command", return_value={"blockdevices": disks}):
                self.assertEqual(files.mount_names()["/srv/array"], "md127")

    def test_network_mounts_are_distinguished_from_local_volumes(self):
        mounts = [{"target": "/srv/video", "fstype": "nfs4"},
                  {"target": "/srv/share", "fstype": "cifs"},
                  {"target": "/srv/local", "fstype": "ext4"}]
        with (patch.object(files, "roots", return_value=[m["target"] for m in mounts]),
              patch.object(files, "json_command", return_value={"filesystems": mounts}),
              patch.object(files, "mount_names", return_value={}),
              patch.object(files, "drop"), patch.object(files, "identity") as user,
              patch.object(files.os, "access", return_value=False)):
            user.return_value.pw_dir = "/home/test"
            places = {p["path"]: p for p in files.query("test", None)["places"]}
            self.assertTrue(places["/srv/video"]["network"])
            self.assertTrue(places["/srv/share"]["network"])
            self.assertNotIn("network", places["/srv/local"])

    def test_inaccessible_mount_stays_visible_without_reading_contents(self):
        with (
            patch.object(files, "roots", return_value=["/mnt/usb/locked", "/"]),
            patch.object(files, "drop"),
            patch.object(files, "identity") as identity,
            patch.object(files.os, "access", return_value=False),
        ):
            identity.return_value.pw_dir = "/home/test"
            listing = files.query("test", None)
            self.assertIn("/mnt/usb/locked", listing["roots"])
            self.assertIn({"path": "/mnt/usb/locked", "name": "locked", "kind": "device"}, listing["places"])
            self.assertEqual(listing["trashRoots"], [])
            with self.assertRaisesRegex(files.Rejected, "Permission denied to view this folder"):
                files.query("test", "/mnt/usb/locked")


class FolderPermissionsTest(unittest.TestCase):
    def test_created_folder_respects_process_umask(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(files, "roots", return_value=[tmp]), patch.object(files, "drop"):
                for mask, expected in [(0o022, 0o755), (0o007, 0o770), (0o077, 0o700)]:
                    target = Path(tmp) / str(mask)
                    previous = os.umask(mask)
                    try:
                        files.execute("file.mkdir", {"target": str(target)}, "test")
                    finally:
                        os.umask(previous)
                    self.assertEqual(target.stat().st_mode & 0o777, expected)

    def test_created_folder_inherits_default_acl_and_setgid(self):
        import subprocess
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            parent.chmod(0o2770)
            subprocess.run(["setfacl", "-m", "d:u::rwx,d:g::rwx,d:m::rwx,d:o::---", tmp], check=True)
            target = parent / "shared"
            previous = os.umask(0o077)
            try:
                with patch.object(files, "roots", return_value=[tmp]), patch.object(files, "drop"):
                    files.execute("file.mkdir", {"target": str(target)}, "test")
            finally:
                os.umask(previous)
            self.assertEqual(target.stat().st_mode & 0o2777, 0o2770)
            self.assertEqual(target.stat().st_gid, parent.stat().st_gid)
            acl = subprocess.check_output(["getfacl", "-cp", str(target)], text=True)
            self.assertIn("group::rwx", acl)
            self.assertIn("default:group::rwx", acl)


class AdministratorPermissionsTest(unittest.TestCase):
    def temporary_data(self):
        # CI checkouts under /__w are deliberately outside the permitted data roots.
        parent = Path(__file__).resolve().parents[1]
        if not str(parent).startswith('/home/'):
            parent = Path('/home') if os.geteuid() == 0 else Path.home()
        return tempfile.TemporaryDirectory(dir=parent)

    def test_non_admin_cannot_read_plan_or_apply_permissions(self):
        from types import SimpleNamespace
        with patch.object(files, "identity", return_value=SimpleNamespace(pw_uid=1000, pw_gid=1000)), patch.object(files.grp, "getgrnam", return_value=SimpleNamespace(gr_gid=27)), patch.object(files.os, "getgrouplist", return_value=[1000]):
            for call in [lambda: files.query("ordinary", 'permissions-selection:["/srv/data"]'), lambda: files.permission_plan({"items": []}, "ordinary"), lambda: files.permission_apply({"items": []}, "ordinary"), lambda: files.query("ordinary", "permissions:/srv/data"), lambda: files.plan("file.permissions", {"target":"/srv/data"}, "ordinary"), lambda: files.execute("file.permissions", {"target":"/srv/data"}, "ordinary")]:
                with self.assertRaisesRegex(files.Rejected, "Administrator"):
                    call()

    def test_current_folder_only_and_stale_revision(self):
        import subprocess
        with self.temporary_data() as tmp:
            parent = Path(tmp)
            child = parent / "unchanged"
            child.mkdir(mode=0o700)
            subprocess.run(["setfacl", "-m", "d:u::rwx,d:g::rwx,d:m::rwx,d:o::---", tmp], check=True)
            acl_before = subprocess.check_output(["getfacl", "-dcp", tmp], text=True)
            with patch.object(files, "permission_admin"), patch.object(files, "json_command", return_value={"filesystems":[{"fstype":"ext4"}]}):
                info = files.query("admin", "permissions:"+tmp)
                params = {"target":tmp,"owner":str(os.getuid()),"group":str(os.getgid()),"mode":"2770","revision":info["revision"]}
                files.plan("file.permissions", params, "admin")
                files.execute("file.permissions", params, "admin")
                self.assertEqual(parent.stat().st_mode & 0o2777, 0o2770)
                self.assertEqual(child.stat().st_mode & 0o777, 0o700)
                self.assertEqual(subprocess.check_output(["getfacl", "-dcp", tmp], text=True), acl_before)
                with self.assertRaisesRegex(files.Rejected, "changed"):
                    files.execute("file.permissions", params, "admin")

    def test_batch_files_and_folders_preserve_unchanged_bits_and_preflight(self):
        with self.temporary_data() as tmp:
            folder = Path(tmp) / "folder"
            folder.mkdir(mode=0o750)
            file = Path(tmp) / "file"
            file.write_text("test")
            file.chmod(0o640)
            with patch.object(files, "permission_admin"), patch.object(files, "json_command", return_value={"filesystems":[{"fstype":"ext4"}]}):
                data = files.permission_selection("admin", [str(folder), str(file)])
                self.assertIn("users", data)
                params = {"items": [{"target": i["target"], "revision": i["revision"]} for i in data["items"]], "mask": 0o2020, "bits": 0o2020}
                files.permission_plan(params, "admin")
                file.chmod(0o600)
                with self.assertRaisesRegex(files.Rejected, "changed"):
                    files.permission_apply(params, "admin")
                self.assertEqual(folder.stat().st_mode & 0o7777, 0o750)
                data = files.permission_selection("admin", [str(folder), str(file)])
                params["items"] = [{"target": i["target"], "revision": i["revision"]} for i in data["items"]]
                files.permission_apply(params, "admin")
                self.assertEqual(folder.stat().st_mode & 0o7777, 0o2770)
                self.assertEqual(file.stat().st_mode & 0o7777, 0o620)
                link = Path(tmp) / "link"
                link.symlink_to(file)
                with self.assertRaisesRegex(files.Rejected, "symbolic link"):
                    files.permission_selection("admin", [str(link)])

    def test_rejects_system_paths_symlinks_and_network_filesystems(self):
        with self.temporary_data() as tmp:
            link = Path(tmp) / "link"
            link.symlink_to(tmp, target_is_directory=True)
            with patch.object(files, "permission_admin"):
                with self.assertRaisesRegex(files.Rejected, "protected"):
                    files.permission_info("admin", "/etc")
                with self.assertRaisesRegex(files.Rejected, "symbolic link"):
                    files.permission_info("admin", str(link))
                with patch.object(files, "json_command", return_value={"filesystems":[{"fstype":"nfs"}]}):
                    with self.assertRaisesRegex(files.Rejected, "local Linux"):
                        files.permission_info("admin", tmp)


if __name__ == "__main__":
    unittest.main()
