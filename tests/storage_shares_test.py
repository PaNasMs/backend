import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "management"))
import sharing
import storage
from common import Rejected

TARGET = "/dev/md9"
POINT = "/srv/md9"


def share(name, path, smb=True, nfs=False):
    return {
        "name": name, "path": path, "smb": smb, "nfs": nfs, "readers": ["alice"], "writers": [],
        "clients": ["192.168.1.0/24"] if nfs else [], "readOnly": False, "mountpoint": POINT, "volume": "uuid",
    }


class DeleteArrayWithShares(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        for key in ("STATE", "SMB", "EXPORTS", "JOURNAL", "LOCK"):
            self.start(patch.object(sharing, key, root / key))
        self.start(patch.object(sharing, "atomic", side_effect=lambda p, s, mode=0o600: p.write_text(s)))
        self.start(patch.object(sharing, "validate_config"))
        self.reload = self.start(patch.object(sharing, "reload_services"))
        self.start(patch.object(sharing.shutil, "which", return_value="/usr/bin/tool"))
        self.commands = []
        self.start(patch.object(sharing, "command", side_effect=lambda argv, **_: self.commands.append(argv) or ""))
        md = root / "sys/class/block/md9/md"
        md.mkdir(parents=True)
        (md.parent / "slaves").mkdir()
        for member in ("sda", "sdb"):
            (md.parent / "slaves" / member).touch()
        (md / "reshape_position").write_text("none\n")
        (md / "sync_action").write_text("idle\n")
        (md / "uuid").write_text("uuid\n")
        (root / "etc").mkdir()
        (root / "etc/fstab").write_text("")
        self.inv = {
            TARGET: {"kname": "md9", "type": "raid1", "mountpoints": [POINT], "parent": None},
            "/dev/sda": {"kname": "sda", "type": "disk", "mountpoints": [], "parent": None},
            "/dev/sdb": {"kname": "sdb", "type": "disk", "mountpoints": [], "parent": None},
        }
        real = Path

        def path(*parts):
            value = real(*parts)
            return real(str(root) + str(value)) if str(value).startswith(("/sys/", "/etc/fstab")) else value

        self.start(patch.object(storage, "Path", side_effect=path))
        self.start(patch.object(storage, "inventory", return_value=self.inv))
        self.start(patch.object(storage, "protected"))
        self.start(patch.object(storage, "mount_targets", return_value={POINT}))
        self.start(patch.object(storage.pwd, "getpwall", return_value=[]))
        self.etab = self.start(patch.object(storage, "etab_exports", return_value=set()))
        self.fuser = self.start(
            patch.object(storage.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, "", ""))
        )

    def start(self, patcher):
        self.addCleanup(patcher.stop)
        return patcher.start()

    def publish(self, *shares):
        state = {"shares": list(shares), "accounts": {}}
        sharing.STATE.write_text(json.dumps(state))
        smb, nfs = sharing.config(state["shares"])
        sharing.SMB.write_text(smb)
        sharing.EXPORTS.write_text(nfs)
        self.etab.return_value = {s["path"] for s in shares if s["nfs"]}

    def test_shared_folder_blocks_delete_without_the_option(self):
        self.publish(share("c05share", POINT + "/c05share"))
        for params in ({"target": TARGET}, {"target": TARGET, "removeShares": False}):
            with self.assertRaises(Rejected) as caught:
                storage.plan("raid.delete", params)
            message = str(caught.exception)
            self.assertIn("Operation on /dev/md9 has not started.", message)
            self.assertIn("Shared folders on this volume: c05share (/srv/md9/c05share).", message)
            self.assertIn("Also stop sharing folders on this array", message)
            self.assertNotIn("via NFS", message)
        with self.assertRaisesRegex(Rejected, "Choose whether"):
            storage.plan("raid.delete", {"target": TARGET, "removeShares": "yes"})

    def test_other_operations_do_not_offer_the_delete_dialog_option(self):
        self.publish(share("c05share", POINT + "/c05share"))
        with self.assertRaises(Rejected) as caught:
            storage.mount_blockers(TARGET, self.inv)
        self.assertIn("c05share (/srv/md9/c05share). Remove their shares in Shared folders first.", str(caught.exception))
        self.assertNotIn("delete dialog", str(caught.exception))

    def test_option_allows_delete_and_details_list_removed_shares(self):
        self.publish(
            share("c05share", POINT + "/c05share"),
            share("media", POINT + "/media", smb=False, nfs=True),
            share("elsewhere", "/srv/other/docs"),
        )
        plan = storage.plan("raid.delete", {"target": TARGET, "removeShares": True})
        self.assertIn("Sharing will be removed: c05share (/srv/md9/c05share)", plan["details"])
        self.assertIn("Sharing will be removed: media (/srv/md9/media)", plan["details"])
        self.assertFalse(any("elsewhere" in detail for detail in plan["details"]))
        self.assertEqual(plan["confirmation"], TARGET)
        # The reviewed plan is bound to the exact set of shares it listed.
        self.publish(share("c05share", POINT + "/c05share"), share("elsewhere", "/srv/other/docs"))
        changed = storage.plan("raid.delete", {"target": TARGET, "removeShares": True})
        self.assertNotEqual(plan["fingerprint"], changed["fingerprint"])

    def test_option_without_shares_changes_nothing_else(self):
        plan = storage.plan("raid.delete", {"target": TARGET, "removeShares": True})
        self.assertFalse(any("Sharing will be removed" in detail for detail in plan["details"]))

    def test_foreign_export_still_blocks_with_the_option(self):
        self.publish(share("c05share", POINT + "/c05share"))
        self.etab.return_value = {POINT + "/legacy"}
        with self.assertRaises(Rejected) as caught:
            storage.plan("raid.delete", {"target": TARGET, "removeShares": True})
        message = str(caught.exception)
        self.assertIn("Folders shared via NFS: /srv/md9/legacy.", message)
        self.assertNotIn("c05share", message)
        # A foreign export of a folder that the panel shares only over SMB is still foreign.
        self.etab.return_value = {POINT + "/c05share"}
        with self.assertRaisesRegex(Rejected, "Folders shared via NFS: /srv/md9/c05share"):
            storage.plan("raid.delete", {"target": TARGET, "removeShares": True})

    def test_other_blockers_still_block_with_the_option(self):
        self.publish(share("c05share", POINT + "/c05share"))
        self.fuser.return_value = subprocess.CompletedProcess([], 0, "123", "")
        with patch.object(storage, "process_label", return_value="bash (PID 123, user pasha)"):
            with self.assertRaisesRegex(Rejected, "is busy: bash"):
                storage.plan("raid.delete", {"target": TARGET, "removeShares": True})

    def test_smb_server_does_not_block_the_plan_when_its_shares_will_be_removed(self):
        self.publish(share("c05share", POINT + "/c05share"))
        self.fuser.return_value = subprocess.CompletedProcess([], 0, "123 124", "")
        with patch.object(storage, "process_name", return_value="smbd"):
            plan = storage.plan("raid.delete", {"target": TARGET, "removeShares": True})
            self.assertIn("Sharing will be removed: c05share (/srv/md9/c05share)", plan["details"])
            # Without the option the connected client is still reported.
            with patch.object(storage, "process_label", return_value="smbd (PID 123, user root)"):
                with self.assertRaisesRegex(Rejected, "is busy: smbd"):
                    storage.mount_blockers(TARGET, self.inv)
        # Another process next to smbd keeps blocking and is the only one named.
        names = {123: "smbd", 124: "bash"}
        with (
            patch.object(storage, "process_name", side_effect=names.get),
            patch.object(storage, "process_label", side_effect=lambda pid: f"{names[pid]} (PID {pid})"),
        ):
            with self.assertRaises(Rejected) as caught:
                storage.plan("raid.delete", {"target": TARGET, "removeShares": True})
        self.assertIn("is busy: bash (PID 124).", str(caught.exception))
        self.assertNotIn("smbd", str(caught.exception))

    def test_smb_server_blocks_the_plan_without_a_panel_smb_share_on_the_volume(self):
        self.fuser.return_value = subprocess.CompletedProcess([], 0, "123", "")
        for shares in ([], [share("media", POINT + "/media", smb=False, nfs=True)], [share("elsewhere", "/srv/other/docs")]):
            self.publish(*shares)
            with (
                patch.object(storage, "process_name", return_value="smbd"),
                patch.object(storage, "process_label", return_value="smbd (PID 123, user root)"),
            ):
                with self.assertRaisesRegex(Rejected, "is busy: smbd"):
                    storage.plan("raid.delete", {"target": TARGET, "removeShares": True})

    def test_execution_checks_smb_server_strictly_after_closing_shares(self):
        self.publish(share("c05share", POINT + "/c05share"))
        self.fuser.return_value = subprocess.CompletedProcess([], 0, "123", "")
        with (
            patch.object(storage, "process_name", return_value="smbd"),
            patch.object(storage, "process_label", return_value="smbd (PID 123, user root)"),
            patch.object(storage, "command") as command,
        ):
            with self.assertRaisesRegex(Rejected, "is busy: smbd"):
                storage.execute("raid.delete", {"target": TARGET, "removeShares": True})
        command.assert_not_called()
        self.assertEqual(sharing.read()["shares"], [])

    def test_review_names_a_mapped_volume_by_its_mapper_path(self):
        inv = {
            "/dev/dm-0": {"kname": "dm-0", "name": "e03secure", "type": "crypt"},
            "/dev/sde": {"kname": "sde", "name": "sde", "type": "disk"},
        }
        self.assertEqual(storage.friendly_path("/dev/dm-0", inv), "/dev/mapper/e03secure")
        self.assertEqual(storage.friendly_path("/dev/sde", inv), "/dev/sde")
        self.assertEqual(storage.friendly_path("New file system: ext4", inv), "New file system: ext4")
        self.inv["/dev/dm-0"] = {
            "kname": "dm-0", "name": "e03secure", "type": "crypt", "fstype": "ext4",
            "mountpoints": ["/srv/secure"], "parent": None,
        }
        with patch.object(storage, "mount_targets", return_value={"/srv/secure"}), patch.object(storage, "mountpoint"):
            plan = storage.plan("mount.detach", {"target": "/dev/dm-0"})
        self.assertEqual(plan["details"][0], "/dev/mapper/e03secure")
        self.assertEqual(plan["target"], "/dev/dm-0")
        self.assertEqual(plan["confirmation"], "/dev/dm-0")

    def test_interrupted_or_edited_sharing_configuration_blocks_the_plan(self):
        self.publish(share("c05share", POINT + "/c05share"))
        sharing.SMB.write_text("edited")
        with self.assertRaisesRegex(Rejected, "edited outside the panel"):
            storage.plan("raid.delete", {"target": TARGET, "removeShares": True})
        sharing.JOURNAL.write_text("{}")
        with self.assertRaisesRegex(Rejected, "requires recovery"):
            storage.plan("raid.delete", {"target": TARGET, "removeShares": True})

    def test_helper_removes_only_named_shares_and_closes_connections(self):
        keep = share("elsewhere", "/srv/other/docs")
        self.publish(share("c05share", POINT + "/c05share"), share("media", POINT + "/media", nfs=True), keep)
        removed = sharing.remove_shares(["c05share", "media", "missing"])
        self.assertEqual([s["name"] for s in removed], ["c05share", "media"])
        self.assertEqual(sharing.read()["shares"], [keep])
        self.assertEqual(
            self.commands,
            [["smbcontrol", "smbd", "close-share", "c05share"], ["smbcontrol", "smbd", "close-share", "media"]],
        )
        self.assertIn("[elsewhere]", sharing.SMB.read_text())
        self.assertNotIn("c05share", sharing.SMB.read_text() + sharing.EXPORTS.read_text())
        self.assertFalse(sharing.JOURNAL.exists())
        self.reload.reset_mock()
        self.assertEqual(sharing.remove_shares(["missing"]), [])
        self.reload.assert_not_called()

    def test_failed_share_removal_restores_shares_and_stops_the_delete(self):
        self.publish(share("c05share", POINT + "/c05share"))
        before = sharing.read()
        self.reload.side_effect = [Rejected("failed"), None]
        calls = []
        with patch.object(storage, "command", side_effect=lambda argv, **_: calls.append(argv) or ""):
            with self.assertRaisesRegex(Rejected, "previous configuration restored"):
                storage.execute("raid.delete", {"target": TARGET, "removeShares": True})
        self.assertEqual(calls, [])
        self.assertEqual(sharing.read(), before)

    def test_execution_removes_shares_before_unmounting(self):
        keep = share("elsewhere", "/srv/other/docs")
        self.publish(share("c05share", POINT + "/c05share"), keep)
        order = []
        self.reload.side_effect = lambda shares: order.append("shares:" + ",".join(s["name"] for s in shares))

        def run(argv, **_):
            order.append(" ".join(argv[:2]))
            if argv[:2] == ["mdadm", "--stop"]:
                (sharing.STATE.parent / "sys/class/block/md9/md").rename(sharing.STATE.parent / "stopped")
            return ""

        conf = Path(self.tmp.name) / "mdadm.conf"
        conf.write_text("")
        real = storage.Path.side_effect
        storage.Path.side_effect = lambda *parts: conf if parts == ("/etc/mdadm/mdadm.conf",) else real(*parts)
        with (
            patch.object(storage, "command", side_effect=run),
            patch.object(storage, "atomic"),
            patch.object(storage, "fstab_change"),
            patch.object(storage.storage_reshape, "backup_path", return_value=Path(self.tmp.name) / "none"),
        ):
            storage.execute("raid.delete", {"target": TARGET, "removeShares": True})
        self.assertEqual(order[:3], ["shares:elsewhere", "umount --", "mdadm --stop"])
        self.assertEqual(sharing.read()["shares"], [keep])

    def test_execution_without_the_option_leaves_shares_alone(self):
        self.publish(share("c05share", POINT + "/c05share"))
        with patch.object(storage, "command", side_effect=Rejected("stop here")):
            with self.assertRaisesRegex(Rejected, "stop here"):
                storage.execute("raid.delete", {"target": TARGET})
        self.assertEqual([s["name"] for s in sharing.read()["shares"]], ["c05share"])
        self.reload.assert_not_called()

    def test_share_added_after_review_blocks_execution_after_removal(self):
        self.publish(share("c05share", POINT + "/c05share"))
        self.etab.return_value = {POINT + "/late"}
        with patch.object(storage, "command") as command:
            with self.assertRaisesRegex(Rejected, "Folders shared via NFS: /srv/md9/late"):
                storage.execute("raid.delete", {"target": TARGET, "removeShares": True})
        command.assert_not_called()


if __name__ == "__main__":
    unittest.main()
