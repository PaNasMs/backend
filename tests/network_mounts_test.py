from pathlib import Path
from types import SimpleNamespace
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "management"))
import network_mounts as n
from common import Rejected


class NetworkMounts(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.conf = self.root / "fstab"
        self.original = "UUID=root / ext4 defaults 0 1\n"
        self.conf.write_text(self.original)
        self.creds = self.root / "credentials"
        self.point = self.root / "share"
        self.params = {
            "target": "//nas/share",
            "point": str(self.point),
            "username": "pasha",
            "password": "private-secret",
            "automount": True,
        }
        for target, value in [
            ("FSTAB", self.conf),
            ("CREDENTIALS", self.creds),
            ("mountpoint", lambda p: Path(p)),
            ("atomic", self.atomic),
        ]:
            p = patch.object(n, target, value)
            p.start()
            self.addCleanup(p.stop)
        p = patch.object(n.pwd, "getpwnam", return_value=SimpleNamespace(pw_uid=1000, pw_gid=1000))
        p.start()
        self.addCleanup(p.stop)

    def atomic(self, path, content, mode):
        path.write_text(content)
        path.chmod(mode)

    def test_smb_secret_is_private_and_not_in_mount_or_fstab(self):
        with patch.object(n, "command", return_value="") as command:
            n.execute("smb.mount", self.params, "pasha")
        credential = self.creds / n.key(self.point)
        self.assertEqual(credential.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.creds.stat().st_mode & 0o777, 0o700)
        self.assertIn("private-secret", credential.read_text())
        self.assertNotIn("private-secret", self.conf.read_text())
        self.assertNotIn("private-secret", str(command.call_args_list))
        self.assertIn("uid=1000,gid=1000", self.conf.read_text())
        with patch.object(n, "command", return_value=""):
            n.execute("smb.unmount", {"target": str(self.point)}, "pasha")
        self.assertEqual(self.conf.read_text(), self.original)
        self.assertFalse(credential.exists())

    def test_failed_mount_leaves_no_credentials_or_fstab_entry(self):
        with patch.object(n, "command", side_effect=Rejected("failed")):
            with self.assertRaisesRegex(Rejected, "Could not mount"):
                n.execute("smb.mount", self.params, "pasha")
        self.assertEqual(self.conf.read_text(), self.original)
        self.assertFalse((self.creds / n.key(self.point)).exists())

    def test_existing_credentials_not_deleted_on_conflict(self):
        self.creds.mkdir()
        credential = self.creds / n.key(self.point)
        credential.write_text("existing")
        with self.assertRaises(Rejected):
            n.execute("smb.mount", self.params, "pasha")
        self.assertEqual(credential.read_text(), "existing")

    def test_reject_credential_injection_and_duplicate_point(self):
        with patch.object(n, "mounted", return_value=[]):
            with self.assertRaises(Rejected):
                n.plan("smb.mount", {**self.params, "password": "x\nusername=evil"}, "pasha")
            self.conf.write_text(f"nas:/data {self.point} nfs defaults 0 0\n")
            with self.assertRaisesRegex(Rejected, "fstab"):
                n.plan("smb.mount", self.params, "pasha")

    def test_failed_unmount_keeps_configuration_and_secret(self):
        with patch.object(n, "command", return_value=""):
            n.execute("smb.mount", self.params, "pasha")
        saved = self.conf.read_text()
        with patch.object(n, "command", side_effect=Rejected("busy")):
            with self.assertRaises(Rejected):
                n.execute("smb.unmount", {"target": str(self.point)}, "pasha")
        self.assertEqual(self.conf.read_text(), saved)
        self.assertTrue((self.creds / n.key(self.point)).exists())

    def test_nfs_readonly_without_persistence(self):
        with patch.object(n, "command", return_value="") as command:
            n.execute(
                "nfs.mount", {"target": "nas:/video", "point": str(self.point), "readOnly": True}, "pasha"
            )
        self.assertEqual(self.conf.read_text(), self.original)
        self.assertIn("ro,nosuid,nodev,_netdev", str(command.call_args_list))
