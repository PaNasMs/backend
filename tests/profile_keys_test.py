from pathlib import Path
import runpy
import tempfile
import unittest
import subprocess

m = runpy.run_path(str(Path(__file__).resolve().parents[1] / "packaging/profile-keys.py"))


class KeysTest(unittest.TestCase):
    def test_preserves_existing_lines_and_add_remove(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".ssh").mkdir()
            original = '# Existing restrictions must remain\ncommand="/usr/bin/true" ssh-rsa AAAA keep\n'
            (root / ".ssh/authorized_keys").write_text(original)
            subprocess.run(
                ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(root / "test")], check=True
            )
            key = (root / "test.pub").read_text()
            rows = m["manage"](root, {"action": "add", "key": key})
            with self.assertRaises(ValueError):
                m["manage"](root, {"action": "add", "key": key})
            self.assertTrue((root / ".ssh/authorized_keys").read_text().startswith(original))
            m["manage"](root, {"action": "delete", "id": rows[-1]["id"]})
            self.assertEqual((root / ".ssh/authorized_keys").read_text(), original)

    def test_refuses_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".ssh").mkdir()
            (root / "outside").write_text("preserve")
            (root / ".ssh/authorized_keys").symlink_to(root / "outside")
            with self.assertRaises(OSError):
                m["manage"](root, {"action": "list"})
            self.assertEqual((root / "outside").read_text(), "preserve")

    def test_refuses_private_or_option_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            for key in [
                "-----BEGIN OPENSSH PRIVATE KEY-----",
                'command="evil" ssh-ed25519 AAAA',
                "ssh-ed25519 AAAA\nssh-ed25519 AAAA",
            ]:
                with self.assertRaises(ValueError):
                    m["manage"](Path(tmp), {"action": "add", "key": key})


if __name__ == "__main__":
    unittest.main()
