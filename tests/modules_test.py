import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "management"))
import module_manager as m
from common import Rejected


class Modules(unittest.TestCase):
    def test_dependency_order_and_missing(self):
        all = {
            "files": {"version": "1.0.0", "dependencies": {"indexer": ">=1.0.0,<2.0.0"}},
            "indexer": {"version": "1.2.0"},
        }
        self.assertEqual(m.resolve("files", all, {}), ["indexer", "files"])
        with self.assertRaisesRegex(Rejected, "Missing module"):
            m.resolve("files", {"files": all["files"]}, {})
        with self.assertRaisesRegex(Rejected, "Incompatible"):
            m.resolve("files", {**all, "indexer": {"version": "2.0.0"}}, {})

    def test_cycles_and_reverse_dependencies(self):
        with self.assertRaisesRegex(Rejected, "Dependency cycle"):
            m.resolve(
                "files",
                {
                    "files": {"version": "1.0.0", "dependencies": {"indexer": ">=1.0.0"}},
                    "indexer": {"version": "1.0.0", "dependencies": {"files": ">=1.0.0"}},
                },
                {},
            )
        installed = {
            "files": {"version": "1.0.0", "dependencies": {"indexer": "<2.0.0"}},
            "indexer": {"version": "1.0.0"},
        }
        with self.assertRaisesRegex(Rejected, "would break"):
            m.resolve("indexer", {"indexer": {"version": "2.0.0"}}, installed)
        self.assertEqual(m.dependents("indexer", installed), ["files"])

    def test_version_constraints_and_disabled_dependency(self):
        self.assertTrue(m.satisfies("0.1.5", ">=0.1.0,<0.2.0"))
        self.assertFalse(m.satisfies("0.2.0", ">=0.1.0,<0.2.0"))
        self.assertEqual(
            m.resolve(
                "files",
                {},
                {
                    "files": {
                        "version": "1.0.0",
                        "enabled": False,
                        "dependencies": {"indexer": ">=1.0.0"},
                    },
                    "indexer": {"version": "1.0.0", "enabled": False},
                },
            ),
            ["indexer", "files"],
        )

    def test_previous_namespace_modules_are_incompatible(self):
        with self.assertRaisesRegex(Rejected, "incompatible"):
            m.manifest({"id": "files", "version": "0.1.3", "api": 1,
                        "core": ">=0.1.2,<0.2.0"})

    def test_signed_archive_and_tampering(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            key = root / "key"
            pub = root / "local.pem"
            subprocess.run(
                ["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(key)],
                check=True,
                capture_output=True,
            )
            subprocess.run(
                ["openssl", "pkey", "-in", str(key), "-pubout", "-out", str(pub)],
                check=True,
                capture_output=True,
            )
            payload = b'console.log("module")'
            manifest = {
                "id": "files",
                "title": "Files",
                "version": "0.1.0",
                "api": 1,
                "core": ">=0.2.0,<0.3.0",
                "architecture": "all",
                "signer": "local",
                "files": {"ui/index.js": hashlib.sha256(payload).hexdigest(),
                          "LICENSE": hashlib.sha256(b"license").hexdigest(),
                          "NOTICE": hashlib.sha256(b"notice").hexdigest()},
            }
            raw = json.dumps(manifest).encode()
            (root / "manifest").write_bytes(raw)
            subprocess.run(
                [
                    "openssl",
                    "pkeyutl",
                    "-sign",
                    "-inkey",
                    str(key),
                    "-rawin",
                    "-in",
                    str(root / "manifest"),
                    "-out",
                    str(root / "sig"),
                ],
                check=True,
                capture_output=True,
            )

            def build(content, extra=None):
                path = root / "module.zip"
                with zipfile.ZipFile(path, "w") as z:
                    z.writestr("bundle.json", '{"root":"files"}')
                    z.writestr("modules/files/manifest.json", raw)
                    z.writestr("modules/files/signature", (root / "sig").read_bytes())
                    z.writestr("modules/files/ui/index.js", content)
                    z.writestr("modules/files/LICENSE", b"license")
                    z.writestr("modules/files/NOTICE", b"notice")
                    if extra:
                        z.writestr(extra, b"bad")
                return path

            with patch.object(m, "KEYS", root):
                self.assertEqual(m.inspect_bundle(build(payload))[0], "files")
                with self.assertRaisesRegex(Rejected, "Corrupted"):
                    m.inspect_bundle(build(b"evil"))
                with self.assertRaisesRegex(Rejected, "Unsafe archive path"):
                    m.inspect_bundle(build(payload, "../escape"))
                with self.assertRaisesRegex(Rejected, "unknown files"):
                    m.inspect_bundle(build(payload, "extra"))
                (root / "sig").write_bytes(b"x" * 64)
                with self.assertRaisesRegex(Rejected, "signature"):
                    m.inspect_bundle(build(payload))

    def test_upload_is_bound_to_owner(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(m, "UPLOADS", Path(tmp)):
            token = "a" * 32
            (Path(tmp) / ("alice-" + token + ".zip")).write_bytes(b"x")
            self.assertTrue(m.upload_path(token, "alice").exists())
            with self.assertRaises(Rejected):
                m.upload_path(token, "bob")
            with self.assertRaises(Rejected):
                m.upload_path("../alice", "bob")

    def test_remove_blocked_by_dependents_and_active_work(self):
        installed = {
            "files": {"title": "Files", "version": "0.1.0", "enabled": True},
            "indexer": {"version": "0.1.0", "dependencies": {"files": ">=0.1.0"}},
        }
        with patch.object(m, "registry", return_value=installed):
            with self.assertRaisesRegex(Rejected, "Dependent modules"):
                m.plan("module.remove", {"target": "files"}, "pasha")
        with (
            patch.object(m, "registry", return_value={"files": installed["files"]}),
            patch.object(m, "require_idle", side_effect=Rejected("занят")),
        ):
            with self.assertRaisesRegex(Rejected, "занят"):
                m.plan("module.disable", {"target": "files"}, "pasha")

    def test_restart_recovers_old_payload_and_registry(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            units = root / "units"
            units.mkdir()
            before = {"files": {"id": "files", "enabled": True, "version": "0.1.0"}}
            (root / "files").mkdir()
            (root / "files" / "payload").write_text("new")
            tx = root / ".transaction"
            tx.mkdir()
            (tx / "old-files").mkdir()
            (tx / "old-files" / "payload").write_text("old")
            (tx / "journal.json").write_text(
                json.dumps({"before": before, "affected": ["files"], "committed": False})
            )
            with (
                patch.object(m, "ROOT", root),
                patch.object(m, "REGISTRY", root / "registry.json"),
                patch.object(m, "UNITS", units),
                patch.object(m, "command"),
                patch.object(m, "activate") as activate,
            ):
                m.recover()
                self.assertEqual((root / "files" / "payload").read_text(), "old")
                self.assertEqual(m.registry(), before)
                activate.assert_called_once_with(before["files"])
                self.assertFalse(tx.exists())

    def test_failed_recovery_preserves_backup_for_retry(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tx = root / ".transaction"
            tx.mkdir()
            (tx / "old-files").mkdir()
            (tx / "journal.json").write_text(
                json.dumps(
                    {
                        "before": {"files": {"id": "files", "enabled": True}},
                        "affected": ["files"],
                        "committed": False,
                    }
                )
            )
            with (
                patch.object(m, "ROOT", root),
                patch.object(m, "command", side_effect=Rejected("service unavailable")),
            ):
                with self.assertRaises(Rejected):
                    m.recover()
                self.assertTrue((tx / "old-files").exists())
                self.assertTrue((tx / "journal.json").exists())

    def test_upgrade_preserves_disabled_root_module(self):
        for enabled in (False, True):
            with self.subTest(enabled=enabled), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                archive = root / "upload.zip"
                new = {"id": "files", "version": "0.2.11", "files": {"ui/index.js": "hash"}, "service": "bin/server"}
                with zipfile.ZipFile(archive, "w") as bundle:
                    bundle.writestr("modules/files/ui/index.js", "updated")
                before = {"files": {**new, "version": "0.2.10", "enabled": enabled}}
                (root / "files").mkdir()
                with patch.object(m, "ROOT", root), patch.object(m, "REGISTRY", root / "registry.json"), patch.object(m, "UNITS", root), patch.object(m, "upload_path", return_value=archive), patch.object(m, "inspect_bundle", return_value=("files", {"files": new})), patch.object(m, "manifest"), patch.object(m, "package_plan", return_value=([], [])), patch.object(m, "require_idle"), patch.object(m, "command"), patch.object(m, "write_unit"), patch.object(m, "atomic", side_effect=lambda path, text, mode=0o600: Path(path).write_text(text)), patch.object(m, "activate") as activate:
                    m.save_registry(before)
                    m.execute("module.install", {"upload": "test"}, "alice")
                    self.assertEqual(m.registry()["files"]["enabled"], enabled)
                    self.assertEqual(m.registry()["files"]["version"], "0.2.11")
                    self.assertEqual(activate.call_count, int(enabled))

    def test_busy_module_is_not_stopped(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            before = {"files": {"id": "files", "enabled": True, "version": "0.1.0"}}
            with (
                patch.object(m, "ROOT", root),
                patch.object(m, "REGISTRY", root / "registry.json"),
                patch.object(m, "command") as command,
                patch.object(m, "require_idle", side_effect=Rejected("занят")),
                patch.object(
                    m, "atomic", side_effect=lambda path, text, mode: Path(path).write_text(text)
                ),
            ):
                m.save_registry(before)
                with self.assertRaisesRegex(Rejected, "занят"):
                    m.execute("module.disable", {"target": "files"}, "alice")
                self.assertEqual(m.registry(), before)
                command.assert_not_called()
                self.assertFalse((root / ".transaction").exists())
