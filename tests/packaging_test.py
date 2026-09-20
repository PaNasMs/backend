import os
import runpy
import sqlite3
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class PackagingTest(unittest.TestCase):
    def test_shell_syntax(self):
        for name in ["preinst", "postinst", "prerm", "postrm", "ostojaos-configure", "start-agent"]:
            subprocess.run(["sh", "-n", str(ROOT / "packaging" / name)], check=True)
        subprocess.run(["sh", "-n", str(ROOT / "scripts/build-deb.sh")], check=True)

    def test_legacy_installation_blocks_both_packages_without_changes(self):
        for component in ("packaging", "cooling"):
            with self.subTest(component=component), tempfile.TemporaryDirectory() as d:
                root = Path(d)
                state = root / "etc/pinas"
                state.mkdir(parents=True)
                sentinel = state / "pinas.env"
                sentinel.write_text("existing configuration")
                script = (ROOT / component / "preinst").read_text()
                for prefix in ("/etc/", "/var/lib/", "/usr/lib/"):
                    script = script.replace(prefix, str(root) + prefix)
                path = root / "preinst"
                path.write_text(script)
                result = subprocess.run(["sh", str(path), "install"], capture_output=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(b"Existing PiNAS installation", result.stderr)
                self.assertEqual(sentinel.read_text(), "existing configuration")

    def test_hardware_detection_without_control_writes(self):
        inspect = runpy.run_path(str(ROOT / "packaging/ostojaos-inspect-hardware"))["inspect"]
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            hw = root / "class/hwmon/hwmon0"
            hw.mkdir(parents=True)
            for name, value in {
                "name": "pwmfan",
                "fan1_input": "3150",
                "pwm1": "75",
                "pwm1_enable": "1",
            }.items():
                (hw / name).write_text(value)
            chip = root / "class/pwm/pwmchip0"
            chip.mkdir(parents=True)
            (chip / "npwm").write_text("4")
            report = inspect(root)
            self.assertEqual(report["fanControllers"][0]["attributes"]["fan1_input"], "3150")
            self.assertEqual(report["coolingControl"], "unchanged")
            self.assertEqual((hw / "pwm1").read_text(), "75")
            self.assertFalse((chip / "export").exists())
            self.assertEqual(report["errors"], [])
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(inspect(Path(d))["fanControllers"], [])

    def test_installer_syntax(self):
        subprocess.run(["bash", "-n", str(ROOT / "scripts/install-prototype.sh")], check=True)

    def test_purge_preserves_unmanaged_files(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            for p in [
                "etc/ostojaos",
                "var/lib/ostojaos",
                "var/lib/ostojaos-installer",
                "var/lib/ostojaos-agent/backups",
                "usr/lib/ostojaos/management/__pycache__",
                "etc/systemd/system",
                "run/ostojaos-filesystems",
                "bin",
                "data",
            ]:
                (root / p).mkdir(parents=True)
            owned = [
                root / "etc/ostojaos/ostojaos.env",
                root / "etc/ostojaos/tls.key",
                root / "etc/ostojaos/tls.crt",
                root / "var/lib/ostojaos/state.db",
            ]
            for p in owned:
                p.write_text("owned")
            for name in ["jobs.db", "jobs.db-wal", "jobs.db-shm"]:
                p = root / "var/lib/ostojaos-agent" / name
                p.write_text("owned")
                owned.append(p)
            backup = root / "var/lib/ostojaos-agent/backups/fstab.123456"
            backup.write_text("old config")
            pycache = root / "usr/lib/ostojaos/management/__pycache__/main.cpython-313.pyc"
            pycache.write_text("cache")
            for suffix in ["timer", "service"]:
                p = root / ("etc/systemd/system/ostojaos-smart-0123456789abcdef." + suffix)
                p.write_text("owned")
                owned.append(p)
            preserved = root / "etc/systemd/system/ostojaos-cooling.service"
            preserved.write_text("independent cooling")
            sentinel = root / "var/lib/ostojaos/do-not-delete"
            sentinel.write_text("user data")
            data = root / "data/important"
            data.write_text("storage")
            (root / "bin/systemctl").write_text("#!/bin/sh\nexit 0\n")
            (root / "bin/systemctl").chmod(0o755)
            (root / "bin/udevadm").write_text("#!/bin/sh\nexit 0\n")
            (root / "bin/udevadm").chmod(0o755)
            runtime = root / "run/ostojaos-filesystems/sde1.json"
            runtime.write_text("cache")
            preserved_runtime = root / "run/ostojaos-filesystems/user-note"
            preserved_runtime.write_text("keep")
            script = (ROOT / "packaging/postrm").read_text()
            for prefix in [
                "/etc/ostojaos",
                "/var/lib/ostojaos",
                "/usr/lib/ostojaos",
                "/etc/systemd/system",
                "/run/ostojaos-filesystems",
            ]:
                script = script.replace(prefix, str(root) + prefix)
            path = root / "postrm"
            path.write_text(script)
            env = dict(os.environ, PATH=str(root / "bin") + ":" + os.environ["PATH"])
            subprocess.run(["sh", str(path), "purge"], env=env, check=True, capture_output=True)
            self.assertTrue(all(not p.exists() for p in owned))
            self.assertEqual(sentinel.read_text(), "user data")
            self.assertEqual(data.read_text(), "storage")
            self.assertEqual(preserved.read_text(), "independent cooling")
            self.assertEqual(backup.exists(), os.geteuid() != 0)
            self.assertEqual(pycache.exists(), os.geteuid() != 0)
            self.assertEqual(runtime.exists(), os.geteuid() != 0)
            self.assertEqual(preserved_runtime.read_text(), "keep")
            subprocess.run(["sh", str(path), "purge"], env=env, check=True, capture_output=True)

    def test_active_job_blocks_package_change(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            dbpath = root / "jobs.db"
            log = root / "systemctl.log"
            with sqlite3.connect(dbpath) as db:
                db.execute("create table jobs(status text)")
                db.execute("insert into jobs values ('running')")
            db.close()
            tool = root / "systemctl"
            tool.write_text('#!/bin/sh\necho "$@" >> "' + str(log) + '"\n')
            tool.chmod(0o755)
            script = (
                (ROOT / "packaging/prerm").read_text().replace("/var/lib/ostojaos-agent/jobs.db", str(dbpath))
            )
            path = root / "prerm"
            path.write_text(script)
            env = dict(os.environ, PATH=str(root) + ":" + os.environ["PATH"])
            result = subprocess.run(["sh", str(path), "remove"], env=env, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(log.exists())
            with sqlite3.connect(dbpath) as db:
                db.execute("update jobs set status='succeeded'")
            db.close()
            subprocess.run(["sh", str(path), "remove"], env=env, capture_output=True, check=True)
            self.assertIn("stop ostojaos-core.service ostojaos-agent.service", log.read_text())

    def test_purge_refuses_symlink_parent(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "etc").mkdir()
            (root / "outside").mkdir()
            (root / "outside/tls.key").write_text("preserve")
            (root / "etc/ostojaos").symlink_to(root / "outside", target_is_directory=True)
            script = (
                (ROOT / "packaging/postrm")
                .read_text()
                .replace("/etc/ostojaos", str(root / "etc/ostojaos"))
                .replace("systemctl daemon-reload || true", ":")
            )
            p = root / "script"
            p.write_text(script)
            result = subprocess.run(["sh", str(p), "purge"], capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual((root / "outside/tls.key").read_text(), "preserve")


if __name__ == "__main__":
    unittest.main()
