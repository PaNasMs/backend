#!/usr/bin/python3
"""Validate removal of the panel and immediately reinstall, preserving its state in a private snapshot."""
import hashlib
import json
import os
from pathlib import Path
import pwd
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time

assert os.geteuid() == 0
package = Path(sys.argv[1]).resolve()
assert package.is_file()
snapshot = Path(tempfile.mkdtemp(prefix="ostojaos-reinstall-snapshot-", dir="/var/tmp"))
snapshot.chmod(0o700)


def run(*args):
    subprocess.run(args, check=True)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest() if Path(path).exists() else None


protected = [
    "/etc/passwd",
    "/etc/group",
    "/etc/fstab",
    "/etc/mdadm/mdadm.conf",
    "/etc/exports.d/ostojaos.exports",
    "/etc/ostojaos-cooling/config.json",
]
# passwd/group change only by removal and recreation of the dedicated panel service account.
config = {p: digest(p) for p in protected[2:]}
identity = pwd.getpwnam("pasha")
cooling = subprocess.check_output(["systemctl", "show", "-p", "MainPID", "--value", "ostojaos-cooling"]).strip()
for path in ("/var/lib/ostojaos/state.db", "/var/lib/ostojaos-agent/jobs.db"):
    if Path(path).exists():
        with sqlite3.connect(path) as source, sqlite3.connect(str(snapshot / Path(path).name)) as backup:
            source.backup(backup)
for path in ("/etc/ostojaos", "/var/lib/ostojaos-agent/backups"):
    if Path(path).exists():
        shutil.copytree(path, snapshot / Path(path).name)
restored = False
try:
    run("ostojaos-uninstall", "--purge")
    assert not Path("/usr/lib/ostojaos/ostojaos-core").exists()
    assert not Path("/usr/lib/ostojaos/management").exists()
    for path in ("/etc/ostojaos", "/var/lib/ostojaos", "/var/lib/ostojaos-agent"):
        assert not Path(path).exists(), path + " remains"
    assert subprocess.check_output(["systemctl", "is-active", "ostojaos-cooling"]).strip() == b"active"
    assert pwd.getpwnam("pasha") == identity
    for path, value in config.items():
        assert digest(path) == value, path + " changed during purge"
    print("PASS full purge, user/storage/NFS/cooling configuration preserved", flush=True)
finally:
    try:
        run("apt-get", "install", "-y", "--reinstall", str(package))
        run("systemctl", "stop", "ostojaos-core", "ostojaos-agent")
        if (snapshot / "ostojaos").exists():
            shutil.copytree(snapshot / "ostojaos", "/etc/ostojaos", dirs_exist_ok=True)
        core = pwd.getpwnam("ostojaos")
        for name, target, uid, gid in [
            ("state.db", "/var/lib/ostojaos/state.db", core.pw_uid, core.pw_gid),
            ("jobs.db", "/var/lib/ostojaos-agent/jobs.db", 0, 0),
        ]:
            if (snapshot / name).exists():
                Path(target).parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                shutil.copy2(snapshot / name, target)
                os.chown(target, uid, gid)
                os.chmod(target, 0o600)
        for path in Path("/etc/ostojaos").glob("*"):
            os.chown(path, 0, core.pw_gid)
        os.chown("/etc/ostojaos", 0, core.pw_gid)
        os.chown("/var/lib/ostojaos", core.pw_uid, core.pw_gid)
        if (snapshot / "backups").exists():
            shutil.copytree(snapshot / "backups", "/var/lib/ostojaos-agent/backups", dirs_exist_ok=True)
        run("ostojaos-configure")
        for _ in range(30):
            if (
                subprocess.run(
                    ["curl", "--fail", "--silent", "http://localhost/api/v1/health"],
                    stdout=subprocess.DEVNULL,
                ).returncode
                == 0
            ):
                break
            time.sleep(1)
        else:
            raise RuntimeError("panel did not return")
        for path, value in config.items():
            assert digest(path) == value, path + " changed"
        assert (
            subprocess.check_output(
                ["systemctl", "show", "-p", "MainPID", "--value", "ostojaos-cooling"]
            ).strip()
            == cooling
        )
        assert pwd.getpwnam("pasha") == identity
        restored = True
        print(
            "PASS reinstall with original SQLite/preferences/jobs restored; cooling uninterrupted", flush=True
        )
    finally:
        if restored:
            shutil.rmtree(snapshot)
        else:
            print("Recovery snapshot retained:", snapshot, file=sys.stderr)
