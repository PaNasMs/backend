#!/usr/bin/python3
import os
from pathlib import Path
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "management"))
import storage
import host
from common import command

assert os.geteuid() == 0
with tempfile.TemporaryDirectory(prefix="ostojaos-fs-test-", dir="/var/tmp") as scratch:
    mount = "/mnt/ostojaos_fs_" + str(os.getpid())
    Path(mount).mkdir()
    try:
        for fs in ("btrfs", "xfs"):
            image = Path(scratch) / (fs + ".img")
            with image.open("wb") as f:
                f.truncate(1024 * 1048576)
            dev = command(["losetup", "--find", "--show", str(image)]).strip()
            try:
                p = {"target": dev, "format": fs}
                storage.plan("filesystem.format", p)
                storage.execute("filesystem.format", p)
                p = {"target": dev, "point": mount}
                storage.plan("mount.attach", p)
                storage.execute("mount.attach", p)
                marker = Path(mount) / "marker"
                marker.write_text("resize test")
                p = {"target": mount, "owner": "pasha", "group": "pasha", "mode": "0770"}
                host.plan("folder.permissions", p)
                host.execute("folder.permissions", p)
                import pwd

                assert Path(mount).stat().st_uid == pwd.getpwnam("pasha").pw_uid
                assert Path(mount).stat().st_mode & 0o777 == 0o770
                if fs == "btrfs":
                    p = {"target": dev, "sizeMiB": 512}
                    storage.plan("filesystem.resize", p)
                    storage.execute("filesystem.resize", p)
                with image.open("r+b") as f:
                    f.truncate(1536 * 1048576)
                command(["losetup", "--set-capacity", dev])
                p = {"target": dev, "sizeMiB": 0}
                storage.plan("filesystem.resize", p)
                storage.execute("filesystem.resize", p)
                assert marker.read_text() == "resize test"
                p = {"target": dev}
                storage.plan("mount.detach", p)
                storage.execute("mount.detach", p)
                storage.plan("disk.prepare", p)
                storage.execute("disk.prepare", p)
                assert not storage.inventory()[dev].get("fstype")
                print(
                    "PASS",
                    fs,
                    "format/mount/permissions/resize/data preservation/unmount/prepare",
                    flush=True,
                )
            finally:
                subprocess.run(["umount", mount], capture_output=True)
                subprocess.run(["losetup", "--detach", dev], check=True)
    finally:
        Path(mount).rmdir()
