#!/usr/bin/python3
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "management"))
import storage
from common import command, Rejected

assert os.geteuid() == 0
baseline = [
    "lsblk",
    "--json",
    "--output",
    "NAME,TYPE,FSTYPE,UUID,MOUNTPOINTS",
    "/dev/sda",
    "/dev/sdb",
    "/dev/sdc",
    "/dev/sdd",
    "/dev/mmcblk0",
]
before = command(baseline)
with tempfile.TemporaryDirectory(prefix="ostojaos-eject-") as tmp:
    image = Path(tmp) / "disk"
    image.write_bytes(b"")
    image.open("r+b").truncate(128 * 1048576)
    loop = command(["losetup", "--find", "--show", "--partscan", str(image)]).strip()
    mounts = [Path("/mnt/ostojaos_eject_" + str(os.getpid()) + "_" + str(i)) for i in range(2)]
    sysroot = Path(tmp) / "sys"
    signal = sysroot / Path(loop).name / "device/delete"
    signal.parent.mkdir(parents=True)
    signal.write_text("0")
    busy = None
    original = storage.inventory

    def inventory():
        inv = original()
        inv[loop]["type"] = "disk"
        return inv

    def path(value):
        return sysroot if str(value) == "/sys/class/block" else Path(value)

    try:
        command(
            [
                "parted",
                "--script",
                loop,
                "mklabel",
                "gpt",
                "mkpart",
                "primary",
                "1MiB",
                "60MiB",
                "mkpart",
                "primary",
                "60MiB",
                "120MiB",
            ]
        )
        command(["udevadm", "settle"])
        for i, mount in enumerate(mounts):
            mount.mkdir()
            part = loop + "p" + str(i + 1)
            command(["mkfs.ext4", "-F", part])
            command(["mount", part, str(mount)])
        busy = subprocess.Popen(["sleep", "60"], cwd=mounts[1])
        with (
            patch.object(storage, "inventory", side_effect=inventory),
            patch.object(storage, "Path", side_effect=path),
        ):
            try:
                storage.plan("disk.eject", {"target": loop})
                raise AssertionError("busy mount accepted")
            except Rejected as e:
                assert str(busy.pid) in str(e)
            assert all(os.path.ismount(p) for p in mounts)
            print("PASS busy process blocks eject before any unmount", flush=True)
            busy.terminate()
            busy.wait()
            busy = None
            storage.plan("disk.eject", {"target": loop})
            storage.execute("disk.eject", {"target": loop})
            assert all(not os.path.ismount(p) for p in mounts)
            assert signal.read_text() == "1"
            print("PASS all partitions unmounted before simulated sysfs eject", flush=True)
    finally:
        if busy:
            busy.terminate()
            busy.wait()
        for mount in mounts:
            subprocess.run(["umount", str(mount)], capture_output=True)
            if mount.exists():
                mount.rmdir()
        command(["losetup", "--detach", loop])
        assert command(baseline) == before
        print("PASS real devices unchanged", flush=True)
