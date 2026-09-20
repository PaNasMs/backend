#!/usr/bin/python3
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "management"))
import storage
from common import command


def wait_idle(array):
    md = Path("/sys/class/block") / Path(os.path.realpath(array)).name / "md"
    for _ in range(240):
        if (md / "sync_action").read_text().strip() == "idle":
            return md
        time.sleep(0.5)
    raise RuntimeError("Temporary array did not finish background operation")


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
with tempfile.TemporaryDirectory(prefix="panasms-grow-test-", dir="/var/tmp") as tmp:
    loops = []
    array = "/dev/md/panasms_grow_" + str(os.getpid())
    mount = Path("/mnt/panasms_grow_" + str(os.getpid()))
    mount.mkdir()
    try:
        for i in range(5):
            image = Path(tmp) / str(i)
            with image.open("wb") as f:
                f.truncate(128 * 1048576)
            loops.append(command(["losetup", "--find", "--show", "--partscan", str(image)]).strip())
        for level, count in [("5", 3), ("6", 4)]:
            command(
                [
                    "mdadm",
                    "--create",
                    array,
                    "--run",
                    "--metadata=1.2",
                    "--level=" + level,
                    "--raid-devices=" + str(count),
                    *loops[:count],
                ]
            )
            wait_idle(array)
            original_size = int(command(["blockdev", "--getsize64", array]))
            command(["parted", "--script", array, "mklabel", "gpt", "mkpart", "primary", "1MiB", "100MiB"])
            command(["udevadm", "settle"])
            real = os.path.realpath(array)
            part = real + "p1"
            command(["mkfs.ext4", "-F", part])
            command(["mount", part, str(mount)])
            marker = mount / "retained.bin"
            marker.write_bytes(os.urandom(2 * 1048576))
            expected = hashlib.sha256(marker.read_bytes()).hexdigest()
            part_before = storage.table(real)["partitions"]
            fs_before = command(["dumpe2fs", "-h", part])
            blocks_before = next(line for line in fs_before.splitlines() if line.startswith("Block count:"))
            params = {"target": array, "replacement": loops[count]}
            preview = storage.plan("raid.grow", params)
            assert "Размер" not in preview["confirmation"]
            storage.execute("raid.grow", params)
            md = wait_idle(array)
            assert int((md / "raid_disks").read_text()) == count + 1
            assert (md / "degraded").read_text().strip() == "0"
            assert int(command(["blockdev", "--getsize64", array])) > original_size
            assert storage.table(real)["partitions"] == part_before
            assert blocks_before in command(["dumpe2fs", "-h", part]).splitlines()
            assert hashlib.sha256(marker.read_bytes()).hexdigest() == expected
            print(
                "PASS RAID"
                + level
                + " grow: active members, capacity, partition geometry, filesystem size and file checksum",
                flush=True,
            )
            command(["umount", str(mount)])
            command(["mdadm", "--stop", array])
            for dev in loops[: count + 1]:
                command(["mdadm", "--zero-superblock", dev])
    finally:
        subprocess.run(["umount", str(mount)], capture_output=True)
        if Path(array).exists():
            wait_idle(array)
            command(["mdadm", "--stop", array])
        for dev in loops:
            command(["losetup", "--detach", dev])
        mount.rmdir()
        assert command(baseline) == before
        print("PASS real disk topology, filesystems and mounts unchanged", flush=True)
