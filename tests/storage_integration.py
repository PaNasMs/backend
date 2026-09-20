#!/usr/bin/python3
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "management"))
import storage
from common import command, Rejected


def perform(action, params):
    plan = storage.plan(action, params)
    require = plan["fingerprint"]
    fresh = storage.plan(action, params)
    assert require == fresh["fingerprint"]
    result = storage.execute(action, params)
    print("PASS", action, flush=True)
    return result


assert os.geteuid() == 0
scratch = tempfile.TemporaryDirectory(prefix="panasms-storage-test-", dir="/var/tmp")
loops = []
array = "/dev/md/panasms_test_" + str(os.getpid())
mount = "/mnt/panasms_test_" + str(os.getpid())
luks = "panasms_test_" + str(os.getpid())
baseline_args = [
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
before = command(baseline_args)
try:
    for i in range(3):
        img = Path(scratch.name) / f"disk{i}.img"
        with img.open("wb") as f:
            f.truncate(256 * 1048576)
        loops.append(command(["losetup", "--find", "--show", "--partscan", str(img)]).strip())
    perform("raid.create", {"name": Path(array).name, "level": "1", "members": loops[:2]})
    for attempt in range(60):
        md = Path("/sys/class/block") / Path(os.path.realpath(array)).name / "md/sync_action"
        if md.read_text().strip() == "idle":
            break
        time.sleep(1)
    perform("partition.create", {"target": array, "startMiB": 1, "endMiB": 200})
    parts = [
        d
        for d in storage.inventory().values()
        if d.get("parent") == os.path.realpath(array) and d["type"] == "part"
    ]
    assert len(parts) == 1
    perform("partition.delete", {"target": parts[0]["path"]})
    perform("filesystem.format", {"target": array, "format": "ext4"})
    perform("mount.attach", {"target": array, "point": mount, "automount": True})
    marker = Path(mount) / "fixture.txt"
    marker.write_text("temporary test data\n")
    assert marker.read_text() == "temporary test data\n"
    try:
        storage.plan("filesystem.format", {"target": array, "format": "ext4"})
        raise AssertionError("mounted volume accepted")
    except Rejected:
        print("PASS mounted format rejected", flush=True)
    perform("mount.detach", {"target": array})
    perform("mount.attach", {"target": array, "point": mount, "automount": True})
    assert marker.read_text() == "temporary test data\n"
    perform("raid.delete", {"target": array})
    assert not Path(array).exists()
    perform("raid.create", {"name": Path(array).name, "level": "0", "members": loops[:2]})
    assert storage.inventory()[os.path.realpath(array)]["type"] == "raid0"
    for action in ("raid.check", "raid.replace", "raid.add"):
        try:
            storage.plan(action, {"target": array, "replacement": loops[2], "member": loops[0]})
            raise AssertionError("RAID0 redundancy operation accepted")
        except Rejected:
            print("PASS RAID0 operation rejected:", action, flush=True)
    perform("raid.delete", {"target": array})
    assert not Path(array).exists()
    perform("partition.create", {"target": loops[2], "startMiB": 1, "endMiB": 240})
    part = loops[2] + "p1"
    perform("filesystem.format", {"target": part, "format": "ext4"})
    perform("partition.resize", {"target": part, "sizeMiB": 128})
    perform("partition.resize", {"target": part, "sizeMiB": 200})
    perform("partition.delete", {"target": part})
    perform("luks.create", {"target": loops[0], "passphrase": "isolated-test-only"})
    perform("luks.open", {"target": loops[0], "name": luks, "passphrase": "isolated-test-only"})
    perform("luks.close", {"target": "/dev/mapper/" + luks})
    print(
        "PASS RAID create/format/mount/remount/delete, partitions create/resize/delete, LUKS create/open/close",
        flush=True,
    )
finally:
    subprocess.run(["umount", mount], capture_output=True)
    subprocess.run(["cryptsetup", "close", luks], capture_output=True)
    if Path(array).exists():
        try:
            perform("raid.delete", {"target": array})
        except Exception:
            subprocess.run(["mdadm", "--stop", array], capture_output=True)
    for dev in loops:
        subprocess.run(["losetup", "--detach", dev], capture_output=True)
    try:
        Path(mount).rmdir()
    except OSError:
        pass
    scratch.cleanup()
    assert command(baseline_args) == before
    print("PASS actual disk topology, filesystems and mounts preserved", flush=True)
