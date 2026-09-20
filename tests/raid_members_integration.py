#!/usr/bin/python3
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "management"))
import storage
from common import command

assert os.geteuid() == 0
loops = []
array = "/dev/md/ostojaos_members_" + str(os.getpid())


def perform(action, p):
    storage.plan(action, p)
    storage.execute(action, p)
    print("PASS", action, flush=True)


def idle():
    md = Path("/sys/class/block") / Path(os.path.realpath(array)).name / "md/sync_action"
    for _ in range(120):
        if md.read_text().strip() == "idle":
            return
        time.sleep(0.5)
    raise RuntimeError("array operation timeout")


with tempfile.TemporaryDirectory(prefix="ostojaos-members-test-", dir="/var/tmp") as scratch:
    try:
        for i in range(4):
            img = Path(scratch) / str(i)
            with img.open("wb") as f:
                f.truncate(256 * 1048576)
            loops.append(command(["losetup", "--find", "--show", str(img)]).strip())
        perform("raid.create", {"name": Path(array).name, "level": "1", "members": loops[:2]})
        idle()
        perform("raid.check", {"target": array})
        idle()
        perform("raid.add", {"target": array, "replacement": loops[2]})
        perform("raid.replace", {"target": array, "member": loops[0], "replacement": loops[3]})
        idle()
        detail = command(["mdadm", "--detail", array])
        assert loops[3] in detail
        perform("raid.delete", {"target": array})
        assert array not in Path("/etc/mdadm/mdadm.conf").read_text()
    finally:
        if Path(array).exists():
            idle()
            perform("raid.delete", {"target": array})
        for dev in loops:
            subprocess.run(["losetup", "--detach", dev], check=True)
