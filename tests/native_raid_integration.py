#!/usr/bin/env python3
"""Run native RAID acceptance only in an offline disposable VM with a rollback snapshot."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time


def command(*args):
    return subprocess.check_output(args, text=True).strip()


class Worker:
    def __init__(self, helper, actor):
        self.helper = helper
        self.actor = actor

    def invoke(self, mode, action, params, **confirmation):
        result = subprocess.run(
            [self.helper, mode, self.actor],
            input=json.dumps(dict(action="raid." + action, params=params, **confirmation)),
            text=True, check=True, capture_output=True, timeout=600,
        )
        return json.loads(result.stdout)

    def plan(self, action, params):
        # A previous command can finish before its last metadata-change event.
        for attempt in range(6):
            command("udevadm", "settle")
            plan = self.invoke("plan", action, params)
            if plan.get("error") != "Could not verify storage dependencies. No changes were made." or attempt == 5:
                break
            time.sleep(0.5)
        assert "error" not in plan, (action, plan)
        return plan

    def perform(self, action, **params):
        plan = self.plan(action, params)
        result = self.invoke("execute", action, params, fingerprint=plan["fingerprint"], confirmation=plan["confirmation"])
        assert "error" not in result, (action, result)
        print("PASS", action, flush=True)


def interrupt_config(worker, action, **params):
    config = "/etc/mdadm/mdadm.conf"
    command("mount", "--bind", config, config)
    try:
        plan = worker.plan(action, params)
        result = worker.invoke("execute", action, params, fingerprint=plan["fingerprint"], confirmation=plan["confirmation"])
        assert "error" in result, result
        journals = list(Path("/var/lib/panasms-agent/raid-lifecycle").glob("*.json"))
        assert len(journals) == 1, journals
        record = json.loads(journals[0].read_text())
        assert record["action"] == "raid." + action
        assert record["step"] == {"create": "register", "delete": "stopped"}[action], record["step"]
        assert subprocess.run([worker.helper, "raid", "check-removal"]).returncode != 0
    finally:
        command("umount", config)
    marker = "# unrelated change during recovery " + record["uuid"]
    with Path(config).open("a") as stream:
        stream.write("\n" + marker + "\n")
    with Path("/etc/fstab").open("a") as stream:
        stream.write("\n" + marker + "\n")
    command(worker.helper, "raid", "finish", record["uuid"])
    assert marker in Path(config).read_text() and marker in Path("/etc/fstab").read_text()
    # A retained pre-reboot record cannot authorize device writes against a new boot.
    record["identity"]["bootId"] = "00000000-0000-0000-0000-000000000000"
    raw = json.dumps(record).encode()
    journals[0].touch(mode=0o600)
    journals[0].write_bytes(raw)
    assert subprocess.run([worker.helper, "raid", "finish", record["uuid"]]).returncode != 0
    assert subprocess.run([worker.helper, "raid", "archive", record["uuid"], "stale"]).returncode != 0
    command(worker.helper, "raid", "archive", record["uuid"], hashlib.sha256(raw).hexdigest())
    assert any(p.read_bytes() == raw for p in journals[0].parent.glob(journals[0].name + ".history-*"))
    assert not journals[0].exists()
    command(worker.helper, "raid", "check-removal")
    print("PASS", action, "interrupted configuration update and recovery", flush=True)


def idle(array, level=None):
    md = Path("/sys/class/block") / Path(array.resolve()).name / "md"
    for _ in range(1000):
        sync = md / "sync_action"
        if (not sync.exists() or sync.read_text().strip() == "idle") and (md / "reshape_position").read_text().strip() == "none":
            if level is None or (md / "level").read_text().strip() == "raid" + level:
                return md
        time.sleep(0.2)
    raise AssertionError("Array maintenance timed out")


def run():
    assert __debug__ and os.geteuid() == 0
    uuid = os.environ["PANASMS_ACCEPTANCE_VM_UUID"]
    assert re.fullmatch(r"[0-9a-f-]{36}", uuid)
    assert Path("/sys/class/dmi/id/product_uuid").read_text().strip().lower() == uuid
    assert command("systemd-detect-virt", "--vm") in ("qemu", "kvm")
    for family in ("-4", "-6"):
        assert not json.loads(command("ip", family, "-j", "route"))
    assert not any(i["ifname"] != "lo" and "LOWER_UP" in i["flags"] for i in json.loads(command("ip", "-j", "link")))
    shares = subprocess.run(["findmnt", "-J", "-t", "virtiofs,9p,nfs,nfs4,cifs,smb3,fuse.sshfs"], capture_output=True, text=True)
    assert shares.returncode in (0, 1) and not json.loads(shares.stdout or "{}").get("filesystems")
    helper = Path(os.environ.get("PANASMS_RAID_HELPER", "/usr/lib/panasms/panasms-system-helper"))
    assert hashlib.sha256(helper.read_bytes()).hexdigest() == os.environ["PANASMS_RAID_HELPER_SHA256"]
    assert not list(Path("/var/lib/panasms-agent/raid-reshape").glob("*.json"))
    worker = Worker(helper, os.environ["PANASMS_TEST_ADMIN"])
    temp = tempfile.mkdtemp(prefix="panasms-raid-", dir="/var/tmp")
    loops = []
    array = Path("/dev/md") / ("panasms_test_" + str(os.getpid()))
    assert not os.path.lexists(array)
    try:
        for i in range(7):
            image = Path(temp) / str(i)
            with image.open("xb") as stream:
                stream.truncate(128 << 20)
            loop = command("losetup", "--find", "--show", "--partscan", str(image))
            assert re.fullmatch(r"/dev/loop[0-9]+", loop)
            loops.append(loop)
        interrupt_config(worker, "create", name=array.name, level="1", members=loops[:2])
        md = idle(array)
        marker = os.urandom(1 << 20)
        with array.open("r+b", buffering=0) as stream:
            stream.write(marker)
            os.fsync(stream.fileno())
        for level, extra in [("5", loops[2]), ("6", loops[3]), ("5", "")]:
            if level == "6":
                (md / "sync_speed_max").write_text("1000")
            worker.perform("convert", target=str(array), level=level, replacement=extra)
            if level == "6":
                worker.perform("pause", target=str(array))
                assert (md / "sync_action").read_text().strip() == "frozen"
                assert subprocess.run([helper, "raid", "check-removal"]).returncode != 0
                (md / "sync_speed_max").write_text("200000")
                worker.perform("resume", target=str(array))
            idle(array, level)
            with array.open("rb") as stream:
                assert stream.read(len(marker)) == marker
        array_uuid = (md / "uuid").read_text().strip()
        command("mdadm", "--stop", str(array))
        command("udevadm", "settle")
        for _ in range(2):
            command(helper, "raid", "recover")
        command(helper, "raid", "check-removal")
        array = Path("/dev/md/panasms-recover-" + re.sub("[:-]", "", array_uuid)[:16])
        md = idle(array)
        for entry in md.glob("dev-*"):
            if (entry / "slot").read_text().strip() == "none":
                spare = "/dev/" + entry.name[4:]
                assert spare in loops
                command("mdadm", "--manage", str(array), "--remove", spare)
        old = next("/dev/" + e.name[4:] for e in md.glob("dev-*") if (e / "slot").read_text().strip() == "0")
        assert old in loops
        command("mdadm", "--manage", str(array), "--fail", old)
        worker.perform("replace", target=str(array), member=old, replacement=loops[4])
        idle(array)
        (md / "sync_speed_max").write_text("1000")
        assert (md / ("dev-" + Path(loops[4]).name)).is_dir()
        worker.perform("grow", target=str(array), replacement=loops[5])
        worker.perform("pause", target=str(array))
        (md / "sync_speed_max").write_text("200000")
        worker.perform("resume", target=str(array))
        idle(array)
        command(helper,"raid","check-removal")
        with array.open("rb") as stream:
            assert stream.read(len(marker)) == marker
        (md / "sync_speed_max").write_text("1000")
        worker.perform("check", target=str(array))
        worker.perform("check-stop", target=str(array))
        idle(array)
        worker.perform("add", target=str(array), replacement=loops[6])
        assert (md / ("dev-" + Path(loops[6]).name)).is_dir()
        interrupt_config(worker, "delete", target=str(array))
    finally:
        errors = []
        if array.exists():
            if subprocess.run(["mdadm", "--stop", str(array)]).returncode:
                errors.append(str(array))
        for loop in reversed(loops):
            if subprocess.run(["losetup", "--detach", loop]).returncode:
                errors.append(loop)
        for image in Path(temp).iterdir():
            if command("losetup", "-j", str(image)):
                errors.append(str(image))
        if errors:
            raise RuntimeError(f"Disks still active. Inspect {temp}: {errors}")
        shutil.rmtree(temp)


if __name__ == "__main__":
    run()
