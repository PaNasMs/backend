#!/usr/bin/env python3
"""Exercise the privileged native helper against fresh images in an offline test VM."""
import hashlib
import json
import os
import pwd
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import tempfile
import threading


def command(*args):
    return subprocess.check_output(args, text=True).strip()


class Worker:
    def __init__(self):
        self.helper = os.environ["PANASMS_LUKS_HELPER"]
        assert hashlib.sha256(Path(self.helper).read_bytes()).hexdigest() == os.environ["PANASMS_LUKS_HELPER_SHA256"]
        self.actor = os.environ["PANASMS_TEST_ADMIN"]
        self.secrets = [secrets.token_hex(20) for _ in range(3)]
        self.leaked = False

    def check(self, data):
        if any(password.encode() in data for password in self.secrets):
            self.leaked = True
            raise AssertionError("Found a test password outside the request")

    def invoke(self, mode, request):
        result = subprocess.run([self.helper, mode, self.actor], input=json.dumps(request).encode(),
                                capture_output=True, check=True, timeout=600)
        self.check(result.stdout + result.stderr)
        return json.loads(result.stdout)

    def action(self, action, failure=None, **params):
        request = dict(action="luks." + action, params=params)
        command("udevadm", "settle")
        phase = "plan"
        result = self.invoke(phase, request)
        if "error" not in result:
            request.update({field: result[field] for field in ("confirmation", "fingerprint")})
            phase = "execute"
            result = self.invoke(phase, request)
        if failure:
            assert (phase, result.get("error")) == failure, (action, phase, result)
        else:
            assert "error" not in result, (action, phase, result)
        print("PASS", action, "rejected" if failure else "completed", flush=True)

    def query(self, target):
        return self.invoke("query", dict(view="storage-luks", target=target))

    def monitor(self, done):
        while not done.is_set():
            for file in Path("/proc").glob("[0-9]*/cmdline"):
                try:
                    self.check(file.read_bytes())
                except OSError:
                    continue
            done.wait(0.1)


def replaced_device(worker, root, loop, restore):
    # A block-for-block clone has the same UUID, header and key slots.
    clone = root / "clone.img"
    other = None
    alias = Path("/dev") / ("panasms_test_restore_" + str(os.getpid()))
    alias.symlink_to(loop)
    try:
        request = dict(action=restore["action"], params=dict(restore["params"], target=str(alias)))
        plan = worker.invoke("plan", request)
        assert "fingerprint" in plan, plan
        shutil.copyfile(root / "disk.img", clone)
        other = command("losetup", "--find", "--show", clone)
        assert re.fullmatch(r"/dev/loop[0-9]+", other) and other != loop
        command("udevadm", "settle")
        alias.unlink()
        alias.symlink_to(other)
        result = worker.invoke("execute", dict(request, fingerprint=plan["fingerprint"], confirmation=plan["confirmation"]))
        assert result.get("error") == "State has changed. Review a new operation plan." and result.get("noChanges"), result
        assert command("cryptsetup", "luksDump", "--dump-json-metadata", other) == command("cryptsetup", "luksDump", "--dump-json-metadata", loop)
    finally:
        alias.unlink(missing_ok=True)
        if other:
            command("losetup", "--detach", other)
        command("udevadm", "settle")


def exercise(worker, root, loop):
    first, second, wrong = worker.secrets
    mapping = "panasms_test_" + str(os.getpid())
    mapped = "/dev/mapper/" + mapping
    assert not os.path.lexists(mapped)
    params = dict(target=loop, passphrase=first)
    worker.action("create", **params)
    command("udevadm", "settle")
    original = worker.query(loop)
    uuid = original["uuid"]
    assert original == dict(target=loop, uuid=uuid, slots=[0], automatic=False, managedSlot=None)
    worker.action("open", target=loop, name=mapping, passphrase=wrong, failure=("execute", "The LUKS password did not unlock this volume"))
    worker.action("open", **params, name=mapping)
    command("mkfs.ext4", "-q", mapped)
    mount = Path("/mnt") / mapping
    mount.mkdir(mode=0o700)
    command("mount", mapped, mount)
    try:
        (mount / "marker").write_text(uuid)
        worker.action("close", target=mapped, failure=("plan", "Unmount file systems first"))
    finally:
        command("umount", mount)
    worker.action("close", target=mapped)
    worker.action("header-backup", target=loop, folder=str(root))
    backup = root / (uuid + ".luks-header")
    owner = pwd.getpwnam(worker.actor)
    assert backup.is_file() and backup.stat().st_mode & 0o777 == 0o600
    assert (backup.stat().st_uid, backup.stat().st_gid) == (owner.pw_uid, owner.pw_gid)
    worker.action("key-remove", **params, slot=0, failure=("plan", "The last LUKS key cannot be removed"))
    worker.action("key-add", **params, password=second)
    worker.action("key-remove", **params, slot=0, failure=("execute", "Enter a password that unlocks a different key slot"))
    slot, = set(worker.query(loop)["slots"]) - {0}
    worker.action("key-remove", **params, slot=slot)
    worker.action("open", target=loop, name=mapping, passphrase=second, failure=("execute", "The LUKS password did not unlock this volume"))
    worker.action("key-add", **params, password=second)
    restore = dict(action="luks.header-restore", params=dict(target=loop, folder=str(root)))
    replaced_device(worker, root, loop, restore)
    plan = worker.invoke("plan", restore)
    assert "fingerprint" in plan, plan
    moved = backup.with_suffix(".original")
    backup.rename(moved)
    # Back up the current two-slot volume. Both backups are genuine.
    command("cryptsetup", "luksHeaderBackup", "--header-backup-file", backup, loop)
    assert command("cryptsetup", "luksUUID", backup) == uuid
    stale = worker.invoke("execute", dict(**restore, confirmation=plan["confirmation"], fingerprint=plan["fingerprint"]))
    assert stale.get("error") == "State has changed. Review a new operation plan." and stale.get("noChanges"), stale
    assert worker.query(loop)["slots"] == [0, slot]
    backup.unlink()
    moved.rename(backup)
    worker.action("header-restore", target=loop, folder=str(root))
    assert worker.query(loop)["slots"] == [0]
    # The Python helper persists its slot reservation before enrolling the key.
    # Resume that exact interruption boundary with the native worker.
    records = Path("/etc/panasms/luks")
    records.mkdir(mode=0o700, parents=True, exist_ok=True)
    record = records / (uuid + ".json")
    assert not record.exists()
    with record.open("x") as stream:
        os.fchmod(stream.fileno(), 0o600)
        json.dump(dict(uuid=uuid, name=mapping, slot=31), stream)
    interrupted = worker.query(loop)
    assert interrupted["managedSlot"] == 31 and not interrupted["automatic"]
    worker.action("auto-enable", **params, name=mapping)
    policy = worker.query(loop)
    assert policy["automatic"] and policy["managedSlot"] in policy["slots"]
    key = Path("/etc/panasms/luks") / (uuid + ".key")
    assert key.stat().st_mode & 0o777 == 0o600 and key.stat().st_uid == 0
    worker.action("key-remove", **params, slot=policy["managedSlot"], failure=("plan", "Disable automatic unlocking before removing its key"))
    unit = "systemd-cryptsetup@" + mapping + ".service"
    command("systemctl", "start", unit)
    command("mount", mapped, mount)
    try:
        assert (mount / "marker").read_text() == uuid
    finally:
        command("umount", mount)
    command("systemctl", "stop", unit)
    mount.rmdir()
    worker.action("auto-disable", **params)
    assert worker.query(loop) == original and not key.exists()
    report = worker.invoke("recover", dict(action="luks.key-add", params=dict(target=loop)))
    assert report["checks"] and worker.query(loop) == original
    for directory in (Path("/etc/panasms/luks"), Path("/var/lib/panasms-agent")):
        for file in directory.rglob("*.json"):
            if file.is_file():
                worker.check(file.read_bytes())
    worker.check(command("journalctl", "-b", "--no-pager", "-o", "cat").encode())

    # Older containers retain basic open/close support.
    subprocess.run(["cryptsetup", "luksFormat", "--batch-mode", "--type", "luks1",
                    "--iter-time", "10", "--key-file", "-", loop], input=first.encode(), check=True)
    command("udevadm", "settle")
    assert "require LUKS2" in worker.query(loop)["error"]
    worker.action("open", **params, name=mapping)
    worker.action("close", target=mapped)


def main():
    assert __debug__ and os.geteuid() == 0
    assert Path("/sys/class/dmi/id/product_uuid").read_text().strip() == os.environ["PANASMS_ACCEPTANCE_VM_UUID"]
    assert command("systemd-detect-virt", "--vm") in ("qemu", "kvm")
    assert all(not json.loads(command("ip", family, "-j", "route")) for family in ("-4", "-6"))
    assert not any(i["ifname"] != "lo" and "LOWER_UP" in i["flags"] for i in json.loads(command("ip", "-j", "link")))
    worker = Worker()
    done = threading.Event()
    monitor = threading.Thread(target=worker.monitor, args=(done,), daemon=True)
    monitor.start()
    try:
        with tempfile.TemporaryDirectory(dir="/var/tmp", prefix="panasms-luks-test-") as tmp:
            root = Path(tmp)
            image = root / "disk.img"
            with image.open("xb") as stream:
                stream.truncate(128 << 20)
            loop = command("losetup", "--find", "--show", image)
            assert re.fullmatch(r"/dev/loop[0-9]+", loop)
            try:
                exercise(worker, root, loop)
            finally:
                command("losetup", "--detach", loop)
    finally:
        done.set()
        monitor.join()
    assert not worker.leaked
    print("PASS native LUKS, systemd boot policy and secret checks", flush=True)


if __name__ == "__main__":
    main()
