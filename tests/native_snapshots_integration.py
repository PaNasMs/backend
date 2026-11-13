#!/usr/bin/env python3
"""Run native Btrfs snapshot acceptance on new loop images in an offline test VM."""
import contextlib
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile


def command(*args):
    return subprocess.check_output(args, text=True).strip()


def vm_guard():
    assert __debug__ and os.geteuid() == 0
    uuid = os.environ["PANASMS_ACCEPTANCE_VM_UUID"].lower()
    assert re.fullmatch(r"[0-9a-f-]{36}", uuid)
    assert Path("/sys/class/dmi/id/product_uuid").read_text().strip().lower() == uuid
    assert command("systemd-detect-virt", "--vm") in ("qemu", "kvm")
    assert all(not json.loads(command("ip", f, "-j", "route")) for f in ("-4", "-6"))
    assert not any(i["ifname"] != "lo" and "LOWER_UP" in i["flags"] for i in json.loads(command("ip", "-j", "link")))
    shares = subprocess.run(["findmnt", "-J", "-t", "virtiofs,9p,nfs,nfs4,cifs,smb3,fuse.sshfs"],
                            capture_output=True, text=True)
    assert shares.returncode in (0, 1) and not json.loads(shares.stdout or "{}").get("filesystems")


@contextlib.contextmanager
def loop_image(root, name):
    image = root / name
    with image.open("xb") as stream:
        stream.truncate(256 << 20)
    loop = command("losetup", "--find", "--show", image)
    assert re.fullmatch(r"/dev/loop[0-9]+", loop)
    try:
        backing, = json.loads(command("losetup", "--json", "--output", "BACK-FILE", loop))["loopdevices"]
        assert Path(backing["back-file"]) == image
        yield loop
    finally:
        command("losetup", "--detach", loop)
        command("udevadm", "settle")


# Linux uapi: _IOW(0x94, 23/63, btrfs_ioctl_vol_args_v2[4096 bytes]) and _IO(0x94, 8).
SNAP_CREATE = 0x50009417
SNAP_DELETE = 0x5000943F
BTRFS_SYNC = 0x9408
KILL_PROCESS = 0x80000000
RETURN_EIO = 0x00050000 | errno.EIO


class ArgCompare(ctypes.Structure):
    _fields_ = [("arg", ctypes.c_uint), ("op", ctypes.c_uint),
                ("datum_a", ctypes.c_uint64), ("datum_b", ctypes.c_uint64)]


def fault_filter(request, decision):
    # The filter belongs only to the helper child, and matches ioctl's request argument.
    lib = ctypes.CDLL("libseccomp.so.2")
    lib.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    lib.seccomp_init.argtypes = [ctypes.c_uint32]
    lib.seccomp_init.restype = ctypes.c_void_p
    lib.seccomp_rule_add_array.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int,
                                           ctypes.c_uint, ctypes.POINTER(ArgCompare)]
    lib.seccomp_load.argtypes = lib.seccomp_release.argtypes = [ctypes.c_void_p]
    lib.seccomp_release.restype = None
    ctx = lib.seccomp_init(0x7FFF0000)  # SCMP_ACT_ALLOW
    assert ctx
    try:
        syscall = lib.seccomp_syscall_resolve_name(b"ioctl")
        selector = ArgCompare(1, 4, request, 0)  # SCMP_CMP_EQ
        assert syscall >= 0
        assert lib.seccomp_rule_add_array(ctx, decision, syscall, 1, ctypes.byref(selector)) == 0
        assert lib.seccomp_load(ctx) == 0
    finally:
        lib.seccomp_release(ctx)


class Worker:
    def __init__(self, target):
        helper = Path(os.environ.get("PANASMS_SNAPSHOTS_HELPER", "/usr/lib/panasms/panasms-system-helper"))
        assert hashlib.sha256(helper.read_bytes()).hexdigest() == os.environ["PANASMS_SNAPSHOTS_HELPER_SHA256"]
        self.args = [str(helper), os.environ["PANASMS_TEST_ADMIN"]]
        self.target = target

    def invoke(self, mode, body, fault=None, cancel=False):
        argv = [self.args[0], mode, self.args[1]]
        with contextlib.ExitStack() as stack:
            options = {}
            if fault:
                options["preexec_fn"] = lambda: fault_filter(*fault)
            if cancel:
                read, write = os.pipe()
                stack.callback(os.close, read)
                stack.callback(os.close, write)
                os.write(write, b"1")
                options.update(pass_fds=(read,), env={**os.environ, "PANASMS_CONTROL_FD": str(read)})
            result = subprocess.run(argv, input=json.dumps(body), text=True, capture_output=True,
                                    timeout=120, **options)
        if fault and fault[1] == KILL_PROCESS:
            assert result.returncode == -signal.SIGSYS and not result.stdout.strip(), (result.returncode, result.stdout)
            return None
        assert result.returncode == 0, (result.returncode, result.stderr)
        return json.loads(result.stdout)

    def request(self, action, **params):
        return {"action": "filesystem.snapshot-" + action, "params": {"target": self.target, **params}}

    def query(self):
        return self.invoke("query", {"view": "storage-snapshots", "target": self.target})

    def approved(self, action, **params):
        req = self.request(action, **params)
        plan = self.invoke("plan", req)
        assert plan.get("confirmation") == plan.get("target") == self.target and plan.get("fingerprint"), plan
        assert plan["details"], plan
        return {**req, "confirmation": plan["confirmation"], "fingerprint": plan["fingerprint"]}

    def perform(self, action, **params):
        result = self.invoke("execute", self.approved(action, **params))
        assert result.get("target") == self.target and result.get("message") and not result.get("error"), result

    def refused(self, action, reason, **params):
        result = self.invoke("plan", self.request(action, **params))
        assert reason.lower() in result.get("error", "").lower() and result.get("noChanges"), result


def read_only(path):
    return command("btrfs", "property", "get", "-ts", path, "ro") == "ro=true"


@contextlib.contextmanager
def shared_snapshot(root, point, path, volume):
    # This namespace shadows the policy file without updating the guest SMB/NFS configuration.
    state = Path("/etc/panasms/sharing.json")
    with contextlib.ExitStack() as mounts:
        if state.exists():
            cfg = json.loads(state.read_bytes())
        else:
            # Create the policy only in a disposable upper layer on fresh installations.
            upper, work = root / "upper", root / "work"
            upper.mkdir(mode=0o700)
            work.mkdir(mode=0o700)
            command("mount", "-t", "overlay", "overlay", "-o",
                    f"lowerdir={state.parent},upperdir={upper},workdir={work}", state.parent)
            mounts.callback(command, "umount", state.parent)
            state.touch(mode=0o600)
            cfg = {"shares": [], "accounts": {}}
        cfg["shares"].append({"name": "snapshot-test", "path": str(path), "mountpoint": str(point),
                              "volume": volume, "smb": True})
        overlay = root / "sharing.json"
        overlay.write_text(json.dumps(cfg))
        overlay.chmod(0o600)
        command("mount", "--bind", overlay, state)
        mounts.callback(command, "umount", state)
        yield


def interrupted(worker, point, store):
    original = (point / "data").read_bytes()
    for action, operation, params, path in (
        ("create", SNAP_CREATE, {"name": "interrupted"}, store / "interrupted"),
        ("restore", SNAP_CREATE, {"snapshot": "first", "name": "interrupted_copy"}, point / "interrupted_copy"),
        ("delete", SNAP_DELETE, {"snapshot": "interrupted"}, store / "interrupted"),
    ):
        exists_before = action == "delete"
        req = worker.approved(action, **params)
        result = worker.invoke("execute", req, cancel=True)
        assert result.get("cancelled") and result.get("noChanges") and path.exists() == exists_before, result
        result = worker.invoke("execute", req, fault=(operation, RETURN_EIO))
        assert "input/output error" in result.get("error", "").lower() and path.exists() == exists_before, result
        worker.invoke("execute", req, fault=(operation, KILL_PROCESS))
        assert path.exists() == exists_before
        worker.invoke("execute", req, fault=(BTRFS_SYNC, KILL_PROCESS))
        assert path.exists() != exists_before
        if path.exists():
            assert read_only(path) == (action == "create")
        marker = point / "interrupted_copy" / "data"
        if action == "restore":
            marker.write_text("preserve the recovered copy")
        for _ in range(2):
            report = worker.invoke("recover", worker.request(action, **params))
            assert not report.get("recoveryAction"), report
            observed = {item["label"]: item["value"] for item in report["checks"]}
            assert observed.get(str(path)) == ("Present" if path.exists() else "Absent"), report
        assert path.exists() != exists_before
        if action in ("restore", "delete"):
            assert marker.read_text() == "preserve the recovered copy"
        result = worker.invoke("execute", req)
        assert result.get("error") and result.get("noChanges"), result
        assert (point / "data").read_bytes() == original
        print("PASS", action, "cancellation, failed ioctl, interrupted write and non-replaying recovery", flush=True)


def exercise(worker, root, point):
    store = point / ".panasms-snapshots"
    before = os.urandom(4096)
    after = os.urandom(4096)
    (point / "data").write_bytes(before)
    (point / "folder").mkdir()
    nested = point / "nested"
    command("btrfs", "subvolume", "create", nested)
    (nested / "private").write_bytes(before)
    assert worker.query() == {"target": worker.target, "point": str(point), "snapshots": []}
    store.mkdir(mode=0o755)
    store.chmod(0o755)
    worker.refused("create", "private", name="untrusted")
    assert not (store / "untrusted").exists()
    store.rmdir()
    store.symlink_to(nested)
    result = worker.invoke("plan", worker.request("create", name="redirected"))
    assert result.get("error") and result.get("noChanges") and not (nested / "redirected").exists(), result
    store.unlink()
    worker.perform("create", name="first")
    snap = store / "first"
    assert read_only(snap) and store.stat().st_uid == 0 and store.stat().st_mode & 0o077 == 0
    assert not (snap / "nested/private").exists()
    (point / "data").write_bytes(after)
    assert (snap / "data").read_bytes() == before
    (store / "link").symlink_to(snap)
    (store / "ordinary").mkdir()
    command("btrfs", "subvolume", "snapshot", point, store / "writable")
    listed = worker.query()
    assert listed.get("snapshots") == [{"name": "first"}], listed
    worker.refused("create", "name", name="first")
    worker.refused("restore", "name", snapshot="first", name="data")
    restore = {"snapshot": "first", "name": "copy"}
    req = worker.approved("restore", **restore)
    snap.rename(store / "previous")
    command("btrfs", "subvolume", "snapshot", "-r", point, snap)
    result = worker.invoke("execute", req)
    assert result.get("error") == "State has changed. Review a new operation plan." and result.get("noChanges"), result
    assert not (point / "copy").exists()
    command("btrfs", "subvolume", "delete", "--commit-after", snap)
    (store / "previous").rename(snap)
    command("mount", "--bind", root, snap / "folder")
    try:
        worker.refused("delete", "mount", snapshot="first")
        worker.refused("restore", "mount", **restore)
    finally:
        command("umount", snap / "folder")
    command("btrfs", "subvolume", "snapshot", "-r", point, store / "previous_format")
    volume = command("blkid", "-s", "UUID", "-o", "value", worker.target)
    with shared_snapshot(root, point, snap / "folder", volume):
        worker.refused("delete", "share", snapshot="first")
        worker.refused("restore", "share", **restore)
    # Btrfs command-line snapshots are the legacy on-disk format.
    worker.perform("restore", snapshot="previous_format", name="legacy_copy")
    assert (point / "legacy_copy/data").read_bytes() == after
    worker.perform("delete", snapshot="previous_format")
    worker.perform("restore", **restore)
    assert not read_only(point / "copy")
    assert (point / "copy/data").read_bytes() == before
    assert (point / "data").read_bytes() == after
    assert not (point / "copy/nested/private").exists()
    assert (nested / "private").read_bytes() == before
    interrupted(worker, point, store)
    worker.perform("delete", snapshot="first")
    listed = worker.query()
    assert listed.get("snapshots") == [], listed
    assert (point / "copy/data").read_bytes() == before and (point / "data").read_bytes() == after
    print("PASS readonly snapshots, nested subvolumes, stale source, mounts, shares and original data", flush=True)
    return before, after


def main():
    vm_guard()
    if len(sys.argv) == 1:
        subprocess.run(["unshare", "--mount", "--propagation", "private", "--", sys.executable,
                        str(Path(__file__).resolve()), "--private-mounts"], check=True)
        return
    assert sys.argv[1:] == ["--private-mounts"]
    assert os.readlink("/proc/self/ns/mnt") != os.readlink("/proc/1/ns/mnt")
    with tempfile.TemporaryDirectory(dir="/var/tmp", prefix="panasms-snapshots-") as tmp:
        root = Path(tmp)
        with loop_image(root, "ext4.img") as other:
            command("mkfs.ext4", "-q", other)
            command("udevadm", "settle")
            worker = Worker(other)
            assert "btrfs" in worker.query().get("error", "").lower()
            worker.refused("create", "Btrfs", name="refused")
        with loop_image(root, "btrfs.img") as loop:
            command("mkfs.btrfs", "-f", loop)
            command("udevadm", "settle")
            with tempfile.TemporaryDirectory(dir="/mnt", prefix="panasms-snapshots-") as mount:
                point = Path(mount)
                command("mount", loop, point)
                try:
                    before, after = exercise(Worker(loop), root, point)
                finally:
                    command("umount", point)
                command("mount", "-o", "ro", loop, point)
                try:
                    assert (point / "copy/data").read_bytes() == before and (point / "data").read_bytes() == after
                    Worker(loop).refused("create", "read-only", name="refused")
                finally:
                    command("umount", point)
    print("PASS native snapshot acceptance", flush=True)


if __name__ == "__main__":
    main()
