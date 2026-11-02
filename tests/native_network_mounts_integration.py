#!/usr/bin/env python3
"""VM-only native folder and network-mount acceptance.

Set PANASMS_TEST_VM_UUID to the verified disposable guest UUID, then pass the
candidate helper path and SHA256. Runs real loopback SMB/NFS in new mount/PID/net
namespaces and a private root, with synthetic accounts and owned loop storage.
The only systemctl fixture supports daemon-reload; no guest service bus is exposed.
"""
import hashlib, json, os, secrets, shutil, signal, subprocess, sys, tempfile, time
from pathlib import Path

UUID = os.environ.get("PANASMS_TEST_VM_UUID", "").lower()


def cmd(*args, **kw):
    return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT, **kw).strip()


def guard():
    assert (
        UUID
        and os.geteuid() == 0
        and Path("/sys/class/dmi/id/product_uuid").read_text().strip().lower() == UUID
    )
    assert cmd("systemd-detect-virt", "--vm") in ("kvm", "qemu")
    assert not any(
        x["ifname"] != "lo" and "LOWER_UP" in x["flags"] for x in json.loads(cmd("ip", "-j", "link"))
    )
    assert not json.loads(cmd("ip", "-j", "route")) and not json.loads(cmd("ip", "-6", "-j", "route"))
    r = subprocess.run(
        ["findmnt", "-J", "-t", "virtiofs,9p,nfs,nfs4,cifs,fuse.sshfs"], capture_output=True, text=True
    )
    assert r.returncode in (0, 1) and not json.loads(r.stdout or "{}").get("filesystems")


def outer():
    guard()
    binary = Path(sys.argv[1])
    expected = sys.argv[2]
    assert not binary.is_symlink() and hashlib.sha256(binary.read_bytes()).hexdigest() == expected
    with tempfile.TemporaryDirectory(prefix="panasms-go07-network-", dir="/var/tmp") as tmp:
        scratch = Path(tmp)
        root = scratch / "root"
        root.mkdir()
        image = scratch / "volume.img"
        with image.open("wb") as f:
            f.truncate(128 * 1024 * 1024)
        loop = cmd("losetup", "--find", "--show", str(image))
        try:
            assert (
                Path(
                    json.loads(cmd("losetup", "--json", "--output", "BACK-FILE", loop))["loopdevices"][0][
                        "back-file"
                    ]
                ).resolve()
                == image.resolve()
            )
            cmd("mkfs.ext4", "-q", "-F", loop)
            r = subprocess.Popen(
                [
                    "unshare",
                    "--mount",
                    "--pid",
                    "--fork",
                    "--net",
                    "--",
                    sys.executable,
                    __file__,
                    "--namespace",
                    str(root),
                    loop,
                    str(binary.resolve()),
                    secrets.token_hex(16),
                ],
                start_new_session=True,
            )
            try:
                r.wait(timeout=360)
            except subprocess.TimeoutExpired:
                os.killpg(r.pid, signal.SIGKILL)
                r.wait()
                raise
            if r.returncode:
                for log in (root / "fixture").glob("rpc*.log"):
                    print(log.name, log.read_text()[-4000:], flush=True)
            assert r.returncode == 0, r.returncode
            print(
                json.dumps(
                    {
                        "result": "PASS",
                        "helperSHA256": expected,
                        "scope": "native SMB/NFS helper lifecycle in private root and namespaces",
                    }
                ),
                flush=True,
            )
        finally:
            assert (
                Path(
                    json.loads(cmd("losetup", "--json", "--output", "BACK-FILE", loop))["loopdevices"][0][
                        "back-file"
                    ]
                ).resolve()
                == image.resolve()
            )
            cmd("losetup", "--detach", loop)


def namespace(root, loop, binary, nonce):
    assert os.getpid() == 1
    guard()
    cmd("mount", "--make-rprivate", "/")
    root = Path(root)
    for name in (
        "usr/bin",
        "usr/sbin",
        "usr/lib/panasms",
        "etc/panasms",
        "etc/samba",
        "etc/pam.d",
        "etc/exports.d",
        "proc",
        "dev",
        "tmp",
        "run",
        "run/rpcbind",
        "fixture/bin",
        "srv/data",
        "var/lib/panasms-agent",
        "var/lib/panasms-updates",
        "var/lib/samba/private",
        "var/cache/samba",
        "var/log/samba",
        "var/lib/nfs/rpc_pipefs",
        "var/lib/nfs/v4recovery",
        "var/lib/nfs/sm",
        "var/lib/nfs/sm.bak",
        "var/lock",
        "mnt",
        "root",
    ):
        (root / name).mkdir(parents=True, exist_ok=True)
    for name in ("bin", "sbin", "lib", "lib64"):
        (root / name).symlink_to("usr/" + name)
    for name in (
        "bin",
        "sbin",
        "lib64",
        "lib/x86_64-linux-gnu",
        *[str(x.relative_to("/usr")) for x in Path("/usr/lib").glob("python3*") if x.is_dir()],
        "share/samba",
    ):
        target = root / "usr" / name
        target.mkdir(parents=True, exist_ok=True)
        cmd("mount", "--bind", "/usr/" + name, str(target))
        cmd("mount", "-o", "remount,bind,ro", str(target))
    cmd("mount", "-t", "proc", "proc", str(root / "proc"))
    for name in ("null", "urandom", "random", "zero"):
        (root / "dev" / name).touch()
        cmd("mount", "--bind", "/dev/" + name, str(root / "dev" / name))
    cmd("mount", loop, str(root / "srv/data"))
    for name in ("netconfig", "services", "protocols", "rpc"):
        if Path("/etc", name).is_file():
            shutil.copy(Path("/etc", name), root / "etc" / name)
    (root / "tmp").chmod(0o1777)
    (root / "fixture/nonce").write_text(nonce)
    (root / "etc/nsswitch.conf").write_text("passwd: files\ngroup: files\nshadow: files\n")
    (root / "etc/hosts").write_text("127.0.0.1 localhost\n")
    (root / "etc/passwd").write_text(
        "root:x:0:0:root:/root:/bin/bash\nadmin:x:15000:15000:Admin:/srv/data/homes/admin:/bin/bash\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n_rpc:x:15004:15004:rpcbind:/run/rpcbind:/usr/sbin/nologin\n"
    )
    (root / "etc/group").write_text(
        "root:x:0:\nsudo:x:27:admin\nadmin:x:15000:\nnogroup:x:65534:\n_rpc:x:15004:\n"
    )
    (root / "etc/shadow").write_text("root:!:1:0:99999:7:::\nadmin:!:1:0:99999:7:::\n")
    (root / "etc/shadow").chmod(0o600)
    (root / "etc/pam.d/samba").write_text("account required pam_permit.so\nsession required pam_permit.so\n")
    (root / "etc/fstab").write_text("# private GO07 fixture\n")
    (root / "etc/exports").write_text("")
    tool = root / "fixture/bin/systemctl"
    tool.write_text(
        '#!/usr/bin/python3\nimport sys,os,time,json\nfrom pathlib import Path\nassert sys.argv[1:]==["daemon-reload"],sys.argv\nif Path("/fixture/pause-reload").exists():\n Path("/fixture/reload-event").write_text(json.dumps({"pid":os.getpid()}))\n while True:time.sleep(.05)\n'
    )
    tool.chmod(0o755)
    shutil.copy(binary, root / "usr/lib/panasms/panasms-system-helper")
    (root / "usr/lib/panasms/panasms-system-helper").chmod(0o755)
    shutil.copy(__file__, root / "fixture/harness.py")
    os.chroot(root)
    os.chdir("/fixture")
    os.environ["PATH"] = "/fixture/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    os.environ["GO07_NONCE"] = nonce
    os.execv("/usr/bin/python3", ["/usr/bin/python3", "/fixture/harness.py", "--scenarios"])


def invoke(mode, action, p):
    body = {"action": action, "params": p}
    if mode == "execute":
        plan = invoke("plan", action, p)
        assert not plan.get("error"), plan
        body.update(fingerprint=plan["fingerprint"], confirmation=plan["confirmation"])
    r = subprocess.run(
        ["/usr/lib/panasms/panasms-system-helper", mode, "admin"],
        input=json.dumps(body),
        text=True,
        capture_output=True,
        timeout=150,
    )
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


def op(action, p):
    r = invoke("execute", action, p)
    assert not r.get("error"), r
    return r


def scenarios():
    nonce = os.environ.get("GO07_NONCE", "")
    assert os.getpid() == 1 and len(nonce) == 32 and Path("/fixture/nonce").read_text() == nonce
    cmd("ip", "link", "set", "lo", "up")
    homes = Path("/srv/data/homes")
    homes.mkdir(mode=0o711)
    home = homes / "admin"
    home.mkdir(mode=0o700)
    os.chown(home, 15000, 15000)
    (home / "Visible").mkdir()
    os.chown(home / "Visible", 15000, 15000)
    query = subprocess.run(
        ["/usr/lib/panasms/panasms-system-helper", "query", "admin"],
        input=json.dumps({"view": "personal-folders", "target": str(home)}),
        capture_output=True,
        text=True,
    )
    assert query.returncode == 0, query.stderr
    result = json.loads(query.stdout)
    assert not result.get("error") and [x["name"] for x in result["folders"]] == ["Visible"], result
    denied = subprocess.run(
        ["/usr/lib/panasms/panasms-system-helper", "query", "admin"],
        input=json.dumps({"view": "personal-folders", "target": "/root"}),
        capture_output=True,
        text=True,
    )
    assert json.loads(denied.stdout).get("error")
    print(
        "PASS actual dropped-user personal browsing through search-only parent and home boundary", flush=True
    )
    policy = Path("/srv/data/policy")
    policy.mkdir(mode=0o700)
    child = policy / "child"
    child.write_text("unchanged")
    before = child.stat()
    cmd("setfacl", "-m", "d:u:15000:rwx", str(policy))
    defaults = lambda: [
        line for line in cmd("getfacl", "-cp", str(policy)).splitlines() if line.startswith("default:")
    ]
    original_defaults = defaults()
    op("folder.permissions", dict(target=str(policy), owner="admin", group="admin", mode="2770"))
    after = policy.stat()
    assert (after.st_uid, after.st_gid, after.st_mode & 0o7777) == (15000, 15000, 0o2770)
    assert defaults() == original_defaults and (child.stat().st_uid, child.stat().st_mode) == (
        before.st_uid,
        before.st_mode,
    )
    print("PASS actual nonrecursive folder owner/mode change preserves default ACL and child", flush=True)
    share = Path("/srv/data/share")
    share.mkdir()
    share.chmod(0o777)
    (share / "payload").write_text("GO07 payload")
    Path("/etc/samba/smb.conf").write_text(
        "[global]\nsecurity = user\nmap to guest = Never\ninterfaces = lo\nbind interfaces only = yes\npid directory = /run\n[Fixture]\npath = /srv/data/share\nread only = no\nvalid users = admin\n"
    )
    password = secrets.token_urlsafe(24)
    r = subprocess.run(
        ["smbpasswd", "-s", "-a", "admin"],
        input=password + "\n" + password + "\n",
        text=True,
        capture_output=True,
    )
    assert r.returncode == 0
    processes = []
    try:
        for args in (
            ["smbd", "-F", "--no-process-group"],
            ["rpcbind", "-f", "-w"],
            ["rpc.statd", "--foreground", "--no-notify", "--no-syslog"],
            ["rpc.mountd", "-F", "-N", "2", "-N", "4"],
        ):
            log = open("/fixture/" + args[0] + ".log", "w")
            processes.append(subprocess.Popen(args, stdout=log, stderr=log))
            time.sleep(0.3)
            assert processes[-1].poll() is None
        cmd("mount", "-t", "nfsd", "nfsd", "/proc/fs/nfsd")
        cmd("rpc.nfsd", "-N", "4", "4")
        Path("/etc/exports").write_text(
            "/srv/data/share 127.0.0.1(rw,sync,no_subtree_check,no_root_squash)\n"
        )
        cmd("exportfs", "-ra")
        original = Path("/etc/fstab").read_bytes()
        interrupted = dict(
            target="//127.0.0.1/Fixture",
            point="/mnt/interrupted",
            username="admin",
            password=password,
            automount=True,
        )
        plan = invoke("plan", "smb.mount", interrupted)
        assert not plan.get("error"), plan
        assert password not in json.dumps(plan)
        Path("/fixture/pause-reload").touch()
        body = dict(
            action="smb.mount",
            params=interrupted,
            fingerprint=plan["fingerprint"],
            confirmation=plan["confirmation"],
        )
        worker = subprocess.Popen(
            ["/usr/lib/panasms/panasms-system-helper", "execute", "admin"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        worker.stdin.write(json.dumps(body))
        worker.stdin.close()
        event = Path("/fixture/reload-event")
        for _ in range(200):
            if event.exists():
                break
            assert worker.poll() is None
            time.sleep(0.05)
        assert event.exists()
        paused = json.loads(event.read_text())["pid"]
        assert b"/fixture/bin/systemctl" in Path("/proc", str(paused), "cmdline").read_bytes()
        os.kill(worker.pid, signal.SIGKILL)
        os.kill(paused, signal.SIGKILL)
        worker.wait(timeout=10)
        Path("/fixture/pause-reload").unlink()
        event.unlink()
        assert Path("/mnt/interrupted/payload").read_text() == "GO07 payload"
        assert list(Path("/etc/panasms/network-credentials").iterdir())
        assert all(
            x.stat().st_uid == 0 and x.stat().st_mode & 0o777 == 0o600
            for x in Path("/etc/panasms/network-credentials").iterdir()
        )
        op("smb.unmount", {"target": "/mnt/interrupted"})
        assert Path("/etc/fstab").read_bytes() == original and not list(
            Path("/etc/panasms/network-credentials").iterdir()
        )
        print(
            "PASS real helper SIGKILL after fstab publication recovers by explicit ordinary unmount",
            flush=True,
        )

        bad = dict(
            target="//127.0.0.1/Fixture",
            point="/mnt/bad",
            username="admin",
            password="wrong-password",
            automount=True,
        )
        assert invoke("execute", "smb.mount", bad).get("error")
        assert Path("/etc/fstab").read_bytes() == original and not list(
            Path("/etc/panasms/network-credentials").glob("*")
        )
        print("PASS invalid SMB credentials leave no credential or fstab state", flush=True)
        transient = dict(
            target="//127.0.0.1/Fixture",
            point="/mnt/transient",
            username="admin",
            password=password,
            automount=False,
        )
        op("smb.mount", transient)
        cmd("umount", "/mnt/transient")
        key = hashlib.sha256(b"/mnt/transient").hexdigest()[:24]
        journal = Path("/var/lib/panasms-agent/network-mounts", key + ".json")
        record = json.loads(journal.read_text())
        record["bootID"] = "fixture-prior-boot"
        journal.write_text(json.dumps(record))
        op("smb.mount", transient)
        op("smb.unmount", {"target": "/mnt/transient"})
        assert Path("/etc/fstab").read_bytes() == original and not journal.exists()
        print(
            "PASS real remount using synthetic prior-boot journal after mount disappearance (not a cold-boot test)",
            flush=True,
        )
        for protocol, source in [("smb", "//127.0.0.1/Fixture"), ("nfs", "127.0.0.1:/srv/data/share")]:
            for readonly in (False, True):
                point = "/mnt/" + protocol
                p = dict(
                    target=source,
                    point=point,
                    username="admin",
                    password=password,
                    automount=True,
                    readOnly=readonly,
                )
                op(protocol + ".mount", p)
                assert Path(point, "payload").read_text() == "GO07 payload"
                assert invoke("plan", protocol + ".mount", p).get("error")
                if readonly:
                    assert "ro" in cmd("findmnt", "-n", "-o", "OPTIONS", "--target", point).split(",")
                    try:
                        Path(point, "readonly-denied").write_text("no")
                    except OSError:
                        pass
                    else:
                        raise AssertionError("read-only mount writable")
                else:
                    Path(point, "written-" + protocol).write_text("written")
                    busy = open(point + "/payload")
                    assert invoke("plan", protocol + ".unmount", {"target": point}).get("error")
                    busy.close()
                    child = Path(point, "nested")
                    child.mkdir(exist_ok=True)
                    cmd("mount", "-t", "tmpfs", "go07-child", str(child))
                    assert invoke("plan", protocol + ".unmount", {"target": point}).get("error")
                    cmd("umount", str(child))
                op(protocol + ".unmount", {"target": point})
                assert Path("/etc/fstab").read_bytes() == original
                assert not list(Path("/etc/panasms/network-credentials").glob("*"))
                print(
                    "PASS "
                    + protocol
                    + " lifecycle readonly="
                    + str(readonly)
                    + " duplicate/busy/nested checks as applicable",
                    flush=True,
                )
    finally:
        subprocess.run(["exportfs", "-ua"], capture_output=True)
        subprocess.run(["rpc.nfsd", "0"], capture_output=True)
        for p in processes:
            p.terminate()
        for p in processes:
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait()


if __name__ == "__main__":
    if sys.argv[1:2] == ["--namespace"]:
        namespace(*sys.argv[2:])
    elif sys.argv[1:] == ["--scenarios"]:
        scenarios()
    elif len(sys.argv) == 3:
        outer()
    else:
        raise SystemExit("Usage: native_network_mounts_integration.py HELPER SHA256")
