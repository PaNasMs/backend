#!/usr/bin/python3
"""Run the installed agent against disposable /etc and /home in a private mount namespace."""
import http.client
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time

if sys.argv[1:] != ["--isolated"]:
    raise SystemExit(
        subprocess.call(["unshare", "--mount", "--fork", "--", sys.executable, __file__, "--isolated"])
    )
subprocess.run(["mount", "--make-rprivate", "/"], check=True)
with tempfile.TemporaryDirectory(prefix="panasms-profile-test-", dir="/var/tmp") as temporary:
    root = Path(temporary)
    root.chmod(0o755)
    for name in ["usr", "etc/pam.d", "etc/security", "home/tester", "run", "tmp", "dev"]:
        (root / name).mkdir(parents=True, exist_ok=True)
    (root / "tmp").chmod(0o1777)
    (root / "run").chmod(0o700)
    for name in ["bin", "sbin", "lib"]:
        (root / name).symlink_to("usr/" + name)
    mounted = False
    agent = None
    try:
        subprocess.run(["mount", "--bind", "/usr", str(root / "usr")], check=True)
        mounted = True
        subprocess.run(["mount", "-o", "remount,bind,ro", str(root / "usr")], check=True)
        for name in ["null", "urandom"]:
            (root / "dev" / name).touch()
            subprocess.run(["mount", "--bind", "/dev/" + name, str(root / "dev" / name)], check=True)
        user = "tester"
        password = secrets.token_urlsafe(24)
        next_password = secrets.token_urlsafe(24)
        digest = (
            subprocess.check_output(["openssl", "passwd", "-6", "-stdin"], input=(password + "\n").encode())
            .decode()
            .strip()
        )
        (root / "etc/passwd").write_text(
            "root:x:0:0:root:/root:/bin/bash\ntester:x:64523:64523:Test User:/home/tester:/bin/bash\n"
        )
        (root / "etc/group").write_text("root:x:0:\ntester:x:64523:\nsudo:x:27:tester\n")
        (root / "etc/shadow").write_text(
            f"root:*:20000:0:99999:7:::\ntester:{digest}:{int(time.time()/86400)}:0:99999:7:::\n"
        )
        (root / "etc/shadow").chmod(0o600)
        (root / "etc/nsswitch.conf").write_text("passwd: files\nshadow: files\ngroup: files\n")
        shutil.copy("/etc/login.defs", root / "etc/login.defs")
        for name in ["panasms", "common-auth", "common-account", "common-password"]:
            shutil.copy("/etc/pam.d/" + name, root / "etc/pam.d" / name)
        os.chown(root / "home/tester", 64523, 64523)
        env = dict(os.environ, PANASMS_AUTH_MODE="sudo")
        env.pop("PANASMS_ALLOWED_USERS", None)
        agent = subprocess.Popen(
            [
                "chroot",
                str(root),
                "/usr/lib/panasms/panasms-agent",
                "-socket",
                "/run/agent.sock",
                "-peer-uid",
                "0",
                "-peer-gid",
                "0",
            ],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        for _ in range(50):
            if (root / "run/agent.sock").exists():
                break
            time.sleep(0.1)

        def request(path, body=None, expected=200):
            connection = http.client.HTTPConnection("agent", timeout=20)
            connection.sock = socket.socket(socket.AF_UNIX)
            connection.sock.settimeout(20)
            connection.sock.connect(str(root / "run/agent.sock"))
            connection.request(
                "POST" if body is not None else "GET",
                path,
                json.dumps(body) if body is not None else None,
                {"Content-Type": "application/json"},
            )
            response = connection.getresponse()
            raw = response.read()
            status = response.status
            connection.close()
            assert status == expected, f"{path}: expected {expected}, got {status}"
            return json.loads(raw) if status == 200 else None

        request("/authenticate", {"username": user, "password": password})
        assert request("/profile?user=tester")["name"] == "Test User"
        request("/profile?user=tester", {"action": "name", "name": "Updated Name"}, 204)
        assert request("/profile?user=tester")["name"] == "Updated Name"
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(root / "tmp/key")], check=True
        )
        request(
            "/profile?user=tester",
            {"action": "add", "key": (root / "tmp/key.pub").read_text(), "currentPassword": password},
            204,
        )
        keys = request("/profile?user=tester")["keys"]
        assert len(keys) == 1
        request(
            "/profile?user=tester",
            {"action": "delete", "id": keys[0]["id"], "currentPassword": password},
            204,
        )
        assert request("/profile?user=tester")["keys"] == []
        request(
            "/profile?user=tester",
            {"action": "password", "currentPassword": "wrong", "newPassword": next_password},
            403,
        )
        request(
            "/profile?user=tester",
            {"action": "password", "currentPassword": password, "newPassword": next_password},
            204,
        )
        request("/authenticate", {"username": user, "password": password}, 401)
        request("/authenticate", {"username": user, "password": next_password})
        request("/profile?user=root", expected=403)
        print(
            "PASS isolated real PAM change/authentication, profile name, SSH add/delete, current-password and root protection; no host accounts changed"
        )
    finally:
        if agent:
            agent.terminate()
            try:
                agent.wait(timeout=5)
            except subprocess.TimeoutExpired:
                agent.kill()
                agent.wait()
        for name in ["null", "urandom"]:
            subprocess.run(
                ["umount", str(root / "dev" / name)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
        if mounted:
            subprocess.run(["umount", str(root / "usr")], check=True)
