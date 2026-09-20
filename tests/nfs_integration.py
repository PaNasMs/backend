#!/usr/bin/python3
import os
from pathlib import Path
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "management"))
import host
from common import command

assert os.geteuid() == 0
with tempfile.TemporaryDirectory(prefix="panasms-nfs-test-", dir="/var/tmp") as scratch:
    source = "/mnt/panasms_nfs_source_" + str(os.getpid())
    client = "/mnt/panasms_nfs_client_" + str(os.getpid())
    loop = None
    try:
        image = Path(scratch) / "disk.img"
        with image.open("wb") as f:
            f.truncate(96 * 1048576)
        loop = command(["losetup", "--find", "--show", str(image)]).strip()
        command(["mkfs.ext4", "-F", loop])
        Path(source).mkdir()
        Path(client).mkdir()
        command(["mount", loop, source])
        os.chown(source, 1000, 1000)
        params = {"target": source, "clients": "127.0.0.1/32", "readOnly": False}
        host.plan("nfs.export", params)
        host.execute("nfs.export", params)
        mount = {"target": "127.0.0.1:" + source, "point": client, "automount": False}
        host.plan("nfs.mount", mount)
        host.execute("nfs.mount", mount)
        command(
            [
                "runuser",
                "-u",
                "pasha",
                "--",
                "python3",
                "-c",
                'from pathlib import Path; import sys; p=Path(sys.argv[1]);p.write_text("NFS roundtrip");assert p.read_text()=="NFS roundtrip"',
                client + "/fixture",
            ]
        )
        assert Path(source + "/fixture").read_text() == "NFS roundtrip"
        host.plan("nfs.unmount", {"target": client})
        host.execute("nfs.unmount", {"target": client})
        host.plan("nfs.export-remove", {"target": source})
        host.execute("nfs.export-remove", {"target": source})
        print("PASS NFS export/mount/read/write/unmount/unexport with Linux UID permissions")
    finally:
        subprocess.run(["umount", client], capture_output=True)
        conf = Path("/etc/exports.d/panasms.exports")
        if conf.exists():
            conf.write_text(
                "\n".join(line for line in conf.read_text().splitlines() if not line.startswith(source + " "))
                + "\n"
            )
            subprocess.run(["exportfs", "-ra"], check=True)
        subprocess.run(["umount", source], capture_output=True)
        if loop:
            subprocess.run(["losetup", "--detach", loop], check=True)
        for p in (source, client):
            try:
                Path(p).rmdir()
            except FileNotFoundError:
                pass
