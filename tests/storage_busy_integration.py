#!/usr/bin/python3
import os
from pathlib import Path
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "management"))
import storage
from common import Rejected

assert os.geteuid() == 0
with tempfile.TemporaryDirectory(prefix="panasms_busy_", dir="/mnt") as directory:
    nested = directory + "/nested"
    child = None
    subprocess.run(["mount", "-t", "tmpfs", "none", directory], check=True)
    try:
        Path(nested).mkdir()
        subprocess.run(["mount", "-t", "tmpfs", "none", nested], check=True)
        child = subprocess.Popen(["sleep", "120"], cwd=directory)
        inv = {"/dev/test": {"mountpoints": [directory], "parent": None}}
        try:
            storage.mount_blockers("/dev/test", inv)
            raise AssertionError("busy mount accepted")
        except Rejected as e:
            message = str(e)
            assert str(child.pid) in message and "sleep" in message and nested in message, message
            print("PASS real busy PID/process/owner and nested mount are identified")
        child.terminate()
        child.wait()
        child = None
        subprocess.run(["umount", nested], check=True)
        storage.mount_blockers("/dev/test", inv)
        print("PASS mount accepted after blockers removed")
    finally:
        if child:
            child.terminate()
            child.wait()
        subprocess.run(["umount", nested], capture_output=True)
        subprocess.run(["umount", directory], check=True)
