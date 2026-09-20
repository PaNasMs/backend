#!/usr/bin/python3
import os
from pathlib import Path
import sys
import subprocess

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "management"))
import host
from common import command

unit = "nas-fixture-" + str(os.getpid()) + ".service"
path = Path("/etc/systemd/system") / unit
try:
    path.write_text(
        "[Unit]\nDescription=Disposable PaNasMs management test\n[Service]\nExecStart=/usr/bin/sleep infinity\n[Install]\nWantedBy=multi-user.target\n"
    )
    command(["systemctl", "daemon-reload"])
    for action in ["service.start", "service.restart", "service.enable", "service.disable", "service.stop"]:
        host.plan(action, {"target": unit})
        host.execute(action, {"target": unit})
        if action in ("service.start", "service.restart"):
            assert command(["systemctl", "is-active", unit]).strip() == "active"
        print("PASS", action, flush=True)
finally:
    subprocess.run(["systemctl", "disable", "--now", unit], capture_output=True)
    path.unlink(missing_ok=True)
    command(["systemctl", "daemon-reload"])
