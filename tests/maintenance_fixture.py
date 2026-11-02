from pathlib import Path
import re
import shutil
import sys


class MaintenanceFixture:
    def __init__(self, root):
        self.root = Path(root)
        self.bin = self.root / "fixture-bin"
        self.bin.mkdir()
        self.log = self.root / "service-calls.log"
        self.env = {"PATH": str(self.bin), "HOME": str(self.root), "LC_ALL": "C",
                    "PYTHONDONTWRITEBYTECODE": "1", "FIXTURE_SERVICE_LOG": str(self.log)}
        for name in ("sh", "rm", "rmdir", "awk", "sed"):
            target = shutil.which(name)
            if target is None:
                raise RuntimeError("Missing fixture tool: " + name)
            (self.bin / name).symlink_to(target)
        (self.bin / "python3").symlink_to(sys.executable)
        for name in ("systemctl", "udevadm"):
            self.mock(name, 'printf "%s\\n" "' + name + ' $*" >> "$FIXTURE_SERVICE_LOG"\n'
                      'if [ "$1" = is-active ] && [ "${FIXTURE_INACTIVE:-}" = 1 ]; then exit 3; fi\n')

    def mock(self, name, body):
        path = self.bin / name
        path.write_text("#!/bin/sh\n" + body)
        path.chmod(0o755)
        return path

    def rebase(self, script):
        return re.sub(r"/(?:etc|var/lib|usr/lib|run)(?=/|[\s'\"]|$)",
                      lambda match: str(self.root) + match.group(), script)

    def calls(self):
        return self.log.read_text().splitlines() if self.log.exists() else []
