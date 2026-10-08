import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
import sys


class Rejected(Exception):
    pass


def require(ok, message):
    if not ok:
        raise Rejected(message)


def command(args, *, data=None, accepted=(0,), timeout=120):
    if os.environ.get("PANASMS_OPERATION") == "1":
        stages = {
            "mdadm": 'Modifying array',
            "mkfs.ext4": 'Creating file system',
            "mkfs.xfs": 'Creating file system',
            "mkfs.btrfs": 'Creating file system',
            "mkfs.vfat": 'Creating file system',
            "sfdisk": 'Modifying partition',
            "parted": 'Modifying partition table',
            "e2fsck": 'Checking file system',
            "resize2fs": 'Resizing file system',
            "btrfs": 'Modifying file system',
            "xfs_growfs": 'Growing file system',
            "mount": 'Mounting volume',
            "umount": 'Unmounting volume',
            "cryptsetup": 'Processing encrypted volume',
            "rsync": "Copying and verifying home folders",
            "useradd": 'Creating user',
            "usermod": 'Updating user',
            "userdel": 'Deleting user',
            "chpasswd": 'Change password',
            "apt-get": 'Updating packages',
            "systemctl": 'Applying service state',
            "update-initramfs": 'Updating boot configuration',
            "udevadm": 'Checking device state',
            "smartctl": 'Submitting SMART test command',
        }
        print(
            json.dumps({"stage": stages.get(Path(args[0]).name, 'Applying changes')}),
            file=sys.stderr,
            flush=True,
        )
    result = subprocess.run(
        args,
        input=data,
        capture_output=True,
        text=True,
        timeout=timeout,
        env={**os.environ, "LC_ALL": "C", "DEBIAN_FRONTEND": "noninteractive"},
    )
    if result.returncode not in accepted:
        failures = {
            'No space left on device': 'The destination is full. Free space or choose another destination, then retry.',
            'Disk quota exceeded': 'The destination is full. Free space or choose another destination, then retry.',
            'Read-only file system': 'The destination is read-only. Check the file system before retrying.',
            'Input/output error': 'The storage device was disconnected or failed during the operation. Reconnect it, check the file system, then retry.',
        }
        for signature, message in failures.items():
            if signature in result.stderr:
                raise Rejected(message)
        # cryptsetup exits with 2 when no key slot accepts the supplied passphrase.
        if Path(args[0]).name == "cryptsetup" and result.returncode == 2:
            raise Rejected('The LUKS password is incorrect')
    require(
        result.returncode in accepted,
        f"Command {Path(args[0]).name} exited with code {result.returncode}. Check the object's state and system journal.",
    )
    return result.stdout


def json_command(args, **kwargs):
    return json.loads(command(args, **kwargs))


def name(value):
    require(isinstance(value, str) and re.fullmatch(r"[a-z_][a-z0-9_-]{0,30}", value), 'Invalid name')
    return value


def integer(value, low, high):
    require(
        isinstance(value, int) and not isinstance(value, bool) and low <= value <= high,
        'Number outside the allowed range',
    )
    return value


def atomic(path, text, mode=0o600):
    path = Path(path)
    require(not path.is_symlink(), 'The configuration is a symbolic link')
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        backup = Path("/var/lib/panasms-agent/backups")
        backup.mkdir(parents=True, exist_ok=True, mode=0o700)
        prefix = path.name + "." + hashlib.sha256(str(path.absolute()).encode()).hexdigest()[:16] + "."
        saved = backup / (prefix + str(time.time_ns()))
        shutil.copyfile(path, saved)
        saved.chmod(0o600)
        copies = sorted((p for p in backup.iterdir() if p.name.startswith(prefix) and p.name[len(prefix):].isdigit() and p.is_file() and not p.is_symlink()), key=lambda p: int(p.name[len(prefix):]), reverse=True)
        for old in copies[10:]:
            old.unlink(missing_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".panasms-", dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        parent = os.open(path.parent, os.O_DIRECTORY)
        os.fsync(parent)
        os.close(parent)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def fingerprint(action, params, state):
    def redact(value):
        if isinstance(value, dict):
            return {k: redact(v) for k, v in value.items() if not any(secret in k.lower() for secret in ("password", "passphrase", "secret", "token"))}
        if isinstance(value, list):
            return [redact(v) for v in value]
        return value
    public = redact(params)
    return hashlib.sha256(
        json.dumps([action, public, state], sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def clean_path(value):
    require(
        isinstance(value, str)
        and value.startswith("/")
        and len(value) < 1024
        and not any(ord(c) < 32 for c in value),
        'Invalid path',
    )
    require(
        str(Path(value)) == value and ".." not in Path(value).parts,
        'The path must be absolute and normalized',
    )
    return Path(value)
