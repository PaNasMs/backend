"""Compatibility bridge for the legacy storage dispatcher; policy lives in Go."""
import json
import fcntl
from contextlib import contextmanager
from pathlib import Path
from common import command

HELPER = "/usr/lib/panasms/panasms-system-helper"
LOCK = Path("/run/panasms-disk-sleep.lock")


def validate(minutes):
    command([HELPER, "disk-sleep", "validate"], data=json.dumps({"minutes": minutes}))


def save(minutes):
    command([HELPER, "disk-sleep", "save"], data=json.dumps({"minutes": minutes}))


def query():
    return json.loads(command([HELPER, "disk-sleep", "query"]))


@contextmanager
def locked():
    with LOCK.open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        yield


def busy_arrays(kname, root=Path("/sys/class/block"), seen=None):
    seen = set() if seen is None else seen
    if kname in seen:
        return []
    seen.add(kname)
    node = root / kname
    result = []
    sync = node / "md/sync_action"
    if sync.exists() and sync.read_text().strip() != "idle":
        result.append(kname)
    for holder in (node / "holders").glob("*"):
        result += busy_arrays(holder.name, root, seen)
    for part in node.glob(kname + "*"):
        if (part / "partition").exists():
            result += busy_arrays(part.name, root, seen)
    return result
