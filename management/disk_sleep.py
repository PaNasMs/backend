import json
import os
import re
import sys
from pathlib import Path
from common import Rejected, require, command, atomic, integer

CONFIG = Path("/etc/ostojaos/disk-sleep.json")
STATE = Path("/run/ostojaos-disk-sleep/state.json")
TIMEOUTS = (0, 5, 10, 15, 20, 30, 60, 120, 180, 300)


def timer_value(minutes):
    integer(minutes, 0, 300)
    require(minutes in TIMEOUTS, 'Select a sleep timeout from the list')
    return minutes * 12 if minutes <= 20 else 240 + minutes // 30


def check_disk(target, inv):
    from storage import protected

    row = inv[target]
    require(
        row["type"] == "disk" and row.get("tran") == "sata" and row.get("rota") and row.get("serial"),
        'Sleep is supported only for SATA HDDs with a serial number',
    )
    protected(target, inv)
    require(bool(__import__("shutil").which("hdparm")), 'The hdparm package is required to configure disk sleep')


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


def read():
    return json.loads(CONFIG.read_text()) if CONFIG.exists() else None


def save(minutes):
    timer_value(minutes)
    atomic(CONFIG, json.dumps({"minutes": minutes}))
    command(["systemctl", "enable", "--now", "ostojaos-disk-sleep.timer"])
    command(["systemctl", "start", "ostojaos-disk-sleep.service"])


def apply(disable=False):
    from storage import inventory

    cfg = read()
    if cfg is None:
        return
    if disable:
        cfg = {"minutes": 0}
    value = timer_value(cfg["minutes"])
    inv = inventory()
    state = json.loads(STATE.read_text()) if STATE.exists() else {}
    current = {}
    for target, row in inv.items():
        try:
            check_disk(target, inv)
        except Rejected:
            continue
        node = Path("/sys/class/block") / row["kname"]
        sequence = (
            (node / "diskseq").read_text().strip()
            if (node / "diskseq").exists()
            else (node / "dev").read_text().strip()
        )
        key = row["serial"] + ":" + sequence
        if cfg["minutes"] and busy_arrays(row["kname"]):
            current[key] = {"minutes": None, "device": target, "status": "busy"}
            continue
        if state.get(key, {}).get("minutes") == cfg["minutes"]:
            current[key] = state[key]
            continue
        try:
            command(["hdparm", "-S", str(value), target])
            current[key] = {"minutes": cfg["minutes"], "device": target, "status": "applied"}
        except Rejected as e:
            current[key] = {"minutes": None, "device": target, "status": "error", "error": str(e)}
    import tempfile

    STATE.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(mode="w", dir=STATE.parent, delete=False) as f:
        json.dump(current, f)
        temporary = Path(f.name)
    temporary.chmod(0o644)
    temporary.replace(STATE)


if __name__ == "__main__":
    try:
        apply(disable="--disable" in sys.argv)
    except (Rejected, OSError, ValueError, KeyError) as e:
        print(str(e), file=sys.stderr)
        sys.exit(1)
