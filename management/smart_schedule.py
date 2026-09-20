import datetime
import json
import os
import sys
from common import command, require
from disk_sleep import busy_arrays


def due(today, start, weeks):
    elapsed = (today - start).days
    return elapsed >= 0 and elapsed % (weeks * 7) == 0


def run(device, test, weeks, start):
    require(test in ("short", "long") and weeks in (1, 2), 'Invalid schedule')
    if not due(datetime.date.today(), datetime.date.fromisoformat(start), weeks):
        return
    from storage import inventory

    target = os.path.realpath(device)
    inv = inventory()
    require(target in inv and inv[target]["type"] == "disk", 'Disk unavailable')
    if busy_arrays(inv[target]["kname"]):
        print("Skipped: RAID maintenance is running")
        return
    status = json.loads(command(["smartctl", "-c", "-j", target], accepted=tuple(range(0, 256, 8))))
    value = status.get("ata_smart_data", {}).get("self_test", {}).get("status", {}).get("value", 0)
    if value & 0xF0 == 0xF0:
        print("Skipped: SMART self-test is already running")
        return
    command(["smartctl", "-t", test, target], accepted=tuple(range(0, 256, 8)))


if __name__ == "__main__":
    run(sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4])
