from common import *

CHECKERS = {
    "vfat": ("fsck.fat", ["-n"], ["-a"]),
    "exfat": ("fsck.exfat", ["-n"], ["-p"]),
    "ext2": ("e2fsck", ["-f", "-n"], ["-p"]),
    "ext3": ("e2fsck", ["-f", "-n"], ["-p"]),
    "ext4": ("e2fsck", ["-f", "-n"], ["-p"]),
}


def repair_available(fs):
    return fs in CHECKERS and bool(shutil.which(CHECKERS[fs][0]))


def check(target, fs, repair=False):
    require(repair_available(fs), 'Checking and repair are not yet available for this file system')
    tool, inspect, fix = CHECKERS[fs]
    print(
        json.dumps(
            {"stage": 'Repairing file system' if repair else 'Checking file system without changes'}
        ),
        file=sys.stderr,
        flush=True,
    )
    with tempfile.TemporaryFile() as output:
        try:
            result = subprocess.run(
                [tool, *(fix if repair else inspect), target],
                stdin=subprocess.DEVNULL,
                stdout=output,
                stderr=subprocess.STDOUT,
                timeout=3600,
                env={**os.environ, "LC_ALL": "C"},
            )
        except subprocess.TimeoutExpired:
            return False, 'The check exceeded one hour. The volume is unmounted; it can be opened read-only.'
        output.seek(0, 2)
        end = output.tell()
        output.seek(max(0, end - 2000))
        details = output.read().decode("utf-8", errors="replace")
    if repair and result.returncode in (0, 1):
        return check(target, fs)
    if result.returncode == 0:
        return True, ""
    return (
        False,
        ('Errors remain after repair.' if repair else 'The file system failed its check.')
        + " "
        + tool
        + ': code '
        + str(result.returncode)
        + ".\n"
        + details,
    )


def mounted_read_only(point):
    rows = json_command(["findmnt", "--json", "--list", "-o", "TARGET,OPTIONS"]).get("filesystems", [])
    return any(row["target"] == point and "ro" in row.get("options", "").split(",") for row in rows)


from contextlib import contextmanager
import fcntl

STATE = Path("/run/ostojaos-filesystems")


def identity(target):
    node = Path("/sys/class/block") / Path(target).name
    disk = node.resolve().parent if (node / "partition").exists() else node
    return (disk / "diskseq").read_text().strip() + ":" + (node / "dev").read_text().strip()


@contextmanager
def device_lock(target):
    STATE.mkdir(mode=0o700, exist_ok=True)
    with (STATE / (Path(target).name + ".lock")).open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        yield


def cached(target):
    try:
        result = json.loads((STATE / (Path(target).name + ".json")).read_text())
        return result if result["identity"] == identity(target) else None
    except (OSError, ValueError, KeyError):
        return None


def save_state(target, status, reason="", repair=False):
    data = {
        "identity": identity(target),
        "status": status,
        "reason": reason,
        "repairAvailable": repair,
        "checkedAt": time.time(),
    }
    dest = STATE / (Path(target).name + ".json")
    tmp = dest.with_suffix(".tmp")
    tmp.write_text(json.dumps(data))
    tmp.replace(dest)


def inspect_added(name):
    require(bool(re.fullmatch(r"[a-zA-Z0-9_-]+", name)), 'Invalid device')
    target = "/dev/" + name
    with device_lock(target):
        import storage

        inv = storage.inventory()
        require(target in inv, 'Device disconnected')
        row = inv[target]
        parent = inv.get(row.get("parent"), row)
        if (row.get("tran") or parent.get("tran")) != "usb" or row.get("fstype") not in CHECKERS:
            return
        storage.protected(target, inv)
        if storage.mounted_rows(target, inv):
            return
        storage.unused(target, inv)
        old = cached(target)
        if old and old["status"] in ("clean", "errors", "unavailable"):
            return
        supported = repair_available(row["fstype"])
        save_state(target, "checking")
        clean, reason = (
            check(target, row["fstype"])
            if supported
            else (False, 'Check utility is not installed: ' + row["fstype"])
        )
        save_state(
            target,
            "clean" if clean else "errors" if supported else "unavailable",
            reason,
            supported and not row.get("ro"),
        )
    subprocess.run(["udevadm", "trigger", "--action=change", "/sys/class/block/" + name], check=False)


if __name__ == "__main__":
    try:
        inspect_added(sys.argv[1])
    except (Rejected, OSError) as e:
        print(str(e), file=sys.stderr)
        sys.exit(1)
