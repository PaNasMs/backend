import os
import pwd
from pathlib import Path
import re
import shutil
import disk_sleep
import filesystem_health
import datetime
from common import *

ACTIONS = {
    "raid.pause",
    "raid.resume",
    "mount.open",
    "disk.sleep",
    "disk.prepare",
    "raid.create",
    "raid.delete",
    "raid.add",
    "raid.grow",
    "raid.replace",
    "raid.check",
    "raid.check-stop",
    "partition.create",
    "partition.delete",
    "partition.resize",
    "filesystem.format",
    "filesystem.resize",
    "mount.attach",
    "mount.detach",
    "mount.settings",
    "disk.eject",
    "luks.create",
    "luks.open",
    "luks.close",
    "smart.short",
    "smart.long",
    "smart.abort",
    "smart.schedule",
    "smart.unschedule",
}


def raid_name(value):
    require(
        isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_-]{0,30}", value),
        'Array name: 1–31 Latin letters, digits, _ or -. Start with a letter, digit or _. Spaces are not allowed.',
    )
    return value


def inventory():
    data = json_command(
        [
            "lsblk",
            "--json",
            "--bytes",
            "--output",
            "NAME,KNAME,PATH,TYPE,SIZE,MODEL,SERIAL,WWN,FSTYPE,UUID,MOUNTPOINTS,PKNAME,RO,PARTN,ROTA,TRAN",
        ]
    )
    result = {}

    def visit(d, parent=None):
        row = {k: v for k, v in d.items() if k != "children"}
        row["path"] = os.path.realpath(d["path"])
        row["parent"] = parent
        result[row["path"]] = row
        for c in d.get("children", []):
            visit(c, row["path"])

    for d in data["blockdevices"]:
        visit(d)
    return result


def descendants(dev, inv):
    result = {dev}
    while True:
        new = result | {k for k, v in inv.items() if v.get("parent") in result}
        if new == result:
            return result
        result = new


def ancestors(dev, inv):
    result = set()
    while dev and dev not in result:
        result.add(dev)
        dev = inv.get(dev, {}).get("parent")
    return result


def device(value, inv):
    require(isinstance(value, str) and value.startswith("/dev/"), 'Select a block device')
    path = os.path.realpath(value)
    require(path in inv, 'The device no longer exists')
    return path


def protected(dev, inv):
    protected_roots = set()
    for path, d in inv.items():
        if any(
            m and (m == "/" or m.startswith(("/boot", "/usr", "/var", "/home", "[SWAP]")))
            for m in d.get("mountpoints", [])
        ):
            protected_roots |= ancestors(path, inv)

    def backing(path, seen=None):
        seen = set() if seen is None else seen
        if path in seen:
            return seen
        seen.add(path)
        sys = Path("/sys/class/block") / Path(path).name
        for slave in (sys / "slaves").glob("*"):
            backing("/dev/" + slave.name, seen)
        parent = inv.get(path, {}).get("parent")
        if parent:
            backing(parent, seen)
        return seen

    for path, d in inv.items():
        if any(
            m and (m == "/" or m.startswith(("/boot", "/usr", "/var", "/home", "[SWAP]")))
            for m in d.get("mountpoints", [])
        ):
            protected_roots |= backing(path)
    root_ancestors = backing(dev)
    require(not root_ancestors.intersection(protected_roots), 'The system drive or one of its members is protected')
    require(not inv[dev].get("ro"), 'The device is read-only')


def unused(dev, inv, allow_children=False):
    paths = descendants(dev, inv)
    require(allow_children or paths == {dev}, 'Detach dependent devices or delete partitions first')
    require(
        not any(m for p in paths for m in inv[p].get("mountpoints", [])),
        'Unmount file systems first',
    )
    holders = list((Path("/sys/class/block") / inv[dev]["kname"] / "holders").glob("*"))
    require(not holders, 'The device is used by another storage layer')


def eject_check(target, inv):
    protected(target, inv)
    require(inv[target]["type"] == "disk", 'Select a physical drive')
    require(
        (Path("/sys/class/block") / inv[target]["kname"] / "device/delete").exists(),
        'The controller does not support disconnection',
    )
    for dev in descendants(target, inv):
        require(
            inv[dev]["type"] in ("disk", "part"), 'The drive is used by an array or another storage layer'
        )
        holders = list((Path("/sys/class/block") / inv[dev]["kname"] / "holders").glob("*"))
        require(not holders, "Device " + dev + ' is used by: ' + ", ".join(x.name for x in holders))
    mount_blockers(target, inv)


def mountpoint(value):
    p = clean_path(value)
    require(
        str(p).startswith(("/srv/", "/mnt/", "/media/")),
        'The mount point must be under /srv, /mnt or /media',
    )
    require(not any(c.is_symlink() for c in [p, *p.parents]), 'Links in the mount path are not allowed')
    return p


def mounted_rows(dev, inv):
    return [(p, m) for p in descendants(dev, inv) for m in inv[p].get("mountpoints", []) if m]


def mount_targets():
    rows = json_command(["findmnt", "--json", "--output", "TARGET"])["filesystems"]

    def walk(rows):
        for row in rows:
            yield row["target"]
            yield from walk(row.get("children", []))

    return set(walk(rows))


def nfs_exports():
    path = Path("/var/lib/nfs/etab")
    raw = path.read_text() if path.exists() else ""
    return sorted(
        {
            re.sub(r"\\([0-7]{3})", lambda m: chr(int(m[1], 8)), line.split()[0])
            for line in raw.splitlines()
            if line.split()
        }
    )


def process_label(pid):
    import pwd

    path = Path("/proc") / str(pid)
    try:
        label = (path / "comm").read_text().strip()
        uid = path.stat().st_uid
        try:
            owner = pwd.getpwuid(uid).pw_name
        except KeyError:
            owner = str(uid)
        return f'{label} (PID {pid}, user {owner})'
    except FileNotFoundError:
        return f'PID {pid} (process already exited)'


def mount_blockers(target, inv):
    problems = []
    targets = mount_targets()
    exports = nfs_exports()
    for _, point in sorted(set(mounted_rows(target, inv))):
        mountpoint(point)
        result = subprocess.run(
            ["fuser", "-m", point],
            capture_output=True,
            text=True,
            timeout=15,
            env={**os.environ, "LC_ALL": "C"},
        )
        require(
            result.returncode in (0, 1) and not (result.returncode == 1 and result.stderr.strip()),
            f'Could not check which processes use volume “{point}”. Deletion has not started; retry after resolving process access errors.',
        )
        if result.returncode == 0:
            pids = sorted({int(pid) for pid in result.stdout.split() if pid.isdigit()})
            processes = ", ".join(process_label(pid) for pid in pids[:20]) or 'process list unavailable'
            if len(pids) > 20:
                processes += f', {len(pids) - 20} more'
            problems.append(
                f"Volume “{point}” is busy: {processes}. Close the files or stop the relevant service; if this is a terminal, leave the volume's directory."
            )
        nested = sorted(p for p in targets if p.startswith(point + "/"))
        if nested:
            problems.append(
                f'Mounted inside “{point}”: '
                + ", ".join(nested)
                + '. Unmount these nested mounts first.'
            )
        shared = [p for p in exports if p == point or p.startswith(point + "/")]
        if shared:
            problems.append(
                'Folders shared via NFS: '
                + ", ".join(shared)
                + '. Remove their shares in Shared folders first.'
            )
    require(not problems, 'Operation on ' + target + ' has not started. ' + " ".join(problems))


def table(dev):
    return json_command(["sfdisk", "--json", dev])["partitiontable"]


def reshape_control_state(md, action):
    state = {
        key: (md / key).read_text().strip()
        for key in (
            "uuid",
            "level",
            "metadata_version",
            "sync_action",
            "reshape_position",
            "degraded",
            "array_state",
        )
    }
    require(state["reshape_position"].isdigit(), 'No unfinished array reshape')
    require(
        state["level"] in ("raid5", "raid6") and state["metadata_version"] == "1.2",
        'Reshape control is supported for RAID5/RAID6 with MD 1.2 metadata',
    )
    if action == "raid.pause":
        require(
            state["sync_action"] == "reshape",
            'Reshape is not running. Refresh array state.',
        )
    else:
        require(
            state["sync_action"] in ("idle", "frozen"),
            'Reshape is already running or the array is busy with another operation',
        )
        require(
            state["degraded"] == "0", 'Recover missing or failed array members first'
        )
        require(
            state["array_state"] not in ("inactive", "clear", "suspended"),
            'The array is not ready to resume reshape',
        )
    return {key: value for key, value in state.items() if key != "reshape_position"}


def control_reshape(md, target, action):
    reshape_control_state(md, action)
    if action == "raid.pause":
        (md / "sync_action").write_text("frozen")
        require(
            (md / "sync_action").read_text().strip() == "frozen", 'Could not confirm reshape pause'
        )
        return {"message": 'Reshape paused. Position saved.'}
    if (md / "array_state").read_text().strip() in ("read-auto", "readonly"):
        command(["mdadm", "--readwrite", target])
    if (md / "sync_action").read_text().strip() == "frozen":
        (md / "sync_action").write_text("reshape")
    if (md / "sync_action").read_text().strip() != "reshape" and (
        md / "reshape_position"
    ).read_text().strip() != "none":
        command(
            [
                "systemd-run",
                "--scope",
                "--quiet",
                "--unit=ostojaos-raid-resume-" + str(time.time_ns()),
                "/usr/sbin/mdadm",
                "--grow",
                target,
                "--continue",
            ],
            timeout=300,
        )
    for _ in range(30):
        if (md / "sync_action").read_text().strip() == "reshape" or (
            md / "reshape_position"
        ).read_text().strip() == "none":
            return {"message": 'Reshape resumed. Progress is shown on the array card.'}
        time.sleep(0.2)
    raise Rejected(
        'Could not confirm reshape resumption. Refresh array state and check the system journal.'
    )


def growth_state(md):
    state = {
        key: (md / key).read_text().strip()
        for key in (
            "level",
            "raid_disks",
            "degraded",
            "sync_action",
            "reshape_position",
            "metadata_version",
            "component_size",
        )
    }
    require(state["level"] in ("raid5", "raid6"), 'Single-disk expansion is supported for RAID5 and RAID6')
    require(state["metadata_version"] == "1.2", 'Expansion requires an array with MD 1.2 metadata')
    require(
        state["sync_action"] == "idle" and state["reshape_position"] == "none",
        'Wait for the current array operation to finish before expanding',
    )
    require(state["degraded"] == "0", 'Recover failed or missing array members first')
    count = int(state["raid_disks"])
    entries = list(md.glob("dev-*"))
    slots = set()
    for entry in entries:
        value = (entry / "state").read_text().strip().split(",")
        slot = (entry / "slot").read_text().strip()
        require(
            "in_sync" in value and "faulty" not in value and slot.isdigit(),
            'All members must be synchronized; expansion with spare disks is not supported yet',
        )
        slots.add(int(slot))
    require(
        slots == set(range(count)) and len(entries) == count,
        'Array membership changed. Refresh data before expanding',
    )
    return state


def plan(action, p):
    require(action in ACTIONS, 'Unknown storage operation')
    inv = inventory()
    target = p.get("target", "")
    paths = []
    details = []
    growth = None
    if action == "raid.create":
        raid_name(p.get("name"))
        require(p.get("level") in ("0", "1", "5", "6", "10"), 'RAID0/1/5/6/10 are supported')
        members = p.get("members", [])
        require(isinstance(members, list), 'Select disks')
        paths = [device(v, inv) for v in members]
        require(len(paths) == len(set(paths)), 'Duplicate members')
        minimum = {"0": 2, "1": 2, "5": 3, "6": 4, "10": 4}[p["level"]]
        require(len(paths) >= minimum, 'Not enough members')
        require(
            p["level"] != "10" or len(paths) % 2 == 0, 'RAID10 requires an even number of members'
        )
        require(not Path("/dev/md/" + p["name"]).exists(), 'Array name is already in use')
        for dev in paths:
            protected(dev, inv)
            unused(dev, inv)
            require(inv[dev]["type"] in ("disk", "part", "loop"), 'Unsupported member')
            require(not inv[dev].get("fstype"), 'The member contains data or RAID metadata')
        target = p["name"]
        details = [
            'RAID will be created' + p["level"],
            *paths,
            (
                'RAID0 has no redundancy: a disk failure causes array data loss'
                if p["level"] == "0"
                else 'Array synchronization will continue in the background'
            ),
        ]
    elif action == "disk.sleep":
        disk_sleep.timer_value(p.get("minutes"))
        require(bool(shutil.which("hdparm")), 'The hdparm package is required to configure disk sleep')
        target = "all-hdd"
        details = [
            'All non-system SATA HDDs',
            (
                'Never sleep'
                if p["minutes"] == 0
                else f"Sleep after {p['minutes']} minutes of no disk access"
            ),
            'The setting persists across restarts and applies to new HDDs. For busy RAID arrays, it is deferred until the background operation finishes.',
        ]
    elif action in ("smart.schedule", "smart.unschedule"):
        target = device(target, inv)
        paths = [target]
        require(inv[target].get("serial"), 'No serial number')
        require(p.get("test") in ("short", "long"), 'Select a test type')
        if action == "smart.schedule":
            integer(p.get("hour"), 0, 23)
            integer(p.get("weekday"), 0, 6)
            integer(p.get("weeks", 1), 1, 2)
        details = [
            'SMART tests wake disks; busy arrays and running tests are skipped',
            target,
        ]
    else:
        target = device(target, inv)
        paths = [target]
        if action.startswith("smart."):
            require(
                inv[target]["type"] == "disk" and inv[target].get("serial"),
                'SMART requires a physical disk with a serial number',
            )
            details = ['The test may wake the disk', target]
        else:
            protected(target, inv)
            if action.startswith("raid."):
                md = Path("/sys/class/block") / inv[target]["kname"] / "md"
                require(md.is_dir(), 'The device is not an MD RAID array')
                members = sorted("/dev/" + x.name for x in (md.parent / "slaves").iterdir())
                paths += members
                details = [target, *members]
                if action in ("raid.pause", "raid.resume"):
                    reshape_control_state(md, action)
                elif action == "raid.delete":
                    require(
                        (md / "reshape_position").read_text().strip() == "none",
                        'Finish array reshape first',
                    )
                    require(
                        not (md / "sync_action").exists()
                        or (md / "sync_action").read_text().strip() == "idle",
                        'Wait for the array operation to finish',
                    )
                    details += [
                        'ARRAY DATA WILL BECOME INACCESSIBLE',
                        'Volumes will be unmounted and member RAID metadata removed',
                    ]
                    mount_blockers(target, inv)
                elif action in ("raid.check", "raid.check-stop"):
                    require(
                        (md / "reshape_position").read_text().strip() == "none",
                        'Finish array reshape first',
                    )
                    require(inv[target]["type"] != "raid0", 'RAID0 does not support redundancy checks')
                elif action in ("raid.add", "raid.grow", "raid.replace"):
                    require(
                        inv[target]["type"] in ("raid1", "raid5", "raid6", "raid10"),
                        'This RAID level does not support the operation',
                    )
                    require(
                        (md / "sync_action").read_text().strip() == "idle",
                        'Wait for the current array operation to finish',
                    )
                    extra = device(p.get("replacement"), inv)
                    protected(extra, inv)
                    unused(extra, inv)
                    require(not inv[extra].get("fstype"), 'The new member must be empty')
                    paths.append(extra)
                    require(
                        inv[extra]["size"] >= min(inv[m]["size"] for m in members),
                        'The new disk is smaller than the array members',
                    )
                    require(
                        (md / "reshape_position").read_text().strip() == "none",
                        'Finish array reshape first',
                    )
                    if action == "raid.grow":
                        growth = growth_state(md)
                        require(
                            inv[extra]["type"] in ("disk", "part", "loop"),
                            'Select an unused disk or partition',
                        )
                        count = int(growth["raid_disks"])
                        parity = 1 if growth["level"] == "raid5" else 2
                        size = int(growth["component_size"]) * 512
                        details += [
                            f'Members: {count} → {count + 1}',
                            f'Array capacity: approximately {size * (count - parity) // 1048576} → {size * (count + 1 - parity) // 1048576} MiB',
                            'The selected disk will become an active array member. Data will be reshaped in the background.',
                            'Partitions and file systems keep their current sizes. Expand them separately in Partitions and mounts.',
                        ]
                    if action == "raid.replace":
                        require(device(p.get("member"), inv) in members, 'Old member not found')
                    details += [
                        'New member: ' + extra,
                        'Background progress is shown on the array card',
                    ]
            elif action.startswith("partition."):
                if action == "partition.create":
                    unused(target, inv, True)
                    require(
                        inv[target]["type"] in ("disk", "loop", "md")
                        or inv[target]["type"].startswith("raid"),
                        'Select a disk or array',
                    )
                    require(not inv[target].get("fstype"), 'The device contains a file system')
                    start = integer(p.get("startMiB"), 1, inv[target]["size"] // 1048576)
                    end = integer(p.get("endMiB"), start + 1, inv[target]["size"] // 1048576)
                    for k in descendants(target, inv) - {target}:
                        d = inv[k]
                        begin = int((Path("/sys/class/block") / d["kname"] / "start").read_text()) * 512
                        finish = begin + d["size"]
                        require(
                            end * 1048576 <= begin or start * 1048576 >= finish,
                            'The partition overlaps an existing partition',
                        )
                    details = [target, f'New partition: {start}–{end} MiB']
                else:
                    require(inv[target]["type"] == "part", 'Select a partition')
                    unused(target, inv)
                    parent = inv[target]["parent"]
                    paths.append(parent)
                    unused(parent, inv, True)
                    if action == "partition.resize":
                        require(
                            inv[target].get("fstype") in (None, "", "ext2", "ext3", "ext4"),
                            'Resizing a partition with this file system is not supported yet; use separate file system operations',
                        )
                        size = integer(p.get("sizeMiB"), 16, inv[parent]["size"] // 1048576)
                        start = (
                            int((Path("/sys/class/block") / inv[target]["kname"] / "start").read_text()) * 512
                        )
                        require(start + size * 1048576 < inv[parent]["size"] - 1048576, 'Outside disk boundaries')
                        for other in descendants(parent, inv) - {parent, target}:
                            row = inv[other]
                            begin = int((Path("/sys/class/block") / row["kname"] / "start").read_text()) * 512
                            require(
                                start + size * 1048576 <= begin or start >= begin + row["size"],
                                'Not enough contiguous free space',
                            )
                        details = [
                            target,
                            f'New size: {size} MiB',
                            'The ext file system and partition will be resized in a safe order',
                        ]
            elif action == "filesystem.format":
                unused(target, inv)
                require(p.get("format") in supported_formats(), 'The utility for creating this file system is unavailable')
                require(
                    not inv[target].get("fstype") == "linux_raid_member",
                    'Cannot format a RAID member',
                )
                details = [target, 'FORMATTING WILL DESTROY DATA']
            elif action == "filesystem.resize":
                fs = inv[target].get("fstype")
                require(fs in ("ext2", "ext3", "ext4", "btrfs", "xfs"), 'Resizing is not supported')
                if fs.startswith("ext"):
                    unused(target, inv)
                    integer(p.get("sizeMiB"), 16, inv[target]["size"] // 1048576)
                else:
                    require(bool(mounted_rows(target, inv)), 'The file system must be mounted')
                    if fs == "xfs":
                        require(
                            p.get("sizeMiB") in (None, 0), 'XFS can only grow to the device size'
                        )
                    else:
                        integer(p.get("sizeMiB", 0), 0, inv[target]["size"] // 1048576)
                        require(
                            bool(
                                re.search(
                                    r"Total devices\s+1\b",
                                    command(
                                        [
                                            "btrfs",
                                            "filesystem",
                                            "show",
                                            "--raw",
                                            mounted_rows(target, inv)[0][1],
                                        ]
                                    ),
                                )
                            ),
                            'Resizing multi-device Btrfs requires a separate workflow',
                        )
            elif action in ("mount.attach", "mount.settings", "mount.open"):
                require(
                    inv[target].get("fstype")
                    and inv[target]["fstype"] not in ("linux_raid_member", "crypto_LUKS", "swap"),
                    'Select a file system',
                )
                if action == "mount.open":
                    require(
                        p.get("mode", "auto") in ("auto", "repair", "repair-only", "readonly"),
                        'Unknown mount mode',
                    )
                    require(inv[target]["type"] in ("disk", "part"), 'Select a removable drive partition')
                    if p.get("mode") == "repair-only":
                        require(
                            not mounted_rows(target, inv),
                            'Volume already mounted. Unmount it before repairing.',
                        )
                    if p.get("mode") in ("repair", "repair-only"):
                        require(
                            filesystem_health.repair_available(inv[target]["fstype"]),
                            'Automatic repair is unavailable for this file system',
                        )
                        require(not inv[target].get("ro"), 'Device is write-protected')
                        mount_blockers(target, inv)
                point = mountpoint(p.get("point"))
                require(not point.exists() or point.is_dir(), 'The mount point is not a directory')
                require(action != "mount.attach" or not mounted_rows(target, inv), 'Already mounted')
                require(
                    action not in ("mount.attach", "mount.open")
                    or str(point) not in mount_targets()
                    or str(point) in [m for _, m in mounted_rows(target, inv)],
                    'The mount point is already used by another volume',
                )
                require(
                    str(point) in [m for _, m in mounted_rows(target, inv)]
                    or not point.exists()
                    or not any(point.iterdir()),
                    'The mount point directory must be empty',
                )
                require(inv[target].get("uuid"), 'A UUID is required for mounting')
                details = [target, str(point), 'At startup: ' + str(bool(p.get("automount")))]
            elif action == "mount.detach":
                require(bool(mounted_rows(target, inv)), 'Device is not mounted')
                mount_blockers(target, inv)
                details = [target, 'The volume will be unmounted without forcibly terminating processes']
            elif action == "disk.prepare":
                unused(target, inv, True)
                require(inv[target]["type"] in ("disk", "part", "loop"), 'Select a standalone disk or partition')
                details = [
                    target,
                    'PARTITION TABLE AND SIGNATURES WILL BE REMOVED; DATA WILL BECOME INACCESSIBLE',
                    "This does not fully erase the drive's contents",
                ]
            elif action == "disk.eject":
                eject_check(target, inv)
                details = [
                    target,
                    'All mounted drive volumes will be unmounted, pending writes saved, and the device disconnected',
                    *[point for _, point in mounted_rows(target, inv)],
                ]
            elif action.startswith("luks."):
                unused(target, inv)
                if action in ("luks.create", "luks.open"):
                    secret = p.get("passphrase")
                    require(
                        isinstance(secret, str) and 1 <= len(secret) <= 4096 and "\x00" not in secret,
                        'Enter the LUKS password',
                    )
                    if action == "luks.create":
                        require(not inv[target].get("fstype"), 'LUKS requires an empty device')
                    else:
                        require(inv[target].get("fstype") == "crypto_LUKS", 'Select a LUKS container')
                        name(p.get("name"))
                        require(not Path("/dev/mapper/" + p["name"]).exists(), 'Name already in use')
                else:
                    require(inv[target]["type"] == "crypt", 'Select an unlocked LUKS volume')
    if action in (
        "raid.delete",
        "mount.detach",
        "partition.delete",
        "filesystem.format",
        "disk.eject",
        "disk.prepare",
    ) or (action == "mount.open" and p.get("mode") in ("repair", "repair-only")):
        exports = nfs_exports()
        for dev in paths:
            for _, point in mounted_rows(dev, inv):
                shared = [p for p in exports if p == point or p.startswith(point + "/")]
                require(
                    not shared,
                    'Volume “'
                    + point
                    + '” is used by NFS shares: '
                    + ", ".join(shared)
                    + '. Disable them in Shared folders first.',
                )
    state = {k: inv[k] for path in paths for k in descendants(path, inv)}
    if action in ("raid.pause", "raid.resume"):
        state["reshape_control"] = reshape_control_state(md, action)
    if growth is not None:
        state["raid_growth"] = growth
    state["fstab"] = Path("/etc/fstab").read_text()
    return {
        "target": target,
        "details": details or [target],
        "confirmation": target,
        "fingerprint": fingerprint(action, p, state),
    }


def supported_formats():
    return [f for f in ("ext4", "xfs", "btrfs", "vfat") if shutil.which("mkfs." + f)]


def without_array(config, uuid):
    normalized = lambda value: re.sub("[:-]", "", value).lower()

    def matches(row):
        fields = row.split()
        return (
            fields
            and fields[0] == "ARRAY"
            and any(
                field.startswith("UUID=") and normalized(field[5:]) == normalized(uuid)
                for field in fields[1:]
            )
        )

    return "\n".join(row for row in config.splitlines() if not matches(row)) + "\n"


def fstab_change(uuid, line=None):
    path = Path("/etc/fstab")
    rows = path.read_text().splitlines()
    kept = []
    for row in rows:
        fields = row.split()
        if fields and fields[0] == "UUID=" + uuid:
            continue
        kept.append(row)
    if line:
        kept.append(line)
    atomic(path, "\n".join(kept) + "\n", 0o644)
    command(["systemctl", "daemon-reload"])


def open_filesystem(target, p, user, inv):
    fs = inv[target]["fstype"]
    mode = p.get("mode", "auto")
    points = mounted_rows(target, inv)

    def choice(reason):
        return {
            "needsChoice": True,
            "reason": reason,
            "repairAvailable": filesystem_health.repair_available(fs) and not inv[target].get("ro"),
            "message": 'Choose how to open the volume before mounting',
        }

    readonly = mode == "readonly" or (mode == "auto" and bool(p.get("readOnly")))
    if points and mode not in ("repair", "repair-only"):
        point = points[0][1]
        actual_readonly = filesystem_health.mounted_read_only(point)
        if readonly and not actual_readonly:
            mount_blockers(target, inv)
            for _, mounted_point in sorted(points, key=lambda row: len(row[1]), reverse=True):
                command(["umount", "--", mounted_point])
        elif not readonly and actual_readonly:
            return choice(
                'The volume is read-only, possibly due to file system errors. Choose repair or read-only access.'
            )
        else:
            return {"point": point, "readOnly": actual_readonly}
    if mode in ("repair", "repair-only"):
        mount_blockers(target, inv)
        for _, point in sorted(points, key=lambda row: len(row[1]), reverse=True):
            command(["umount", "--", point])
    unused(target, inventory())
    if not readonly:
        if not filesystem_health.repair_available(fs):
            return choice(
                'For ' + fs + ' automatic checking is unavailable. You can mount the volume read-only.'
            )
        clean, reason = filesystem_health.check(target, fs, repair=mode in ("repair", "repair-only"))
        filesystem_health.save_state(
            target,
            "clean" if clean else "errors",
            reason,
            filesystem_health.repair_available(fs) and not inv[target].get("ro"),
        )
        if not clean:
            return choice(reason)
    if mode == "repair-only":
        return {"repaired": True, "message": 'Errors repaired. The volume remains unmounted.'}
    params = {**p, "readOnly": readonly}
    try:
        execute_unlocked("mount.attach", params, user)
    except Rejected as e:
        return choice('Could not mount volume: ' + str(e))
    point = str(mountpoint(p["point"]))
    if not readonly and filesystem_health.mounted_read_only(point):
        return choice(
            'Linux mounted the volume read-only. A file system check is required.'
        )
    return {"point": point, "readOnly": readonly}


def execute(action, p, user=None):
    if action in ("mount.open", "mount.attach", "mount.detach"):
        with filesystem_health.device_lock(os.path.realpath(p.get("target", ""))):
            return execute_unlocked(action, p, user)
    return execute_unlocked(action, p, user)


def execute_unlocked(action, p, user=None):
    inv = inventory()
    target = os.path.realpath(p.get("target", ""))
    if action == "mount.open":
        return open_filesystem(target, p, user, inv)
    if action == "disk.sleep":
        disk_sleep.save(p["minutes"])
    elif action == "raid.create":
        target = "/dev/md/" + p["name"]
        members = [device(m, inv) for m in p["members"]]
        command(
            [
                "mdadm",
                "--create",
                target,
                "--run",
                "--metadata=1.2",
                "--name=" + p["name"],
                "--level=" + p["level"],
                "--raid-devices=" + str(len(members)),
                *members,
            ],
            timeout=300,
        )
        add = command(["mdadm", "--detail", "--scan", target])
        conf = Path("/etc/mdadm/mdadm.conf")
        atomic(conf, conf.read_text() + "\n" + add, 0o644)
        command(["update-initramfs", "-u"], timeout=600)
    elif action == "raid.delete":
        md = Path("/sys/class/block") / inv[target]["kname"] / "md"
        uuid = (md / "uuid").read_text().strip()
        members = sorted("/dev/" + x.name for x in (md.parent / "slaves").iterdir())
        for dev, point in sorted(mounted_rows(target, inv), key=lambda row: len(row[1]), reverse=True):
            command(["umount", "--", point])
        command(["mdadm", "--stop", target])
        for dev in members:
            command(["mdadm", "--zero-superblock", dev])
        conf = Path("/etc/mdadm/mdadm.conf")
        atomic(conf, without_array(conf.read_text(), uuid), 0o644)
        for dev in descendants(target, inv):
            if inv[dev].get("uuid"):
                fstab_change(inv[dev]["uuid"])
        command(["update-initramfs", "-u"], timeout=600)
        require(
            not Path("/sys/class/block/" + inv[target]["kname"] + "/md").exists(), 'Array is still active'
        )
    elif action in ("raid.pause", "raid.resume"):
        return control_reshape(Path("/sys/class/block") / inv[target]["kname"] / "md", target, action)
    elif action == "raid.grow":
        md = Path("/sys/class/block") / inv[target]["kname"] / "md"
        state = growth_state(md)
        count = int(state["raid_disks"]) + 1
        extra = device(p["replacement"], inv)
        unit = "ostojaos-raid-grow-" + str(time.time_ns())
        try:
            if os.environ.get("OSTOJAOS_OPERATION") == "1":
                print(
                    json.dumps({"stage": 'Starting array expansion; reshape will continue in the background'}),
                    file=sys.stderr,
                    flush=True,
                )
            result = subprocess.run(
                [
                    "systemd-run",
                    "--scope",
                    "--quiet",
                    "--unit=" + unit,
                    "/usr/sbin/mdadm",
                    "--grow",
                    target,
                    "--raid-devices=" + str(count),
                    "--add",
                    extra,
                ],
                capture_output=True,
                text=True,
                timeout=300,
                env={**os.environ, "LC_ALL": "C"},
            )
            require(result.returncode == 0, result.stderr.strip()[-1500:] or 'mdadm did not confirm startup')
        except (Rejected, subprocess.TimeoutExpired) as error:
            reason = str(error) if isinstance(error, Rejected) else 'Startup timed out'
            raise Rejected(
                'Could not confirm expansion startup '
                + target
                + '. Check array membership and progress before retrying: the new disk may already be a spare. Reason: '
                + reason
            )
        require(
            int((md / "raid_disks").read_text().split()[0]) == count,
            'The command finished, but the new member count is not confirmed yet. Refresh array state before retrying.',
        )
        command(["udevadm", "settle"], timeout=30)
        return {
            "message": 'Array expansion started. Wait for reshape to finish on the RAID card. Partition and file system sizes are unchanged.',
            "target": target,
        }
    elif action == "raid.add":
        command(["mdadm", "--manage", target, "--add", device(p["replacement"], inv)])
    elif action == "raid.replace":
        new = device(p["replacement"], inv)
        old = device(p["member"], inv)
        command(["mdadm", "--manage", target, "--add", new])
        command(["mdadm", "--manage", target, "--replace", old, "--with", new])
    elif action in ("raid.check", "raid.check-stop"):
        (Path("/sys/class/block") / inv[target]["kname"] / "md/sync_action").write_text(
            "check" if action == "raid.check" else "idle"
        )
    elif action == "partition.create":
        check = subprocess.run(["sfdisk", "--json", target], capture_output=True)
        if check.returncode:
            command(["parted", "--script", target, "mklabel", "gpt"])
        command(
            [
                "parted",
                "--script",
                target,
                "mkpart",
                "primary",
                str(p["startMiB"]) + "MiB",
                str(p["endMiB"]) + "MiB",
            ]
        )
    elif action == "partition.delete":
        command(["parted", "--script", inv[target]["parent"], "rm", str(inv[target]["partn"])])
        if inv[target].get("uuid"):
            fstab_change(inv[target]["uuid"])
    elif action == "partition.resize":
        row = inv[target]
        size = p["sizeMiB"]
        fs = row.get("fstype")
        shrink = size * 1048576 < row["size"]
        if fs:
            command(["e2fsck", "-f", "-p", target], accepted=(0, 1), timeout=86400)
        if fs and shrink:
            command(["resize2fs", target, str(size - 4) + "M"], timeout=86400)
        start = int((Path("/sys/class/block") / row["kname"] / "start").read_text()) * 512
        sector = table(row["parent"]).get("sectorsize", 512)
        command(
            ["sfdisk", "-N", str(row["partn"]), row["parent"]],
            data="size=" + str(size * 1048576 // sector) + "\n",
        )
        command(["udevadm", "settle"])
        if fs:
            command(["resize2fs", target], timeout=86400)
    elif action == "filesystem.format":
        fs = p["format"]
        args = {
            "ext4": ["mkfs.ext4", "-F"],
            "xfs": ["mkfs.xfs", "-f"],
            "btrfs": ["mkfs.btrfs", "-f"],
            "vfat": ["mkfs.vfat"],
        }[fs]
        command([*args, target], timeout=86400)
        if inv[target].get("uuid"):
            fstab_change(inv[target]["uuid"])
    elif action == "filesystem.resize":
        fs = inv[target]["fstype"]
        if fs.startswith("ext"):
            command(["e2fsck", "-f", "-p", target], accepted=(0, 1), timeout=86400)
            command(["resize2fs", target, str(p["sizeMiB"]) + "M"], timeout=86400)
        else:
            point = mounted_rows(target, inv)[0][1]
            command(
                (
                    ["xfs_growfs", point]
                    if fs == "xfs"
                    else [
                        "btrfs",
                        "filesystem",
                        "resize",
                        str(p["sizeMiB"]) + "M" if p.get("sizeMiB") else "max",
                        point,
                    ]
                ),
                timeout=86400,
            )
    elif action in ("mount.attach", "mount.settings"):
        point = mountpoint(p["point"])
        for directory in reversed([point, *point.parents]):
            if not directory.exists():
                directory.mkdir()
                directory.chmod(0o755)
        uuid = inv[target]["uuid"]
        opts = ("ro" if p.get("readOnly") else "rw") + ",noatime,nofail,x-systemd.device-timeout=30s"
        if inv[target]["fstype"] in ("vfat", "exfat", "ntfs", "ntfs3"):
            require(bool(user), 'No user specified for mounting the volume')
            owner = pwd.getpwnam(user)
            opts += f",uid={owner.pw_uid},gid={owner.pw_gid},fmask=0177,dmask=0077"
        if p.get("readOnly") and inv[target]["fstype"] in ("ext3", "ext4"):
            opts += ",noload"
        escaped = str(point).replace("\\", "\\134").replace(" ", "\\040")
        fstab_change(
            uuid, f'UUID={uuid} {escaped} {inv[target]["fstype"]} {opts} 0 0' if p.get("automount") else None
        )
        if action == "mount.attach":
            command(["mount", "-o", opts, "--", target, str(point)])
    elif action == "mount.detach":
        for _, point in sorted(mounted_rows(target, inv), key=lambda row: len(row[1]), reverse=True):
            command(["umount", "--", point])
    elif action == "disk.prepare":
        command(["wipefs", "--all", "--", target])
        for dev in descendants(target, inv):
            if inv[dev].get("uuid"):
                fstab_change(inv[dev]["uuid"])
    elif action == "disk.eject":
        eject_check(target, inv)
        for _, point in sorted(set(mounted_rows(target, inv)), key=lambda row: len(row[1]), reverse=True):
            try:
                command(["umount", "--", point])
            except Rejected:
                raise Rejected(
                    'Could not unmount '
                    + point
                    + '. The drive was not disconnected; previously processed volumes may already be unmounted. Check processes and mounts.'
                )
        unused(target, inventory(), True)
        command(["sync"])
        (Path("/sys/class/block") / inv[target]["kname"] / "device/delete").write_text("1")
    elif action == "luks.create":
        command(
            ["cryptsetup", "luksFormat", "--type", "luks2", "--batch-mode", "--key-file", "-", target],
            data=p["passphrase"],
            timeout=300,
        )
    elif action == "luks.open":
        command(
            ["cryptsetup", "open", "--type", "luks", "--key-file", "-", target, p["name"]],
            data=p["passphrase"],
            timeout=300,
        )
    elif action == "luks.close":
        command(["cryptsetup", "close", inv[target]["name"]])
    elif action.startswith("smart."):
        if action in ("smart.schedule", "smart.unschedule"):
            serial = inv[target]["serial"]
            identifier = hashlib.sha256(serial.encode()).hexdigest()[:16]
            base = "ostojaos-smart-" + identifier
            unit = base + "-" + p["test"]
            legacy = smart_schedule(serial)
            if legacy and legacy["test"] == p["test"]:
                command(["systemctl", "disable", "--now", base + ".timer"])
                for suffix in (".timer", ".service"):
                    (Path("/etc/systemd/system") / (base + suffix)).unlink(missing_ok=True)
            if action == "smart.unschedule":
                if (Path("/etc/systemd/system") / (unit + ".timer")).exists():
                    command(["systemctl", "disable", "--now", unit + ".timer"])
                for suffix in (".timer", ".service"):
                    (Path("/etc/systemd/system") / (unit + suffix)).unlink(missing_ok=True)
            else:
                links = [
                    str(x)
                    for x in Path("/dev/disk/by-id").glob("ata-*")
                    if "-part" not in x.name and os.path.realpath(x) == target
                ]
                require(links, 'No stable ATA ID')
                require(
                    bool(re.fullmatch(r"/dev/disk/by-id/[a-zA-Z0-9_.:-]+", links[0])),
                    'Unsupported device ID',
                )
                now = datetime.datetime.now()
                start = now.date() + datetime.timedelta(days=(p["weekday"] - now.weekday()) % 7)
                if start == now.date() and now.hour >= p["hour"]:
                    start += datetime.timedelta(days=7)
                weeks = p.get("weeks", 1)
                schedule = {
                    "test": p["test"],
                    "weekday": p["weekday"],
                    "hour": p["hour"],
                    "weeks": weeks,
                    "startDate": start.isoformat(),
                }
                atomic(
                    "/etc/systemd/system/" + unit + ".service",
                    f"[Unit]\nDescription=OstojaOS SMART self-test\n# OstojaOS schedule: {json.dumps(schedule)}\n[Service]\nType=oneshot\nExecStart=/usr/bin/python3 /usr/lib/ostojaos/management/smart_schedule.py {links[0]} {p['test']} {weeks} {start.isoformat()}\n",
                    0o644,
                )
                day = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")[p["weekday"]]
                atomic(
                    "/etc/systemd/system/" + unit + ".timer",
                    f'[Unit]\nDescription=OstojaOS scheduled SMART test\n[Timer]\nOnCalendar={day} *-*-* {p["hour"]:02d}:00:00\nPersistent=false\n[Install]\nWantedBy=timers.target\n',
                    0o644,
                )
                command(["systemctl", "daemon-reload"])
                command(["systemctl", "enable", unit + ".timer"])
                command(["systemctl", "restart", unit + ".timer"])
            command(["systemctl", "daemon-reload"])
        else:
            option = ["-X"] if action == "smart.abort" else ["-t", action.split(".")[1]]
            command(["smartctl", *option, target], accepted=tuple(range(0, 256, 8)))
    command(["udevadm", "settle"], timeout=30)
    return {
        "message": 'Operation complete. Background synchronization or SMART testing is shown in device status.',
        "target": target,
    }


def smart_schedule(serial, root=Path("/etc/systemd/system")):
    if not serial:
        return None
    unit = "ostojaos-smart-" + hashlib.sha256(serial.encode()).hexdigest()[:16]
    timer = root / (unit + ".timer")
    service = root / (unit + ".service")
    if not timer.exists() or not service.exists():
        return None
    calendar = re.search(
        r"^OnCalendar=(Mon|Tue|Wed|Thu|Fri|Sat|Sun) \*-\*-\* (\d{2}):00:00$", timer.read_text(), re.M
    )
    test = re.search(r"^ExecStart=/usr/sbin/smartctl -t (short|long) ", service.read_text(), re.M)
    if not calendar or not test:
        return None
    return {
        "test": test[1],
        "weekday": ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun").index(calendar[1]),
        "hour": int(calendar[2]),
    }


def smart_schedules(serial, root=Path("/etc/systemd/system")):
    legacy = smart_schedule(serial, root)
    result = {legacy["test"]: {**legacy, "weeks": 1}} if legacy else {}
    if not serial:
        return []
    base = "ostojaos-smart-" + hashlib.sha256(serial.encode()).hexdigest()[:16]
    for test in ("short", "long"):
        service = root / (base + "-" + test + ".service")
        timer = root / (base + "-" + test + ".timer")
        if service.exists() and timer.exists():
            match = re.search(r"^# OstojaOS schedule: (.+)$", service.read_text(), re.M)
            if match:
                result[test] = json.loads(match[1])
    return list(result.values())


def media_info(row, sysroot=Path("/sys/class/block")):
    block = sysroot / row["kname"]
    node = block / "device"

    def read(path):
        try:
            return path.read_text().strip()
        except OSError:
            return ""

    info = {"readOnly": read(block / "ro") == "1"}
    card = read(node / "type") if row.get("tran") == "mmc" else ""
    if card in ("SD", "MMC"):
        info["kind"] = "sd" if card == "SD" else "emmc"
        for key, attr in [
            ("name", "name"),
            ("manufacturerId", "manfid"),
            ("manufactured", "date"),
            ("revision", "hwrev"),
        ]:
            value = read(node / attr)
            if value:
                info[key] = value
    elif row.get("tran") == "usb":
        info["kind"] = "usb"
        parent = node.resolve()
        while parent != parent.parent:
            vendor = read(parent / "idVendor")
            product = read(parent / "idProduct")
            if vendor and product:
                info["usbId"] = vendor + ":" + product
                for key, attr in [
                    ("usbVersion", "version"),
                    ("linkMbps", "speed"),
                    ("manufacturer", "manufacturer"),
                    ("name", "product"),
                ]:
                    value = read(parent / attr)
                    if value:
                        info[key] = value
                break
            parent = parent.parent
        if read(block / "removable") == "1":
            info["kind"] = "usb-flash"
    else:
        info["kind"] = "nvme" if row.get("tran") == "nvme" else "hdd" if row.get("rota") else "ssd"
    return info


def query(view, target):
    if view == "raid-candidates":
        inv = inventory()
        target = device(target, inv)
        md = Path("/sys/class/block") / inv[target]["kname"] / "md"
        require(md.is_dir(), 'Array no longer available. Refresh the device list.')
        members = ["/dev/" + p.name for p in (md.parent / "slaves").iterdir()]
        require(members, 'Could not determine array member sizes')
        minimum = min(inv[m]["size"] for m in members)
        candidates = []
        for path, row in inv.items():
            if row["type"] not in ("disk", "part") or row.get("fstype") or row["size"] < minimum:
                continue
            try:
                protected(path, inv)
                unused(path, inv)
            except Rejected:
                continue
            candidates.append(row)
        return {"devices": candidates}
    if view == "storage-options":
        inv = inventory()
        rows = []
        fstab = [
            line.split()
            for line in Path("/etc/fstab").read_text().splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        for path, d in inv.items():
            row = dict(d)
            if d["type"] == "disk":
                row["media"] = media_info(d)
                row["smartSchedule"] = smart_schedule(d.get("serial"))
                row["smartSchedules"] = smart_schedules(d.get("serial"))

            entry = next(
                (f for f in fstab if len(f) >= 4 and d.get("uuid") and f[0] == "UUID=" + d["uuid"]), None
            )
            row["mountSettings"] = (
                {
                    "point": re.sub(r"\\([0-7]{3})", lambda m: chr(int(m[1], 8)), entry[1]),
                    "automount": "noauto" not in entry[3].split(","),
                    "readOnly": "ro" in entry[3].split(","),
                }
                if entry
                else None
            )
            row["filesystemHealth"] = filesystem_health.cached(path)
            row["protectedReason"] = ""
            row["busyReason"] = ""
            row["raidReason"] = ""
            try:
                protected(path, inv)
            except Rejected as e:
                row["protectedReason"] = str(e)
            try:
                unused(path, inv)
            except Rejected as e:
                row["busyReason"] = str(e)
            row["raidReason"] = (
                row["protectedReason"]
                or row["busyReason"]
                or (
                    'The disk contains a file system. Prepare it in Partitions and mounts.'
                    if d.get("fstype")
                    else ""
                )
            )
            row["raidEligible"] = (
                d["type"] == "disk" and not row["raidReason"] and not d["kname"].startswith(("zram", "ram"))
            )
            row["ejectable"] = (
                d["type"] == "disk"
                and not row["protectedReason"]
                and (Path("/sys/class/block") / d["kname"] / "device/delete").exists()
                and all(
                    inv[dev]["type"] in ("disk", "part")
                    and not list((Path("/sys/class/block") / inv[dev]["kname"] / "holders").glob("*"))
                    for dev in descendants(path, inv)
                )
            )
            rows.append(row)
        return {
            "sleepSettings": disk_sleep.read(),
            "sleepStatus": json.loads(disk_sleep.STATE.read_text()) if disk_sleep.STATE.exists() else {},
            "devices": rows,
            "formats": supported_formats(),
            "capabilities": {
                "ext4": {
                    "create": bool(shutil.which("mkfs.ext4")),
                    "grow": True,
                    "shrink": True,
                    "resizeRequiresUnmount": True,
                },
                "xfs": {
                    "create": bool(shutil.which("mkfs.xfs")),
                    "grow": True,
                    "shrink": False,
                    "resizeRequiresMount": True,
                },
                "btrfs": {
                    "create": bool(shutil.which("mkfs.btrfs")),
                    "grow": True,
                    "shrink": True,
                    "resizeRequiresMount": True,
                },
                "vfat": {"create": bool(shutil.which("mkfs.vfat")), "grow": False, "shrink": False},
            },
        }
    if view == "smart":
        inv = inventory()
        target = device(target, inv)
        require(inv[target]["type"] == "disk", 'Select a physical disk')
        raw = command(["smartctl", "-n", "standby,3,5", "-a", "-j", target], accepted=tuple(range(256)))
        return json.loads(raw)
    raise Rejected('Unknown storage query')
