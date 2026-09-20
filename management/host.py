from common import *
import network_mounts

ACTIONS = {
    "system.poweroff",
    "system.reboot",
    "service.start",
    "service.stop",
    "service.restart",
    "service.enable",
    "service.disable",
    "updates.refresh",
    "updates.install",
    "nfs.mount",
    "smb.mount",
    "smb.unmount",
    "nfs.unmount",
    "nfs.export",
    "nfs.export-remove",
    "folder.permissions",
}


def service(value):
    require(
        isinstance(value, str) and re.fullmatch(r"[a-zA-Z0-9_.@:-]+\.service", value),
        'Select a systemd service',
    )
    require(
        not value.startswith(("panasms-", "ssh", "systemd-", "dbus", "network", "NetworkManager", "getty")),
        'This service is protected from changes through the panel',
    )
    require(
        command(["systemctl", "show", "--property=LoadState", "--value", value]).strip() == "loaded",
        'Service is not loaded',
    )
    return value


def query(view, target):
    if view == "nfs":
        return export_query()
    if view == "power":
        raw = command(["vcgencmd", "get_throttled"]).strip()
        value = int(raw.split("=")[1], 16)
        return {
            "throttled": raw,
            "undervoltage": bool(value & 1),
            "throttling": bool(value & 4),
            "pastUndervoltage": bool(value & (1 << 16)),
        }
    if view == "services":
        units = json_command(["systemctl", "list-units", "--type=service", "--all", "--output=json"])
        files = json_command(["systemctl", "list-unit-files", "--type=service", "--output=json"])
        states = {row["unit_file"]: row.get("state") for row in files}
        for unit in units:
            unit["enabled"] = states.get(unit["unit"], "unknown")
        return {"services": units}
    if view == "journal":
        args = ["journalctl", "--no-pager", "--output=json", "--lines=300", "--reverse"]
        filters = json.loads(target) if target.startswith("{") else {"unit": target}
        target = filters.get("unit", "")
        priority = filters.get("priority", 7)
        integer(priority, 0, 7)
        args += ["--priority", str(priority)]
        since = filters.get("since", "24h")
        require(since in ("1h", "24h", "7d", "all"), 'Invalid period')
        if since != "all":
            args += ["--since", {"1h": "1 hour ago", "24h": "1 day ago", "7d": "7 days ago"}[since]]
        boot = filters.get("boot", "all")
        require(boot in ("all", "current", "previous"), 'Invalid boot selection')
        if boot != "all":
            args += ["--boot", "0" if boot == "current" else "-1"]
        if target:
            require(bool(re.fullmatch(r"[a-zA-Z0-9_.@:-]+\.service", target)), 'Invalid service')
            args += ["--unit", target]
        rows = []
        for line in command(args).splitlines():
            row = json.loads(line)
            rows.append(
                {
                    "time": row.get("__REALTIME_TIMESTAMP"),
                    "priority": row.get("PRIORITY"),
                    "unit": row.get("_SYSTEMD_UNIT"),
                    "message": str(row.get("MESSAGE", ""))[:8192],
                }
            )
        return {"entries": rows}
    if view == "updates":
        raw = command(["apt-get", "--simulate", "upgrade"], timeout=60)
        rows = [line for line in raw.splitlines() if line.startswith(("Inst ", "Remv "))]
        return {"packages": rows, "rebootRequired": Path("/run/reboot-required").exists()}
    raise Rejected('Unknown system query')


def plan(action, p, user=None):
    if action in network_mounts.ACTIONS:
        return network_mounts.plan(action, p, user)
    if action == "folder.permissions":
        import pwd, grp

        target = export_path(p.get("target"))
        owner = pwd.getpwnam(name(p.get("owner")))
        group = grp.getgrnam(name(p.get("group")))
        require(owner.pw_uid >= 1000, 'Select a regular user')
        require(
            p.get("mode") in ("0700", "0750", "0770", "0755", "0775", "2770", "2775"), 'Invalid permissions'
        )
        fs = json_command(["findmnt", "--json", "--target", str(target), "--output", "FSTYPE"])[
            "filesystems"
        ][0]["fstype"]
        require(fs in ("ext2", "ext3", "ext4", "xfs", "btrfs"), 'This file system does not support the selected Unix permissions')
        s = target.stat()
        state = [s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_mode]
        return {
            "target": str(target),
            "details": [
                str(target),
                'Owner: ' + owner.pw_name,
                'Group: ' + group.gr_name,
                'Permissions: ' + p["mode"],
                'Apply only to the selected folder, without recursion',
            ],
            "confirmation": str(target),
            "fingerprint": fingerprint(action, p, state),
        }
    if action in ("nfs.export", "nfs.export-remove"):
        return export_plan(action, p)
    require(action in ACTIONS, 'Unknown system operation')
    target = p.get("target", "")
    state = {}
    details = []
    if action in ("system.poweroff", "system.reboot"):
        target = "NAS"
        state = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        details = [action]
    elif action.startswith("service."):
        target = service(target)
        state = command(["systemctl", "show", "--property=ActiveState,UnitFileState,LoadState", target])
        details = [target, action.split(".")[1]]
    elif action.startswith("updates."):
        target = 'OS UPDATE'
        state = query("updates", "")
        details = state["packages"] if action == "updates.install" else ['Refresh available package lists']
        require(action != "updates.install" or bool(details), 'No updates available')
    return {
        "target": target,
        "details": details,
        "confirmation": target,
        "fingerprint": fingerprint(action, p, state),
    }


def execute(action, p, user=None):
    if action in ("system.poweroff", "system.reboot"):
        command(["systemd-run", "--unit=panasms-power-request", "--on-active=5s",
                 "--timer-property=AccuracySec=1s", "/usr/bin/systemctl",
                 "--no-block", action.split(".")[1]])
        return {"message": "Power operation scheduled"}
    if action in network_mounts.ACTIONS:
        return network_mounts.execute(action, p, user)
    if action == "folder.permissions":
        import pwd, grp

        target = export_path(p["target"])
        owner = pwd.getpwnam(p["owner"])
        group = grp.getgrnam(p["group"])
        fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
        try:
            for part in target.parts[1:]:
                nextfd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = nextfd
            os.fchown(fd, owner.pw_uid, group.gr_gid)
            os.fchmod(fd, int(p["mode"], 8))
        finally:
            os.close(fd)
        return {"message": 'Folder ownership and permissions updated'}
    if action in ("nfs.export", "nfs.export-remove"):
        return export_execute(action, p)
    target = p.get("target", "")
    if action.startswith("service."):
        verb = action.split(".")[1]
        command(["systemctl", verb, target])
        state = command(["systemctl", "show", "--property=ActiveState,UnitFileState", "--value", target])
        return {"message": state}
    if action == "updates.refresh":
        command(["apt-get", "update"], timeout=1800)
    elif action == "updates.install":
        command(["apt-get", "-y", "-o", "Dpkg::Options::=--force-confold", "upgrade"], timeout=86400)
    return {"message": 'Done', "rebootRequired": Path("/run/reboot-required").exists()}


def export_path(value):
    from storage import mountpoint

    point = mountpoint(value)
    require(point.is_dir(), 'Directory does not exist')
    row = json_command(["findmnt", "--json", "--target", str(point), "--output", "TARGET,FSTYPE"])[
        "filesystems"
    ][0]
    require(
        row["target"] != "/" and row["fstype"] not in ("nfs", "nfs4", "cifs", "autofs"),
        'The shared folder must be on a mounted local volume',
    )
    require(
        not any(c in str(point) for c in ' \t\\"'), 'The share path must not contain spaces or quotation marks'
    )
    return point


def export_plan(action, p):
    import ipaddress

    target = export_path(p.get("target"))
    conf = Path("/etc/exports.d/panasms.exports")
    state = conf.read_text() if conf.exists() else ""
    if action == "nfs.export":
        clients = p.get("clients", "").split(",")
        require(0 < len(clients) <= 32, 'Specify NFS clients')
        for client in clients:
            try:
                ipaddress.ip_network(client.strip(), strict=False)
            except ValueError:
                raise Rejected('Specify clients as comma-separated IP addresses or subnets')
    return {
        "target": str(target),
        "details": [
            str(target),
            'Clients: ' + p.get("clients", ""),
            'NFS: Linux UID/GID permissions; root_squash enabled',
        ],
        "confirmation": str(target),
        "fingerprint": fingerprint(action, p, state),
    }


def export_execute(action, p):
    target = str(export_path(p["target"]))
    conf = Path("/etc/exports.d/panasms.exports")
    rows = conf.read_text().splitlines() if conf.exists() else []
    rows = [line for line in rows if not line.startswith(target + " ")]
    if action == "nfs.export":
        rows.append(
            target
            + " "
            + " ".join(
                c.strip()
                + "("
                + ("ro" if p.get("readOnly") else "rw")
                + ",sync,no_subtree_check,root_squash)"
                for c in p["clients"].split(",")
            )
        )
    atomic(conf, "\n".join(rows) + "\n", 0o644)
    command(["systemctl", "enable", "--now", "nfs-kernel-server"])
    command(["exportfs", "-ra"])
    return {"message": 'NFS share updated'}


def export_query():
    path = Path("/etc/exports.d/panasms.exports")
    entries = []
    for line in path.read_text().splitlines() if path.exists() else []:
        fields = line.split()
        if fields and not fields[0].startswith("#"):
            entries.append(
                {
                    "path": fields[0],
                    "clients": [v.split("(")[0] for v in fields[1:]],
                    "readOnly": all("(ro," in v for v in fields[1:]),
                }
            )
    return {"exports": entries}
