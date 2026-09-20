import pwd
from common import *
from storage import mountpoint

ACTIONS = {"nfs.mount", "nfs.unmount", "smb.mount", "smb.unmount"}
FSTAB = Path("/etc/fstab")
CREDENTIALS = Path("/etc/panasms/network-credentials")


def key(point):
    return hashlib.sha256(str(point).encode()).hexdigest()[:24]


def marker(point):
    return "# panasms-network-" + key(point)


def entries(text):
    return [line.split() for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")]


def mounted(point):
    result = command(
        ["findmnt", "--json", "--mountpoint", str(point), "-o", "TARGET,SOURCE,FSTYPE,OPTIONS"],
        accepted=(0, 1),
    )
    return json.loads(result).get("filesystems", []) if result.strip() else []


def plan(action, p, user):
    target = p.get("target", "")
    point = mountpoint(p.get("point") if action.endswith(".mount") else target)
    require(
        not any(c.isspace() or c in "\\,#" for c in str(point)),
        'Choose a mount point without spaces, commas or backslashes',
    )
    conf = FSTAB.read_text()
    rows = mounted(point)
    if action.endswith(".mount"):
        pattern = (
            r"[a-zA-Z0-9.-]+:/[^\s\x00\\#]*" if action == "nfs.mount" else r"//[a-zA-Z0-9.-]+/[^/\s\x00\\#]+"
        )
        require(
            isinstance(target, str) and re.fullmatch(pattern, target),
            'Specify server:/path for NFS or //server/share for SMB',
        )
        require(not rows, 'This mount point is already mounted')
        require(
            not point.exists() or (point.is_dir() and not any(point.iterdir())),
            'The mount point must be an empty directory',
        )
        require(
            not any(len(row) > 1 and row[1] == str(point) for row in entries(conf)),
            'The mount point is already configured in fstab',
        )
        for field in ("automount", "readOnly"):
            require(isinstance(p.get(field, False), bool), 'Invalid mount mode')
        if action == "smb.mount":
            for field in ("username", "password", "domain"):
                value = p.get(field, "")
                require(
                    isinstance(value, str) and len(value) <= 4096 and not any(c in value for c in "\r\n\x00"),
                    'Invalid SMB credentials',
                )
            require(bool(p.get("username")) and bool(p.get("password")), 'Specify SMB username and password')
            pwd.getpwnam(user)
        details = [
            target,
            str(point),
            'Read-only' if p.get("readOnly") else 'Read and write',
            'Mount at startup' if p.get("automount") else 'Until unmounted or restarted',
        ]
    else:
        types = ("nfs", "nfs4") if action == "nfs.unmount" else ("cifs",)
        require(rows and rows[0]["fstype"] in types, 'Network mount not found')
        busy = command(["fuser", "-m", str(point)], accepted=(0, 1)).strip()
        require(
            not busy,
            'Folder is in use by processes (PID: '
            + busy
            + '). Finish file transfers or close programs using the folder.',
        )
        details = [
            rows[0]["source"],
            str(point),
            'Unmount the share and remove automatic mounting if configured by the panel',
        ]
    return {
        "target": target,
        "details": details,
        "confirmation": target,
        "fingerprint": fingerprint(action, p, [conf, rows, user]),
    }


def execute(action, p, user):
    point = mountpoint(p.get("point") if action.endswith(".mount") else p["target"])
    credential = CREDENTIALS / key(point)
    if action.endswith(".unmount"):
        command(["umount", "--", str(point)])
        before = FSTAB.read_text()
        after = "\n".join(line for line in before.splitlines() if not line.endswith(marker(point))) + "\n"
        if before != after:
            atomic(FSTAB, after, 0o644)
            command(["systemctl", "daemon-reload"])
        credential.unlink(missing_ok=True)
        return {"message": 'Network share unmounted'}
    point.mkdir(parents=True, exist_ok=True)
    opts = ("ro" if p.get("readOnly") else "rw") + ",nosuid,nodev,_netdev"
    fs = "nfs"
    attached = False
    credential_created = False
    before = FSTAB.read_text()
    try:
        if action == "smb.mount":
            fs = "cifs"
            account = pwd.getpwnam(user)
            CREDENTIALS.mkdir(parents=True, exist_ok=True, mode=0o700)
            CREDENTIALS.chmod(0o700)
            require(
                not credential.exists(), 'Credentials are already stored for this mount point; choose another'
            )
            content = "username=" + p["username"] + "\npassword=" + p["password"] + "\n"
            if p.get("domain"):
                content += "domain=" + p["domain"] + "\n"
            atomic(credential, content, 0o600)
            credential_created = True
            opts += f",credentials={credential},uid={account.pw_uid},gid={account.pw_gid},file_mode=0600,dir_mode=0700,vers=3.0"
        try:
            command(["mount", "-t", fs, "-o", opts, "--", p["target"], str(point)], timeout=120)
        except Rejected:
            raise Rejected(
                'Could not mount network share. Check its address, server availability and read/write permissions'
                + (
                    ', and the SMB username and password.'
                    if fs == "cifs"
                    else ' for the PaNasMs IP address in NFS rules.'
                )
            )
        attached = True
        if p.get("automount"):
            opts += ",nofail,x-systemd.mount-timeout=30s"
            atomic(
                FSTAB, before.rstrip() + f"\n{p['target']} {point} {fs} {opts} 0 0 {marker(point)}\n", 0o644
            )
            command(["systemctl", "daemon-reload"])
    except Exception:
        if attached:
            command(["umount", "--", str(point)])
        if FSTAB.read_text() != before:
            atomic(FSTAB, before, 0o644)
            command(["systemctl", "daemon-reload"])
        if credential_created:
            credential.unlink(missing_ok=True)
        raise
    return {"message": 'Network share mounted', "point": str(point)}
