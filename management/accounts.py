import grp
import pwd
import re
import homes
from common import *

ACTIONS = {
    "homes.move",
    "homes.recover",
    "user.create",
    "user.edit",
    "user.delete",
    "user.password",
    "user.home",
    "group.create",
    "group.edit",
    "group.delete",
}


def bounds(kind):
    values = {kind + "_MIN": 1000, kind + "_MAX": 60000}
    for line in Path("/etc/login.defs").read_text().splitlines():
        f = line.split()
        if len(f) > 1 and f[0] in values:
            values[f[0]] = int(f[1])
    return tuple(values.values())


def normal(user):
    lo, hi = bounds("UID")
    require(lo <= user.pw_uid <= hi and user.pw_name != "ostojaos", 'Service account is protected')


def account(value):
    name(value)
    try:
        u = pwd.getpwnam(value)
    except KeyError:
        raise Rejected('User not found')
    normal(u)
    return u


def home(value, username, existing=False):
    p = clean_path(value)
    require(
        str(p).startswith(("/home/", "/srv/", "/mnt/")),
        'The home folder must be under /home, /srv or /mnt',
    )
    require(len(p.parts) >= 3 and p.name not in ("lost+found",), 'Invalid home folder')
    require(not any(x.is_symlink() for x in [p, *p.parents]), 'Links in the home folder path are not allowed')
    for u in pwd.getpwall():
        if u.pw_name != username:
            require(
                not (
                    str(p) == u.pw_dir
                    or u.pw_dir.startswith(str(p) + "/")
                    or str(p).startswith(u.pw_dir.rstrip("/") + "/")
                    and u.pw_dir not in ("/", "/nonexistent")
                ),
                "The path overlaps another user's home folder",
            )
    if str(p).startswith(("/srv/", "/mnt/")):
        source = command(["findmnt", "-n", "-o", "TARGET", "-T", str(p if p.exists() else p.parent)]).strip()
        require(
            source != "/" and str(p).startswith(source.rstrip("/") + "/"),
            'The home volume is unavailable or the path is a volume root',
        )
    if existing:
        require(p.is_dir(), 'Home folder unavailable')
        require(
            p.stat().st_uid == pwd.getpwnam(username).pw_uid,
            'The home folder belongs to another user',
        )
        mounts = json_command(["findmnt", "--json", "--list", "-o", "TARGET"])["filesystems"]
        require(
            not any(m["target"] == str(p) or m["target"].startswith(str(p) + "/") for m in mounts),
            'The home folder contains mounts',
        )
    else:
        require(not p.exists(), 'Destination folder already exists')
    return p


def admins():
    g = grp.getgrnam("sudo")
    return [
        u
        for u in pwd.getpwall()
        if u.pw_uid > 0
        and (u.pw_name in g.gr_mem or u.pw_gid == g.gr_gid)
        and u.pw_shell not in ("/usr/sbin/nologin", "/bin/false")
    ]


def validate_name(value):
    require(
        isinstance(value, str) and len(value) <= 80 and not any(ord(c) < 32 or c in ":," for c in value),
        'Invalid display name',
    )


def plan(action, p, actor):
    require(action in ACTIONS, 'Unknown user operation')
    if action == "homes.move":
        return homes.plan(p)
    if action == "homes.recover":
        require(homes.JOURNAL.exists(), "No interrupted home move")
        return {"target": "homes", "confirmation": "homes", "details": [], "fingerprint": fingerprint(action, p, homes.JOURNAL.read_text())}
    target = name(p.get("target"))
    details = [target]
    if action.startswith("user."):
        if action == "user.create":
            require(not any(u.pw_name == target for u in pwd.getpwall()), 'User already exists')
            home((p.get("home") or homes.base() + "/" + target), target)
            validate_name(p.get("name", ""))
            password = p.get("password", "")
            require(
                isinstance(password, str)
                and password
                and len(password) <= 4096
                and not any(c in password for c in "\n\r\x00"),
                'Enter your password',
            )
            details += ['Create Linux user and home folder with 0700 permissions', 'SSH is disabled by default']
        else:
            u = account(target)
            if action == "user.delete":
                require(actor != target, 'You cannot delete yourself')
                require(
                    target not in [a.pw_name for a in admins()] or len(admins()) > 1,
                    'The last administrator is protected',
                )
                if p.get("deleteHome", True):
                    home(u.pw_dir, target, True)
                    details += ['DELETE HOME FOLDER: ' + u.pw_dir]
                details += ['Files in shared folders will be preserved']
                command(["pgrep", "-u", str(u.pw_uid)], accepted=(1,))
            elif action == "user.edit":
                validate_name(p.get("name", ""))
                groups = p.get("groups", [])
                require(
                    isinstance(groups, list) and all(isinstance(g, str) for g in groups), 'Select groups'
                )
                for group in groups:
                    grp.getgrnam(name(group))
                if target in [a.pw_name for a in admins()] and "sudo" not in groups:
                    require(
                        actor != target and len(admins()) > 1,
                        'You cannot remove privileges from yourself or the last administrator',
                    )
                if p.get("primaryGroup"):
                    grp.getgrnam(name(p["primaryGroup"]))
            elif action == "user.home":
                home(u.pw_dir, target, True)
                home(p.get("home"), target)
                command(["pgrep", "-u", str(u.pw_uid)], accepted=(1,))
                details += ['Move ' + u.pw_dir + " → " + p["home"]]
            elif action == "user.password":
                password = p.get("password")
                require(
                    isinstance(password, str)
                    and password
                    and len(password) <= 4096
                    and not any(c in password for c in "\n\r\x00"),
                    'Enter your password',
                )
    else:
        if action == "group.create":
            require(not any(g.gr_name == target for g in grp.getgrall()), 'Group already exists')
        else:
            group = grp.getgrnam(target)
            lo, hi = bounds("GID")
            require(lo <= group.gr_gid <= hi, 'Service group is protected')
            if action == "group.delete":
                require(
                    not group.gr_mem and not any(u.pw_gid == group.gr_gid for u in pwd.getpwall()),
                    'The group is used by users',
                )
            else:
                members = p.get("members", [])
                require(isinstance(members, list), 'Select members')
                for member in members:
                    account(member)
    state = {"passwd": Path("/etc/passwd").read_text(), "group": Path("/etc/group").read_text()}
    return {
        "target": target,
        "details": details,
        "confirmation": target,
        "fingerprint": fingerprint(action, p, state),
    }


def execute(action, p):
    if action == "homes.move":
        return homes.execute(p)
    if action == "homes.recover":
        return homes.recover()
    target = p["target"]
    if action == "user.create":
        point = (p.get("home") or homes.base() + "/" + target)
        command(
            [
                "useradd",
                "--create-home",
                "--home-dir",
                point,
                "--shell",
                "/usr/sbin/nologin",
                "--comment",
                p.get("name", ""),
                "--",
                target,
            ]
        )
        os.chmod(point, 0o700)
        command(["chpasswd"], data=target + ":" + p["password"] + "\n")
    elif action == "user.edit":
        args = ["usermod", "--comment", p.get("name", ""), "--groups", ",".join(p.get("groups", []))]
        if p.get("primaryGroup"):
            args += ["--gid", p["primaryGroup"]]
        command([*args, "--", target])
    elif action == "user.password":
        command(["chpasswd"], data=target + ":" + p["password"] + "\n")
    elif action == "user.home":
        command(["usermod", "--home", p["home"], "--move-home", "--", target], timeout=86400)
        os.chmod(p["home"], 0o700)
    elif action == "user.delete":
        u = account(target)
        if p.get("deleteHome", True):
            point = home(u.pw_dir, target, True)
            # Delete contents as their owner; root only removes the now-empty home directory.
            pid = os.fork()
            if pid == 0:
                try:
                    os.setgroups([])
                    os.setgid(u.pw_gid)
                    os.setuid(u.pw_uid)
                    for child in point.iterdir():
                        if child.is_dir() and not child.is_symlink():
                            shutil.rmtree(child)
                        else:
                            child.unlink()
                    os._exit(0)
                except Exception:
                    os._exit(1)
            _, status = os.waitpid(pid, 0)
            require(status == 0, 'Some home files could not be deleted; the account was preserved')
            point.rmdir()
        command(["userdel", "--", target])
    elif action == "group.create":
        command(["groupadd", "--", target])
    elif action == "group.edit":
        command(["gpasswd", "--members", ",".join(p.get("members", [])), target])
    elif action == "group.delete":
        command(["groupdel", "--", target])
    return {"message": 'Users and groups updated'}
