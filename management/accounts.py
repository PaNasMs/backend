import grp
import pwd
import re
import secrets
import homes
import folder_locations
import account_policy
import account_sessions
import account_ssh
from common import *

ACTIONS = {
    "homes.move",
    "homes.recover",
    "user.create",
    "user.security",
    "user.identity",
    "user.key.add",
    "user.key.delete",
    "user.session.end",
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
    require(lo <= user.pw_uid <= hi and user.pw_uid != 65534 and user.pw_name != "panasms" and local(user), 'Service account is protected')


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
        folder_locations.destination(p)
    return p


def local(user):
    rows = [line.split(':') for line in Path('/etc/passwd').read_text().splitlines()]
    return sum(len(row) == 7 and row[2] == str(user.pw_uid) for row in rows) == 1 and any(row[0] == user.pw_name for row in rows)


def admins():
    g = grp.getgrnam('sudo')
    result = []
    for u in pwd.getpwall():
        try: normal(u)
        except Rejected: continue
        policy = account_policy.entry(u)
        state = account_policy.shadow(u.pw_name)
        if (u.pw_name in g.gr_mem or u.pw_gid == g.gr_gid) and not policy.get('disabled') and policy.get('panel', True) and state['passwordStatus'] == 'set' and not account_policy.expired(state) and not account_policy.password_inactive(state):
            result.append(u)
    return result


def protect_admin(user, actor, loses_access):
    if loses_access:
        require(user.pw_name != actor, 'You cannot remove your own panel access or administrator role')
        if user.pw_name in [u.pw_name for u in admins()]:
            require(len(admins()) > 1, 'The last available administrator is protected')


def selected_groups(p):
    values = p.get('groups', [])
    require(isinstance(values, list) and all(isinstance(g, str) for g in values), 'Select groups')
    for value in values: grp.getgrnam(name(value))
    return sorted(set(values))


def shells():
    return [line.strip() for line in Path('/etc/shells').read_text().splitlines() if line.startswith('/') and Path(line.strip()).is_file() and not line.strip().endswith(('nologin', 'false'))]


def query(target=None):
    all_groups = grp.getgrall()
    users = []
    for user in pwd.getpwall():
        groups = [g.gr_name for g in all_groups if g.gr_gid == user.pw_gid or user.pw_name in g.gr_mem]
        category = 'admin' if 'sudo' in groups else 'user'
        try: normal(user)
        except Rejected: category = 'service'
        policy = account_policy.entry(user)
        state = account_policy.shadow(user.pw_name)
        day = state.get('expiryDay', -1)
        users.append({'username': user.pw_name, 'name': user.pw_gecos.split(',')[0], 'uid': user.pw_uid, 'gid': user.pw_gid,
                      'home': user.pw_dir, 'shell': user.pw_shell, 'category': category, 'groups': groups,
                      'primaryGroup': next((g.gr_name for g in all_groups if g.gr_gid == user.pw_gid), str(user.pw_gid)),
                      'panel': category != 'service' and policy.get('panel', category == 'admin'),
                      'disabled': bool(policy.get('disabled')), 'expired': account_policy.expired(state) or account_policy.password_inactive(state),
                      'ssh': policy.get('ssh', user.pw_shell in shells()),
                      'expiry': policy.get('expiry','') if policy.get('disabled') else (str(account_policy.datetime.date(1970,1,1) + account_policy.datetime.timedelta(days=day)) if day >= 0 else ''),
                      'reason': 'Protected or ambiguous system account' if category == 'service' else 'Local account in the Linux user UID range', **state})
    lo, hi = bounds('GID')
    groups = [{'name': g.gr_name, 'gid': g.gr_gid, 'members': sorted(set(g.gr_mem) | {u.pw_name for u in pwd.getpwall() if u.pw_gid == g.gr_gid}),
               'primaryMembers': [u.pw_name for u in pwd.getpwall() if u.pw_gid == g.gr_gid],
               'editable': (lo <= g.gr_gid <= hi or g.gr_name == 'sudo'), 'system': not lo <= g.gr_gid <= hi} for g in all_groups]
    if target:
        user = next((u for u in users if u['username'] == target), None)
        require(user is not None, 'User not found')
        user['keys'] = []
        if user['category'] != 'service':
            import sharing
            user['smb'] = sharing.account_status(target)
            try: user['keys'] = key_operation(target, {'action':'list'})
            except Rejected as error: user['keysError'] = str(error)
        return user
    return {'users': users, 'groups': groups, 'shells': shells(), 'passwordPolicy': 'Linux PAM / passwd', 'sshAvailable': bool(shutil.which('sshd'))}


def key_operation(target, body):
    raw = command(['/usr/bin/python3', '/usr/lib/panasms/profile-keys.py', target], data=json.dumps(body))
    return json.loads(raw)


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
            selected_groups(p)
            if p.get('primaryGroup'): grp.getgrnam(name(p['primaryGroup']))
            else: require(not any(g.gr_name == target for g in grp.getgrall()), 'A group with this name exists; select a primary group')
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
                homes.idle(u.pw_dir, [u])
            elif action == "user.edit":
                validate_name(p.get("name", ""))
                groups = selected_groups(p)
                primary = grp.getgrnam(name(p['primaryGroup'])).gr_gid if p.get('primaryGroup') else u.pw_gid
                sudo_gid = grp.getgrnam('sudo').gr_gid
                currently_admin = u.pw_gid == sudo_gid or u.pw_name in grp.getgrnam('sudo').gr_mem
                protect_admin(u, actor, currently_admin and 'sudo' not in groups and primary != sudo_gid)
            elif action == 'user.security':
                policy = account_policy.entry(u)
                for field in ('panel','ssh','disabled','forcePasswordChange'):
                    require(isinstance(p.get(field), bool), 'Access flags must be boolean')
                disabled = bool(p.get('disabled'))
                panel = bool(p.get('panel'))
                expiry = account_policy.expiry(p.get('expiry', ''))
                protect_admin(u, actor, disabled or not panel or (expiry >= 0 and expiry <= (account_policy.datetime.date.today()-account_policy.datetime.date(1970,1,1)).days))
                if p.get('ssh'):
                    require(bool(shutil.which('sshd')), 'OpenSSH server is not installed')
                    require(p.get('shell') in shells(), 'Select an installed login shell')
                for field in ('minDays', 'maxDays', 'warnDays', 'inactiveDays'):
                    value = p.get(field, -1)
                    require(isinstance(value, int) and not isinstance(value, bool) and -1 <= value <= 99999, 'Invalid password aging value')
                projected = {**account_policy.shadow(target), **{key:p[key] for key in ('minDays','maxDays','warnDays','inactiveDays')}}
                if p.get('forcePasswordChange'): projected['lastChange'] = 0
                protect_admin(u, actor, account_policy.password_inactive(projected))
                if panel and not disabled:
                    require(account_policy.shadow(target)['passwordStatus'] == 'set', 'Set a Linux password before enabling panel access')
                details += ['Panel access and Linux account expiry are checked independently', 'Disabling an account ends its panel and SSH sessions; active transfers may stop']
            elif action == 'user.identity':
                uid = p.get('uid')
                lo, hi = bounds('UID')
                require(isinstance(uid, int) and lo <= uid <= hi and uid != 65534, 'UID is outside the Linux user range')
                require(not any(x.pw_uid == uid and x.pw_name != target for x in pwd.getpwall()), 'UID is already in use')
                protect_admin(u, actor, True)
                homes.idle(u.pw_dir, [u])
                details += ['Only home-folder ownership is updated by usermod; files on other volumes retain their numeric owner']
            elif action in ('user.key.add', 'user.key.delete'):
                if action.endswith('add'):
                    require(isinstance(p.get('key'), str) and 0 < len(p['key']) <= 16384, 'Enter an OpenSSH public key')
                else: require(any(k['id'] == p.get('keyId') for k in key_operation(target, {'action':'list'})), 'Key not found')
                details += ['Changing a key does not enable SSH or end existing SSH sessions']
            elif action == 'user.session.end':
                session = next((x for x in account_sessions.sessions(target) if x['id'] == p.get('sessionId')), None)
                require(session is not None, 'SSH session has already ended')
                details += ['End SSH session: ' + session['id'] + ' ' + str(session['address'])]
            elif action == "user.home":
                home(u.pw_dir, target, True)
                home(p.get("home"), target)
                homes.idle(u.pw_dir, [u])
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
            require(lo <= group.gr_gid <= hi or (group.gr_name == 'sudo' and action == 'group.edit'), 'Service group is protected')
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
                primary = {u.pw_name for u in pwd.getpwall() if u.pw_gid == group.gr_gid}
                require(primary.issubset(set(members)), 'Change the primary group before removing a primary member')
                if target == 'sudo':
                    for username in set(group.gr_mem) - set(members):
                        protect_admin(account(username), actor, True)
                    details += ['Membership in sudo grants administrative privileges in Linux']
    state = {"passwd": Path("/etc/passwd").read_text(), "group": Path("/etc/group").read_text(), 'policy':account_policy.read(), 'shadow':Path('/etc/shadow').read_text()}
    if action.startswith('user.key.'): state['keys'] = key_operation(target, {'action':'list'})
    if action == 'user.session.end': state['sessions'] = account_sessions.sessions(target)
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
                *(["--gid", p["primaryGroup"]] if p.get("primaryGroup") else ["--user-group"]),
                "--comment",
                p.get("name", ""),
                "--",
                target,
            ]
        )
        os.chmod(point, 0o700)
        u = pwd.getpwnam(target)
        account_policy.save(u, {'panel':False, 'ssh':False, 'disabled':False, 'principal':secrets.token_hex(16), 'created':account_policy.datetime.datetime.now(account_policy.datetime.timezone.utc).isoformat()}, revoke=True)
        try: command(['chpasswd'], data=target + ':' + p['password'] + '\n')
        except Exception:
            raise Rejected('User created with panel access disabled; Linux rejected the password. Reset the password before enabling access.')
        args = ['usermod', '--groups', ','.join(selected_groups(p))]
        if p.get('primaryGroup'): args += ['--gid',p['primaryGroup']]
        command([*args, '--', target])
        account_ssh.apply()
        account_policy.save(pwd.getpwnam(target), {'panel':True})
    elif action == "user.edit":
        before = set(os.getgrouplist(target, pwd.getpwnam(target).pw_gid))
        args = ["usermod", "--comment", p.get("name", ""), "--groups", ",".join(p.get("groups", []))]
        if p.get("primaryGroup"):
            args += ["--gid", p["primaryGroup"]]
        command([*args, "--", target])
        current = pwd.getpwnam(target)
        changed_groups = before != set(os.getgrouplist(target, current.pw_gid))
        account_policy.save(current, {}, revoke=changed_groups)
        if changed_groups:
            import sharing
            sharing.disconnect(target)
    elif action == 'user.security':
        u = account(target)
        account_policy.save(u, {'disabled':bool(p.get('disabled')), 'panel':bool(p.get('panel')), 'ssh':bool(p.get('ssh')), 'expiry':p.get('expiry','')}, revoke=True)
        if p.get('disabled'):
            import sharing
            sharing.disable(target)
        expiry = 1 if p.get('disabled') else account_policy.expiry(p.get('expiry',''))
        command(['chage','--expiredate',str(expiry),'--mindays',str(p['minDays']),'--maxdays',str(p['maxDays']),'--warndays',str(p['warnDays']),'--inactive',str(p['inactiveDays']),target])
        if p.get('forcePasswordChange'): command(['chage','--lastday','0',target])
        elif account_policy.shadow(target).get('forcePasswordChange'):
            command(['chage','--lastday',str((account_policy.datetime.date.today()-account_policy.datetime.date(1970,1,1)).days),target])
        command(['usermod','--shell', p['shell'] if p.get('ssh') else '/usr/sbin/nologin','--',target])
        account_ssh.apply()
        if p.get('disabled') or not p.get('ssh'): account_sessions.terminate(target)
    elif action == 'user.identity':
        import sharing
        sharing.disable(target)
        previous = account_policy.entry(account(target))
        command(['usermod','--uid',str(p['uid']),'--',target],timeout=86400)
        account_policy.save(pwd.getpwnam(target), previous, revoke=True)
    elif action.startswith('user.key.'):
        key_operation(target, {'action':'add' if action.endswith('add') else 'delete','key':p.get('key',''),'id':p.get('keyId','')})
    elif action == 'user.session.end':
        account_sessions.terminate(target, p['sessionId'])
    elif action == "user.password":
        command(["chpasswd"], data=target + ":" + p["password"] + "\n")
        account_policy.save(pwd.getpwnam(target), {}, revoke=True)
        if p.get("forcePasswordChange"): command(["chage","--lastday","0",target])
        import sharing
        sharing.sync_password(target, p["password"])
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
        account_policy.save(u, {"disabled":True,"panel":False,"ssh":False}, revoke=True)
        import sharing
        sharing.remove_account(target)
        command(["userdel", "--", target])
        account_ssh.apply()
    elif action == "group.create":
        command(["groupadd", "--", target])
    elif action == "group.edit":
        before = set(grp.getgrnam(target).gr_mem)
        command(["gpasswd", "--members", ",".join(p.get("members", [])), target])
        import sharing
        for username in before ^ set(p.get('members', [])): sharing.disconnect(username)
        if target == 'sudo':
            for username in before ^ set(p.get('members', [])):
                account_policy.save(pwd.getpwnam(username), {}, revoke=True)
    elif action == "group.delete":
        command(["groupdel", "--", target])
    return {"message": 'Users and groups updated'}
