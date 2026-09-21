from common import *
import contextlib
import fcntl
import grp
import ipaddress
import pwd
import account_policy

ACTIONS = {'share.save', 'share.remove', 'share.account', 'share.recover', 'share.disconnect'}
STATE = Path('/etc/panasms/sharing.json')
SMB = Path('/etc/samba/panasms-shares.conf')
EXPORTS = Path('/etc/exports.d/panasms-shares.exports')
JOURNAL = Path('/var/lib/panasms-agent/sharing-transaction.json')
LOCK = Path('/run/panasms-agent/sharing.lock')
HEADER = '# Managed by PaNasMs. Edit using Shared folders.\n'


@contextlib.contextmanager
def locked():
    LOCK.parent.mkdir(parents=True, exist_ok=True)
    with LOCK.open('a') as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        yield


def read():
    return json.loads(STATE.read_text()) if STATE.exists() else {'shares': [], 'accounts': {}}


def text(path):
    return path.read_text() if path.exists() else ''


def config(shares):
    smb, nfs = HEADER, HEADER
    for s in shares:
        if s['smb']:
            members = s['readers'] + s['writers']
            smb += f"\n[{s['name']}]\npath = {s['path']}\nguest ok = no\nread only = yes\nvalid users = {' '.join(members)}\nwrite list = {' '.join(s['writers'])}\ncreate mask = 0660\ndirectory mask = 0770\ninherit permissions = yes\nwide links = no\nfollow symlinks = no\nroot preexec = /usr/bin/python3 /usr/lib/panasms/management/sharing.py --check {s['name']}\nroot preexec close = yes\n"
        if s['smb'] and s['nfs']:
            smb += 'oplocks = no\nlevel2 oplocks = no\nstrict locking = yes\n'
        if s['nfs']:
            nfs += s['path'] + ' ' + ' '.join(c + '(' + ('ro' if s['readOnly'] else 'rw') + ',sync,no_subtree_check,root_squash,mountpoint=' + s['mountpoint'] + ')' for c in s['clients']) + '\n'
    return smb, nfs


def drift(state):
    expected = config(state['shares'])
    return any(p.exists() and text(p) != v for p, v in zip((SMB, EXPORTS), expected)) or bool(state['shares']) and any(not p.exists() for p in (SMB, EXPORTS))


def mountpoint(path):
    return json_command(['findmnt','--noheadings','--json','--target',path,'--output','TARGET'])['filesystems'][0]['target']


def volume(path):
    rows = json_command(['findmnt','--json','--target',path,'--output','UUID,SOURCE,TARGET'])['filesystems']
    row = rows[0]
    require(row['target'] != '/', 'Shared volume is not mounted')
    return row.get('uuid') or row['source']


def normalize(p):
    from host import export_path
    n = p.get('name', '')
    require(isinstance(n, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}', n) and n.lower() not in ('global','homes','printers','print$','ipc$'), 'Choose a unique share name using letters, numbers, dots, dashes or underscores')
    path = str(export_path(p.get('path')))
    require(not any(c in path for c in '%#;[]\r\n'), 'Share path contains unsupported configuration characters')
    for k in ('smb','nfs','readOnly'): require(type(p.get(k)) is bool, 'Protocol settings must be true or false')
    clients = p.get('clients', '')
    require(isinstance(clients, str), 'Enter NFS clients')
    try: clients = sorted(set(str(ipaddress.ip_network(c.strip(), strict=False)) for c in clients.split(',') if c.strip()))
    except ValueError: raise Rejected('Specify NFS clients as IP addresses or subnets')
    require(not p['nfs'] or 0 < len(clients) <= 32, 'Specify at least one NFS client or subnet')
    result = {k: p[k] for k in ('smb','nfs','readOnly')}
    result.update(name=n, path=path, clients=clients, volume=volume(path), mountpoint=mountpoint(path))
    for k in ('readers','writers'):
        values = p.get(k, [])
        require(isinstance(values, list) and len(values) <= 128, 'Invalid access list')
        for v in values:
            require(isinstance(v, str), 'Invalid access entry')
            name(v[1:] if v.startswith('@') else v)
            try:
                if v.startswith('@'): grp.getgrnam(v[1:])
                else:
                    import accounts
                    accounts.normal(pwd.getpwnam(v))
            except KeyError: raise Rejected('Selected user or group no longer exists')
        result[k] = sorted(set(values))
    require(not p['smb'] or result['readers'] or result['writers'], 'Select users or groups allowed to access SMB')
    return result


def plan(action, p, user=None):
    state = read()
    require(action == 'share.recover' or not JOURNAL.exists(), 'Interrupted sharing update requires recovery')
    require(action == 'share.recover' or not drift(state), 'Sharing configuration was edited outside the panel. Restore the managed configuration before continuing.')
    target = p.get('target', '')
    details = []
    if action == 'share.save':
        s = normalize(p)
        require(not target or any(x['name'] == target for x in state['shares']), 'Shared folder no longer exists')
        require(not any(x['name'] != target and (x['name'].lower() == s['name'].lower() or x['path'] == s['path']) for x in state['shares']), 'This name or folder is already shared')
        from host import export_query
        require(not any(e['path'] == s['path'] for e in export_query()['exports']), 'This folder has a legacy NFS publication. Remove that publication first; files are preserved.')
        target = s['name']
        details = [s['path'], 'SMB: '+str(s['smb']), 'NFS: '+str(s['nfs']), 'Existing files and Unix permissions are preserved. Protocol permissions cannot grant more access than Linux permissions.']
    elif action == 'share.remove':
        require(any(x['name'] == target for x in state['shares']), 'Shared folder no longer exists')
        details = ['Stop publishing this folder. Files and permissions are preserved. Connected clients may be disconnected.']
    elif action == 'share.disconnect':
        import accounts
        accounts.normal(pwd.getpwnam(name(target)))
        details = ['Disconnect all SMB sessions for this user. Active transfers may be interrupted.']
    elif action == 'share.account':
        import accounts
        u = pwd.getpwnam(name(target)); accounts.normal(u)
        require(type(p.get('enabled')) is bool, 'Choose SMB access state')
        details = ['Enable SMB access on the next successful panel password login or password change' if p['enabled'] else 'Disable SMB access and disconnect existing SMB sessions']
    elif action == 'share.recover':
        target = 'sharing'
        details = ['Restore the last saved managed configuration. External edits to managed files will be replaced; data files are preserved.']
    else: raise Rejected('Unknown sharing operation')
    return {'target':target,'confirmation':target,'details':details,'fingerprint':fingerprint(action,p,[state,text(SMB),text(EXPORTS),text(JOURNAL),text(Path('/etc/passwd')),text(Path('/etc/group'))])}


def reload_services(shares):
    if shutil.which('testparm'):
        command(['testparm','-s'], timeout=20)
        if any(s['smb'] for s in shares): command(['systemctl','enable','--now','smbd'])
        if command(['systemctl','is-active','smbd'], accepted=(0,3,4)).strip() == 'active':
            command(['smbcontrol','all','reload-config'])
    if shutil.which('exportfs'):
        if any(s['nfs'] for s in shares): command(['systemctl','enable','--now','nfs-kernel-server'])
        command(['exportfs','-ra'])


def validate_config(shares):
    if any(s['smb'] for s in shares):
        fd, candidate_name = tempfile.mkstemp(prefix='panasms-smb-',suffix='.conf')
        os.close(fd)
        candidate = Path(candidate_name)
        try:
            candidate.write_text(text(Path('/etc/samba/smb.conf')).replace('include = /etc/samba/panasms-shares.conf', config(shares)[0]))
            command(['testparm','-s',str(candidate)],timeout=20)
        finally: candidate.unlink()


def apply(state):
    validate_config(state['shares'])
    old = {str(p):text(p) for p in (STATE,SMB,EXPORTS)}
    atomic(JOURNAL,json.dumps(old))
    try:
        for p,v in zip((SMB,EXPORTS),config(state['shares'])): atomic(p,v,0o644)
        reload_services(state['shares'])
        atomic(STATE,json.dumps(state))
        JOURNAL.unlink()
    except Exception:
        try: recover()
        except Exception: raise Rejected('Sharing update failed and rollback needs recovery. No data files were changed.')
        raise Rejected('Sharing update failed; previous configuration restored. Check service logs.')


def recover():
    if JOURNAL.exists():
        old = json.loads(JOURNAL.read_text())
        for p in (STATE,SMB,EXPORTS):
            v = old[str(p)]
            if v: atomic(p,v,0o600 if p == STATE else 0o644)
            elif p.exists(): p.unlink()
        reload_services(read()['shares'])
        JOURNAL.unlink()
    else:
        state = read()
        for p,v in zip((SMB,EXPORTS),config(state['shares'])): atomic(p,v,0o644)
        reload_services(state['shares'])


def execute(action,p,user=None):
    with locked():
        plan(action,p,user)
        state = read()
        if action == 'share.recover': recover()
        elif action == 'share.disconnect': disconnect(p['target'])
        elif action == 'share.account':
            target = p['target']; u = pwd.getpwnam(target)
            old = state['accounts'].get(target,{})
            state['accounts'][target] = {'uid':u.pw_uid,'enabled':p['enabled'],'status':old.get('status','pending') if old.get('uid') == u.pw_uid else 'pending'}
            if not p['enabled']:
                disable(target)
                state['accounts'][target]['status'] = 'disabled'
            else: state['accounts'][target]['status'] = 'pending'
            atomic(STATE,json.dumps(state))
        else:
            target = p.get('target','')
            state['shares'] = [s for s in state['shares'] if s['name'] != target]
            if action == 'share.save': state['shares'].append(normalize(p))
            if any(s['smb'] for s in state['shares']):
                require(shutil.which('smbpasswd') and 'include = /etc/samba/panasms-shares.conf' in text(Path('/etc/samba/smb.conf')), 'Samba server integration is not installed')
            if target and shutil.which('smbcontrol'):
                command(['smbcontrol','smbd','close-share',target],accepted=(0,1))
            apply(state)
    return {'message':'Shared folder settings updated'}


def disconnect(username):
    if not shutil.which('smbstatus'): return
    if command(['systemctl','is-active','smbd'],accepted=(0,3,4)).strip() != 'active': return
    sessions = json_command(['smbstatus','--json'],timeout=10).get('sessions',{})
    main = command(['systemctl','show','--property=MainPID','--value','smbd']).strip()
    for pid in {str(s.get('server_id',{}).get('pid','')) for s in sessions.values() if s.get('username') == username}:
        if pid.isdigit() and int(pid) > 1 and pid != main:
            command(['smbcontrol',pid,'shutdown'],accepted=(0,1))


def disable(user):
    if shutil.which('smbpasswd'):
        command(['smbpasswd','-d',user],accepted=(0,1))
        disconnect(user)


def reconcile():
    with locked():
        state = read()
        changed = False
        for username, record in state['accounts'].items():
            if not record.get('enabled'): continue
            try:
                u = pwd.getpwnam(username)
                policy = account_policy.entry(u)
                shadow = account_policy.shadow(username)
                available = u.pw_uid == record['uid'] and not policy.get('disabled') and shadow.get('passwordStatus') == 'set' and not account_policy.expired(shadow) and not account_policy.password_inactive(shadow)
            except KeyError: available = False
            status = 'disabled' if not available else ('pending' if record.get('passwordRevision') != password_revision(username) else record.get('status','pending'))
            if status != record.get('status'):
                disable(username)
                record['status'] = status
                changed = True
        if changed: atomic(STATE,json.dumps(state))


def remove_account(username):
    with locked():
        state = read()
        if username not in state['accounts']: return
        disable(username)
        command(['smbpasswd','-x',username],accepted=(0,1))
        del state['accounts'][username]
        atomic(STATE,json.dumps(state))


def password_revision(user):
    for line in Path('/etc/shadow').read_text().splitlines():
        fields = line.split(':')
        if fields[0] == user: return hashlib.sha256(fields[1].encode()).hexdigest()
    return ''


def sync_password(user,password):
    with locked():
        state = read(); record = state['accounts'].get(user,{})
        u = pwd.getpwnam(user)
        if not record.get('enabled') or record.get('uid') != u.pw_uid: return
        try:
            require(password and not any(c in password for c in '\x00\r\n'), 'Invalid password')
            policy = account_policy.entry(u); shadow = account_policy.shadow(user)
            require(not policy.get('disabled') and not account_policy.expired(shadow), 'Account is disabled')
            command(['smbpasswd','-s','-a',user],data=password+'\n'+password+'\n')
            command(['smbpasswd','-e',user])
            record['status'] = 'ready'
            record['passwordRevision'] = password_revision(user)
        except Exception:
            record['status'] = 'error'
            atomic(STATE,json.dumps(state))
            raise Rejected('Linux password accepted, but SMB password synchronization failed. See Users → Security and retry by signing in again.')
        atomic(STATE,json.dumps(state))


def account_status(username):
    record = read()['accounts'].get(username, {})
    user = pwd.getpwnam(username)
    if record.get('uid') != user.pw_uid:
        return {'enabled': False, 'status': 'disabled'}
    status = record.get('status', 'pending')
    if record.get('enabled') and status == 'ready' and record.get('passwordRevision') != password_revision(username):
        status = 'pending'
    return {'enabled': bool(record.get('enabled')), 'status': status}


def query():
    state = read()
    sessions = {}
    if shutil.which('smbstatus'):
        try: sessions = json_command(['smbstatus','--json'],timeout=10)
        except Exception: sessions = {'error':'SMB session information unavailable'}
    for username, record in state['accounts'].items():
        revision = record.pop('passwordRevision', None)
        if record.get('enabled') and record.get('status') == 'ready' and revision != password_revision(username): record['status'] = 'pending'
    return {**state,'drift':bool(drift(state)),'recovery':JOURNAL.exists(),'smbAvailable':bool(shutil.which('smbpasswd')),'sessions':sessions,
            'services':{s:command(['systemctl','is-active',s],accepted=(0,3,4)).strip() for s in ('smbd','nfs-kernel-server')}}




def folders(target):
    from host import export_path
    rows = json_command(['findmnt', '--json', '--list', '--output', 'TARGET,FSTYPE,SOURCE']).get('filesystems', [])
    roots = []
    for row in rows:
        if row.get('fstype') not in ('ext2', 'ext3', 'ext4', 'xfs', 'btrfs', 'vfat', 'exfat', 'ntfs', 'ntfs3') or row.get('target') == '/':
            continue
        path = row.get('target', '')
        try:
            export_path(path)
            roots.append(path)
        except Rejected:
            continue
    if not target:
        return {'roots': sorted(set(roots)), 'path': '', 'folders': []}
    path = export_path(target)
    require(any(str(path) == root or str(path).startswith(root.rstrip('/') + '/') for root in roots), 'Choose a folder on a mounted local volume')
    children = []
    with os.scandir(path) as entries:
        for entry in entries:
            if entry.is_dir(follow_symlinks=False) and not entry.name.startswith('.'):
                children.append({'name': entry.name, 'path': entry.path})
                if len(children) >= 1000:
                    break
    return {'roots': sorted(set(roots)), 'path': str(path), 'folders': sorted(children, key=lambda item: item['name'].casefold())}

if __name__ == '__main__':
    try:
        if len(sys.argv) == 3 and sys.argv[1] == '--check':
            s = next(s for s in read()['shares'] if s['name'] == sys.argv[2])
            require(volume(s['path']) == s['volume'], 'Shared volume unavailable')
        elif sys.argv[1:] == ['--sync']:
            body = json.load(sys.stdin); sync_password(body['user'],body['password'])
        elif sys.argv[1:] == ['--reconcile']:
            reconcile()
        elif sys.argv[1:] == ['--remove']:
            with locked():
                state = read()
                for username in state['accounts']: disable(username)
                for path in (SMB,EXPORTS):
                    if path.exists(): path.unlink()
                reload_services([])
        elif sys.argv[1:] == ['--recover'] and JOURNAL.exists():
            with locked(): recover()
        print(json.dumps({}))
    except Exception:
        message = 'SMB password synchronization failed; see Users → Security' if sys.argv[1:] == ['--sync'] else 'Sharing operation failed; check Samba/NFS service logs and the recovery status in Shared folders'
        print(json.dumps({'error':message}))
        sys.exit(1)
