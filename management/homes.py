import job_control
import pwd
from common import *

JOURNAL = Path('/var/lib/panasms-agent/home-move.json')
DEFAULTS = Path('/etc/default/useradd')
NOLOGIN = Path('/run/nologin')
PROC = Path('/proc')


def base():
    for line in DEFAULTS.read_text().splitlines():
        if line.startswith('HOME='):
            return str(clean_path(line.split('=', 1)[1].strip().strip('"\'')))
    return '/home'


def affected(source):
    return [u for u in pwd.getpwall() if u.pw_dir.startswith(source + '/')]


def query():
    source = base()
    return {'path': source, 'users': [{'name': u.pw_name, 'home': u.pw_dir} for u in affected(source)],
            'recovery': JOURNAL.exists()}


def no_links(path):
    require(not any(p.is_symlink() for p in [path, *path.parents]), 'Links in the home folder path are not allowed')


class HomeBusy(Rejected):
    def __init__(self, blockers):
        self.blockers = blockers
        super().__init__('Home folders are in use. Close these sessions or applications: ' + '; '.join(
            b['user'] + ': ' + b['title'] for b in blockers))


def process_app(process, label, descriptions):
    groups = process.joinpath('cgroup').read_text().splitlines()
    units = [part for line in groups for part in line.split(':', 2)[-1].split('/') if part.endswith('.service')]
    unit = units[-1] if units else ''
    if unit.startswith('panasms-cloud-sync-user-') or unit == 'panasms-module-cloud-sync.service':
        return 'Cloud Sync', 'cloudSync', unit
    if unit == 'panasms-module-terminal.service':
        return 'Terminal', 'terminal', unit
    if unit == 'panasms-module-files.service':
        return 'Files', 'files', unit
    if label.startswith('sshd'):
        return 'SSH session', 'ssh', unit
    if label in ('systemd', '(sd-pam)') and unit.startswith('user@'):
        return 'User session', 'session', unit
    if unit:
        if unit not in descriptions:
            descriptions[unit] = command(['systemctl', 'show', unit, '--property=Description', '--value'], accepted=(0, 1)).strip()
        return descriptions[unit] or unit, 'service', unit
    return label, 'application', ''


def blockers(source, users):
    ids = {u.pw_uid: u.pw_name for u in users}
    busy = {}
    descriptions = {}
    for process in PROC.iterdir():
        if not process.name.isdigit() or int(process.name) == os.getpid():
            continue
        try:
            owner = process.stat().st_uid
            label = process.joinpath('comm').read_text().strip()
            used = owner in ids
            if not used:
                for link in [process / 'cwd', process / 'root', *process.joinpath('fd').iterdir()]:
                    try:
                        value = os.readlink(link)
                        if value == source or value.startswith(source + '/'):
                            used = True
                            break
                    except (FileNotFoundError, PermissionError):
                        pass
            if used:
                title, kind, unit = process_app(process, label, descriptions)
                try:
                    username = ids.get(owner) or pwd.getpwuid(owner).pw_name
                except KeyError:
                    username = str(owner)
                key = (owner, title, unit)
                entry = busy.setdefault(key, {'title': title, 'kind': kind, 'unit': unit, 'user': username,
                                             'reason': 'session' if owner in ids else 'openFiles', 'processes': []})
                entry['processes'].append({'name': label, 'pid': int(process.name)})
        except (FileNotFoundError, ProcessLookupError):
            continue
    return list(busy.values())


def idle(source, users):
    busy = blockers(source, users)
    if busy:
        raise HomeBusy(busy)


def preflight(destination):
    try:
        return plan({'destination': destination})
    except HomeBusy as error:
        return {'blockers': error.blockers}


def inspect(destination):
    require(not JOURNAL.exists(), 'An interrupted home move must be recovered first')
    source = clean_path(base())
    target = clean_path(destination)
    require(source != target and source not in target.parents and target not in source.parents, 'Home folder locations must not overlap')
    require(str(source) == '/home' or str(source).startswith(('/home/', '/srv/', '/mnt/')), 'Unsupported current home location')
    require(str(target) == '/home' or (str(target).startswith(('/home/', '/srv/', '/mnt/')) and len(target.parts) >= 3), 'Choose a new folder under /home, /srv or /mnt')
    no_links(source)
    no_links(target)
    require(source.is_dir() and target.parent.is_dir() and not target.exists(), 'The source and destination parent must exist; the destination must be a new folder')
    mounts = json_command(['findmnt', '--json', '--list', '--output', 'TARGET'])['filesystems']
    require(not any(m['target'] == str(source) or m['target'].startswith(str(source) + '/') for m in mounts), 'The home folder contains mounts; unmount them before moving')
    fs = json_command(['findmnt', '--json', '--target', str(target.parent), '--output', 'TARGET,FSTYPE,OPTIONS'])['filesystems'][0]
    require(fs['fstype'] in ('ext2', 'ext3', 'ext4', 'xfs', 'btrfs') and 'rw' in fs['options'].split(','), 'Choose a writable local Linux filesystem for home folders')
    if str(target).startswith(('/srv/', '/mnt/')):
        require(fs['target'] != '/', 'The home volume is unavailable or the path is a volume root')
        persistent = json_command(['findmnt', '--fstab', '--json', '--output', 'TARGET,OPTIONS'])['filesystems']
        require(any(m['target'] == fs['target'] and 'noauto' not in (m.get('options') or '').split(',') for m in persistent), 'Configure automatic mounting for the destination volume first')
    users = affected(str(source))
    require(all(u.pw_uid > 0 for u in users), 'Root home cannot be moved')
    require(all(not (u.pw_dir == str(target) or u.pw_dir.startswith(str(target) + '/') or str(target).startswith(u.pw_dir.rstrip('/') + '/')) for u in pwd.getpwall() if u not in users and u.pw_dir not in ('/', '/nonexistent')), "The path overlaps another user's home folder")
    for user in users:
        require(Path(user.pw_dir).is_dir(), 'Home folder unavailable: ' + user.pw_name)
        no_links(Path(user.pw_dir))
    idle(str(source), users)
    require(shutil.which('rsync'), 'Install rsync before moving home folders')
    return source, target, users


def plan(p):
    source, target, users = inspect(p.get('destination'))
    return {'target': str(target), 'confirmation': str(target),
            'details': [str(source) + ' → ' + str(target)] + [u.pw_name + ': ' + u.pw_dir + ' → ' + str(target) + u.pw_dir[len(str(source)):] for u in users],
            'fingerprint': fingerprint('homes.move', p, [str(source), Path('/etc/passwd').read_text(), source.stat().st_ino, target.parent.stat().st_dev])}


def journal(state):
    atomic(JOURNAL, json.dumps(state))


def mounted(path):
    return any(m['target'] == str(path) for m in json_command(['findmnt', '--json', '--list', '--output', 'TARGET'])['filesystems'])


def identity(path):
    value = path.stat()
    return [value.st_dev, value.st_ino]


def recover():
    if not JOURNAL.exists():
        return {'message': 'No interrupted home move'}
    state = json.loads(JOURNAL.read_text())
    source, target = Path(state['source']), Path(state['target'])
    if state.get('nologin') and not NOLOGIN.exists():
        atomic(NOLOGIN, state['nologin'], mode=0o644)
    if state['phase'] != 'committed':
        require(source.is_dir() and ('sourceIdentity' not in state or identity(source) == state['sourceIdentity']), 'Home volume changed or is unavailable; data was preserved')
        for user in state['users']:
            current = pwd.getpwnam(user['name']).pw_dir
            if current != user['old']:
                command(['usermod', '--home', user['old'], '--', user['name']])
        command(['useradd', '--defaults', '--base-dir', str(source)])
        if mounted(source):
            command(['umount', '--', str(source)])
    else:
        require(target.is_dir() and ('targetIdentity' not in state or identity(target) == state['targetIdentity']), 'Home volume changed or is unavailable; data was preserved')
        if mounted(source):
            command(['umount', '--', str(source)])
        backup = Path(state['backup']) / 'previous'
        if source.exists() and not backup.exists():
            require('sourceIdentity' not in state or identity(source) == state['sourceIdentity'], 'Home volume changed or is unavailable; data was preserved')
            source.rename(backup)
        if backup.exists():
            shutil.rmtree(backup)
    holder = Path(state['backup'])
    if holder.exists() and not any(holder.iterdir()):
        holder.rmdir()
    if state.get('nologin') and NOLOGIN.exists() and NOLOGIN.read_text() == state['nologin']:
        NOLOGIN.unlink()
    JOURNAL.unlink()
    return {'message': 'Home move recovered. Any destination copy was retained.'}


def execute(p):
    source, target, users = inspect(p.get('destination'))
    size = int(command(['du', '-sx', '--block-size=1', '--', str(source)], timeout=86400).split()[0])
    require(shutil.disk_usage(target.parent).free > size + 64 * 1024 * 1024, 'Not enough free space to copy home folders')
    require(not NOLOGIN.exists(), 'System maintenance is already in progress')
    state = {'source': str(source), 'target': str(target), 'phase': 'copying', 'sourceIdentity': identity(source),
             'users': [{'name': u.pw_name, 'old': u.pw_dir, 'new': str(target) + u.pw_dir[len(str(source)):]} for u in users],
             'backup': tempfile.mkdtemp(prefix='.panasms-home-', dir=source.parent),
             'nologin': 'PaNasMs is moving home folders. Please try again shortly.\n'}
    journal(state)
    try:
        with NOLOGIN.open('x') as f:
            f.write(state['nologin'])
        idle(str(source), users)
        command(['mount', '--bind', str(source), str(source)])
        command(['mount', '-o', 'remount,bind,ro', str(source)])
        idle(str(source), users)
        target.mkdir(mode=0o700)
        args = ['rsync', '-aHAXS', '--numeric-ids']
        job_control.copying([*args, str(source) + '/', str(target) + '/'])
        changes = job_control.copying([*args, '--dry-run', '--checksum', '--itemize-changes', '--delete', str(source) + '/', str(target) + '/'])
        require(not changes.strip(), 'Home copy verification failed; original data was preserved')
        command(['sync', '-f', str(target)])
        idle(str(source), users)
        job_control.capability(False)
        job_control.checkpoint()
        state['phase'] = 'switching'
        journal(state)
        for user in state['users']:
            command(['usermod', '--home', user['new'], '--', user['name']])
        command(['useradd', '--defaults', '--base-dir', str(target)])
        state['targetIdentity'] = identity(target)
        state['phase'] = 'committed'
        journal(state)
        recover()
    except Exception:
        try:
            recover()
        except Exception:
            raise Rejected('Home move interrupted. Recovery is required; original data was preserved.')
        raise
    return {'message': 'Home folders moved and user paths updated'}


if __name__ == '__main__':
    require(sys.argv[1:] == ['--recover'], 'Invalid recovery arguments')
    recover()
