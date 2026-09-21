from common import *

LINUX_FILESYSTEMS = ('ext2', 'ext3', 'ext4', 'xfs', 'btrfs')


def within(path, root):
    return path == root or path.startswith(root.rstrip('/') + '/')


def inventory():
    mounts = json_command(['findmnt', '--json', '--list', '--output', 'TARGET,FSTYPE,OPTIONS,MAJ:MIN']).get('filesystems', [])
    persistent = json_command(['findmnt', '--fstab', '--json', '--output', 'TARGET,OPTIONS']).get('filesystems', [])
    devices = json_command(['lsblk', '--json', '--output', 'NAME,MAJ:MIN,TYPE,RM,TRAN']).get('blockdevices', [])
    removable, local = set(), set()

    def visit(rows, unsafe=False):
        for row in rows:
            blocked = unsafe or row.get('rm') in (True, 1, '1') or row.get('tran') == 'usb' or row.get('type') == 'loop'
            number = row.get('maj:min')
            if number:
                local.add(number)
                if blocked:
                    removable.add(number)
            visit(row.get('children', []), blocked)

    visit(devices)
    return mounts, persistent, local, removable


def home_volume(path, state=None):
    mounts, persistent, local, removable = state if state is not None else inventory()
    matches = [row for row in mounts if within(str(path), row['target'])]
    require(matches, 'The destination volume is unavailable')
    fs = max(matches, key=lambda row: len(row['target']))
    require(fs['fstype'] in LINUX_FILESYSTEMS and 'rw' in fs['options'].split(','), 'Choose a writable local Linux filesystem for home folders')
    require(fs.get('maj:min') in local, 'The destination volume is unavailable')
    require(fs['maj:min'] not in removable, 'Home folders cannot be stored on USB or removable devices')
    require(fs['target'] == '/' or any(row['target'] == fs['target'] and 'noauto' not in (row.get('options') or '').split(',') for row in persistent), 'Configure automatic mounting for the destination volume first')
    if str(path).startswith(('/srv/', '/mnt/')):
        require(fs['target'] != '/', 'The home volume is unavailable or the path is a volume root')
    return fs


def destination(path):
    require(path.parent.is_dir(), 'The destination parent folder does not exist')
    return home_volume(path.parent)


def folders(target):
    state = inventory()
    candidates = {'/home'} | {row['target'] for row in state[0] if row['target'].startswith(('/home/', '/srv/', '/mnt/'))}
    roots = []
    for value in sorted(candidates):
        path = Path(value)
        if not path.is_dir() or any(p.is_symlink() for p in [path, *path.parents]):
            continue
        reason = ''
        try:
            home_volume(path, state)
        except Rejected as error:
            reason = str(error)
        roots.append({'name': value, 'path': value, 'reason': reason})
    if not target:
        return {'roots': roots, 'path': '', 'folders': []}
    path = clean_path(target)
    require(any(within(str(path), row['path']) and not row['reason'] for row in roots), 'Choose a folder on a supported home volume')
    require(path.is_dir() and not any(p.is_symlink() for p in [path, *path.parents]), 'Choose an existing folder without symbolic links')
    home_volume(path, state)
    children = []
    with os.scandir(path) as entries:
        for entry in entries:
            if not entry.is_dir(follow_symlinks=False) or entry.name.startswith('.') or entry.name == 'lost+found':
                continue
            reason = ''
            try:
                home_volume(Path(entry.path), state)
            except Rejected as error:
                reason = str(error)
            children.append({'name': entry.name, 'path': entry.path, 'reason': reason})
            if len(children) >= 1000:
                break
    return {'roots': roots, 'path': str(path), 'folders': sorted(children, key=lambda row: row['name'].casefold())}


def mount_folders(target):
    roots = [value for value in ('/srv', '/mnt') if Path(value).is_dir() and not Path(value).is_symlink()]
    if not target:
        return {'roots': roots, 'path': '', 'folders': []}
    path = clean_path(target)
    require(any(within(str(path), root) for root in roots), 'Choose a mount location under /srv or /mnt')
    require(path.is_dir() and not any(p.is_symlink() for p in [path, *path.parents]), 'Choose an existing folder without symbolic links')
    children = []
    with os.scandir(path) as entries:
        for entry in entries:
            if entry.is_dir(follow_symlinks=False) and not entry.name.startswith('.') and entry.name != 'lost+found':
                children.append({'name': entry.name, 'path': entry.path})
                if len(children) >= 1000:
                    break
    return {'roots': roots, 'path': str(path), 'folders': sorted(children, key=lambda row: row['name'].casefold())}
