import os
from pathlib import Path
from common import Rejected, command, fingerprint, name, require

ACTIONS = {'filesystem.snapshot-create', 'filesystem.snapshot-delete', 'filesystem.snapshot-restore'}
DIRECTORY = '.panasms-snapshots'


def context(target):
    import storage
    inv = storage.inventory()
    target = storage.device(target, inv)
    storage.protected(target, inv)
    require(inv[target].get('fstype') == 'btrfs', 'Snapshots require a Btrfs file system')
    points = [p for p in inv[target].get('mountpoints', []) if p]
    require(len(points) == 1, 'Mount the Btrfs volume at one location first')
    root = storage.mountpoint(points[0])
    require(not inv[target].get('ro'), 'The device is read-only')
    require(not os.statvfs(root).f_flag & os.ST_RDONLY, 'The destination is read-only. Check the file system before retrying.')
    command(['btrfs', 'subvolume', 'show', str(root)])
    directory = root / DIRECTORY
    require(not directory.is_symlink(), 'Links in the snapshot path are not allowed')
    if directory.exists():
        st = directory.stat()
        require(directory.is_dir() and st.st_uid == 0 and st.st_mode & 0o077 == 0,
                'The snapshot directory must be owned by root and private')
    return target, root, directory, inv[target].get('uuid')


def snapshot(directory, value):
    path = directory / name(value)
    require(path.is_dir() and not path.is_symlink(), 'Snapshot no longer exists')
    info = command(['btrfs', 'subvolume', 'show', str(path)])
    require(command(['btrfs', 'property', 'get', '-ts', str(path), 'ro']).strip() == 'ro=true',
            'Only read-only snapshots managed by PaNasMs can be used here')
    return path, info


def query(target):
    target, root, directory, uuid = context(target)
    rows = []
    if directory.exists():
        for path in sorted(directory.iterdir()):
            if not path.is_dir() or path.is_symlink():
                continue
            try:
                snapshot(directory, path.name)
            except Rejected:
                continue
            rows.append({'name': path.name})
    return {'target': target, 'point': str(root), 'snapshots': rows}


def plan(action, params, user=None):
    target, root, directory, uuid = context(params.get('target'))
    state = {'uuid': uuid, 'mountpoint': str(root)}
    if action == 'filesystem.snapshot-create':
        label = name(params.get('name'))
        require(not (directory / label).exists(), 'Name already in use')
        details = [target, label, 'The snapshot is read-only. Nested subvolumes are not included. A snapshot is not a backup against disk failure.']
    else:
        path, info = snapshot(directory, params.get('snapshot'))
        state['snapshot'] = info
        import storage
        require(not any(p == str(path) or p.startswith(str(path) + '/') for p in storage.mount_targets()),
                'Unmount the snapshot before deleting or restoring it')
        if action == 'filesystem.snapshot-delete':
            details = [str(path), 'This snapshot will be deleted. The current files will be preserved.']
        else:
            label = name(params.get('name'))
            destination = root / label
            require(not destination.exists() and not destination.is_symlink(), 'Name already in use')
            details = [str(path), str(destination), 'A writable copy will be restored in a new folder. Current files will not be replaced.']
    return {'target': target, 'details': details, 'confirmation': target,
            'fingerprint': fingerprint(action, params, state)}


def execute(action, params, user=None):
    from filesystem_health import device_lock
    with device_lock(os.path.realpath(params.get('target', ''))):
        return execute_locked(action, params, user)


def execute_locked(action, params, user=None):
    plan(action, params, user)
    target, root, directory, uuid = context(params['target'])
    if action == 'filesystem.snapshot-create':
        directory.mkdir(mode=0o700, exist_ok=True)
        command(['btrfs', 'subvolume', 'snapshot', '-r', str(root), str(directory / params['name'])], timeout=600)
    elif action == 'filesystem.snapshot-delete':
        path, _ = snapshot(directory, params['snapshot'])
        command(['btrfs', 'subvolume', 'delete', '--commit-after', str(path)], timeout=600)
    else:
        path, _ = snapshot(directory, params['snapshot'])
        command(['btrfs', 'subvolume', 'snapshot', str(path), str(root / params['name'])], timeout=600)
    return {'target': target, 'message': 'Operation complete.'}
