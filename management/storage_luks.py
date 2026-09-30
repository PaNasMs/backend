import json
import os
from pathlib import Path
import pwd
import re
import tempfile
import shutil
from common import atomic, command, fingerprint, integer, json_command, name, require

ACTIONS = {'luks.key-add', 'luks.key-remove', 'luks.auto-enable', 'luks.auto-disable', 'luks.header-backup', 'luks.header-restore'}
ROOT = Path('/etc/panasms/luks')
CRYPTTAB = Path('/etc/crypttab')


def context(target):
    import storage
    inv = storage.inventory()
    target = storage.device(target, inv)
    storage.protected(target, inv)
    require(inv[target].get('fstype') == 'crypto_LUKS', 'Select a LUKS container')
    uuid = command(['cryptsetup', 'luksUUID', target]).strip()
    require(re.fullmatch(r'[a-fA-F0-9-]{36}', uuid), 'Invalid LUKS UUID')
    metadata = json_command(['cryptsetup', 'luksDump', '--dump-json-metadata', target])
    slots = sorted(int(slot) for slot in metadata['keyslots'])
    record = ROOT / (uuid + '.json')
    config = json.loads(record.read_text()) if record.exists() else None
    return target, uuid, slots, config, inv


def password(params, key='passphrase'):
    value = params.get(key)
    require(isinstance(value, str) and 1 <= len(value) <= 4096 and '\x00' not in value, 'Enter the LUKS password')
    return value


def verify(target, secret, slot=None):
    args = ['cryptsetup', 'open', '--test-passphrase', '--key-file', '-']
    if slot is not None:
        args += ['--key-slot', str(slot)]
    command([*args, target], data=secret, timeout=300)


def config_lines():
    require(not CRYPTTAB.is_symlink(), 'The configuration is a symbolic link')
    return CRYPTTAB.read_text().splitlines() if CRYPTTAB.exists() else []


def crypttab(uuid, mapping=None):
    marker = '# PaNasMs ' + uuid
    rows = config_lines()
    kept = []
    skip = False
    for line in rows:
        if skip:
            skip = False
            continue
        if line == marker:
            skip = True
            continue
        kept.append(line)
    if mapping:
        require(all(not line.split() or line.lstrip().startswith('#') or
                    (line.split()[0] != mapping and ('UUID=' + uuid) not in line.split()) for line in kept),
                'This LUKS volume or mapping already has an unmanaged crypttab entry')
        kept += [marker, f'{mapping} UUID={uuid} {ROOT / (uuid + ".key")} luks,nofail,headless,x-systemd.device-timeout=30s']
    return '\n'.join(kept) + '\n'


def query(target):
    target, uuid, slots, config, inv = context(target)
    return {'target': target, 'uuid': uuid, 'slots': slots,
            'automatic': bool(config and ('# PaNasMs ' + uuid) in config_lines()),
            'managedSlot': config['slot'] if config else None}


def header_path(params, uuid):
    from common import clean_path
    folder = clean_path(params.get('folder'))
    require(folder.is_dir() and not any(p.is_symlink() for p in [folder, *folder.parents]),
            'Select an existing folder without symbolic links')
    return folder / (uuid + '.luks-header')


def plan(action, params, user=None):
    target, uuid, slots, config, inv = context(params.get('target'))
    details = [target, 'LUKS2: ' + uuid]
    state = {'uuid': uuid, 'slots': slots, 'automatic': config, 'crypttab': config_lines()}
    if action in ('luks.key-add', 'luks.key-remove', 'luks.auto-enable', 'luks.auto-disable'):
        password(params)
    if action == 'luks.key-add':
        password(params, 'password')
        require(len(slots) < 32, 'No free LUKS key slot')
        details += ['A new password will be added. Existing passwords remain valid.']
    elif action == 'luks.key-remove':
        slot = integer(params.get('slot'), 0, 31)
        require(slot in slots and len(slots) > 1, 'The last LUKS key cannot be removed')
        require(not config or slot != config['slot'], 'Disable automatic unlocking before removing its key')
        details += [f'Key slot: {slot}', 'The selected key will be revoked. Old header backups can restore revoked keys.']
    elif action == 'luks.auto-enable':
        require(Path('/usr/lib/systemd/systemd-cryptsetup').is_file(), 'Install systemd-cryptsetup before enabling automatic unlocking')
        mapping = name(params.get('name'))
        require(not config or config['name'] == mapping, 'Use the existing automatic-unlock name')
        mapped = os.path.realpath('/dev/mapper/' + mapping)
        require(not Path('/dev/mapper/' + mapping).exists() or inv.get(mapped, {}).get('parent') == target, 'Name already in use')
        require(config or len(slots) < 32, 'No free LUKS key slot')
        crypttab(uuid, mapping)
        details += ['A root-only key will be stored on the system disk. This does not protect against theft of the whole NAS.',
                    'Automatic unlocking takes effect at the next startup. Keep a separate working password and header backup.']
    elif action == 'luks.auto-disable':
        require(config, 'Automatic unlocking is not configured')
        require(any(slot != config['slot'] for slot in slots), 'Keep another working LUKS key first')
        details += ['Automatic unlocking will be disabled and its stored key revoked. The current mapping stays open.']
    elif action == 'luks.header-backup':
        path = header_path(params, uuid)
        require(not path.exists() and not path.is_symlink(), 'A header backup already exists in this folder')
        details += [str(path), 'Store this backup separately. It can restore revoked keys and does not contain your files.']
    elif action == 'luks.header-restore':
        import storage
        storage.unused(target, inv)
        require(not config, 'Disable automatic unlocking before restoring a header')
        path = header_path(params, uuid)
        require(path.is_file() and not path.is_symlink(), 'LUKS header backup not found')
        require(command(['cryptsetup', 'luksUUID', str(path)]).strip() == uuid, 'The backup belongs to another LUKS volume')
        st = path.stat()
        state['backup'] = [str(path), st.st_ino, st.st_size, st.st_mtime_ns]
        details += [str(path), 'Restoring the header replaces current keys with keys from the backup. Files are not restored.']
    return {'target': target, 'details': details, 'confirmation': target,
            'fingerprint': fingerprint(action, params, state)}


def authorize_other_slot(target, secret, slots, excluded):
    from common import Rejected
    for slot in slots:
        if slot == excluded:
            continue
        try:
            verify(target, secret, slot)
            return
        except Rejected:
            pass
    require(False, 'Enter a password that unlocks a different key slot')


def execute(action, params, user=None):
    from filesystem_health import device_lock
    with device_lock(os.path.realpath(params.get('target', ''))):
        return execute_locked(action, params, user)


def execute_locked(action, params, user=None):
    plan(action, params, user)
    target, uuid, slots, config, inv = context(params['target'])
    if action in ('luks.key-add', 'luks.key-remove', 'luks.auto-enable', 'luks.auto-disable'):
        verify(target, password(params))
    if action == 'luks.key-add':
        with tempfile.TemporaryDirectory(prefix='panasms-luks-', dir='/run') as tmp:
            new = Path(tmp) / 'new'
            new.write_text(password(params, 'password'))
            new.chmod(0o600)
            command(['cryptsetup', 'luksAddKey', '--key-file', '-', target, str(new)], data=params['passphrase'], timeout=300)
        verify(target, params['password'])
    elif action == 'luks.key-remove':
        authorize_other_slot(target, params['passphrase'], slots, params['slot'])
        command(['cryptsetup', 'luksKillSlot', '--batch-mode', '--key-file', '-', target, str(params['slot'])], data=params['passphrase'], timeout=300)
    elif action == 'luks.auto-enable':
        require(not any(p.is_symlink() for p in [ROOT, *ROOT.parents]), 'The configuration is a symbolic link')
        ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
        ROOT.chmod(0o700)
        record = ROOT / (uuid + '.json')
        key = ROOT / (uuid + '.key')
        if config is None:
            config = {'uuid': uuid, 'name': params['name'], 'slot': max(set(range(32)) - set(slots))}
            atomic(record, json.dumps(config))
        require(not key.is_symlink(), 'The configuration is a symbolic link')
        if not key.exists():
            fd = os.open(key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'w') as f:
                f.write(os.urandom(64).hex())
                f.flush()
                os.fsync(f.fileno())
        if config['slot'] not in slots:
            command(['cryptsetup', 'luksAddKey', '--key-slot', str(config['slot']), '--key-file', '-', target, str(key)], data=params['passphrase'], timeout=300)
        command(['cryptsetup', 'open', '--test-passphrase', '--key-slot', str(config['slot']), '--key-file', str(key), target], timeout=300)
        atomic(CRYPTTAB, crypttab(uuid, config['name']))
        command(['systemctl', 'daemon-reload'])
    elif action == 'luks.auto-disable':
        authorize_other_slot(target, params['passphrase'], slots, config['slot'])
        atomic(CRYPTTAB, crypttab(uuid))
        command(['systemctl', 'daemon-reload'])
        if config['slot'] in slots:
            command(['cryptsetup', 'luksKillSlot', '--batch-mode', '--key-file', '-', target, str(config['slot'])], data=params['passphrase'], timeout=300)
        (ROOT / (uuid + '.key')).unlink(missing_ok=True)
        (ROOT / (uuid + '.json')).unlink()
    elif action == 'luks.header-backup':
        path = header_path(params, uuid)
        with tempfile.TemporaryDirectory(prefix='panasms-luks-', dir='/run') as tmp:
            header = Path(tmp) / 'header'
            command(['cryptsetup', 'luksHeaderBackup', '--header-backup-file', str(header), target])
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'wb') as output, header.open('rb') as source:
                shutil.copyfileobj(source, output)
                output.flush()
                os.fsync(output.fileno())
                if user:
                    account = pwd.getpwnam(user)
                    os.fchown(output.fileno(), account.pw_uid, account.pw_gid)
    else:
        with tempfile.TemporaryDirectory(prefix='panasms-luks-', dir='/run') as tmp:
            header = Path(tmp) / 'header'
            source = header_path(params, uuid)
            require(source.stat().st_size <= 128 * 1024 * 1024, 'LUKS header backup is too large')
            shutil.copyfile(source, header)
            require(command(['cryptsetup', 'luksUUID', str(header)]).strip() == uuid, 'The backup belongs to another LUKS volume')
            command(['cryptsetup', 'luksHeaderRestore', '--batch-mode', '--header-backup-file', str(header), target], timeout=300)
    return {'target': target, 'message': 'Operation complete.'}
