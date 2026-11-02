import argparse
import base64
import fcntl
import tarfile
from contextlib import contextmanager, ExitStack
import hashlib
import json
import os
from pathlib import Path
import stat
import shutil
import subprocess
import sys
import tempfile
import uuid

from common import Rejected, require

SCHEMA = 1
OWNER = 0
MARKER = Path('/var/lib/panasms-installer/sharing-compat-v1.json')
INSTALL_MODE = Path('/var/lib/panasms-installer/sharing-package-install')
JOURNALS = (Path('/var/lib/panasms-agent/sharing-transaction.json'),
            Path('/var/lib/panasms-agent/sharing-legacy-nfs-transaction.json'))
ATTESTED = tuple(Path(p) for p in (
    '/usr/lib/panasms/management/sharing_compat.py',
    '/usr/lib/panasms/management/system_updates.py',
    '/usr/lib/panasms/management/sharing.py',
    '/usr/lib/panasms/management/host.py',
    '/usr/lib/systemd/system/panasms-agent.service',
    '/usr/lib/systemd/system/panasms-sharing.service',
    '/usr/lib/systemd/system/smbd.service.d/panasms-sharing-restore.conf',
    '/usr/lib/systemd/system/nfs-server.service.d/panasms-sharing-restore.conf',
    '/var/lib/dpkg/info/panasms-prototype.preinst',
    '/var/lib/dpkg/info/panasms-prototype.postinst',
    '/var/lib/dpkg/info/panasms-prototype.prerm'))


def safe_parents(path):
    for parent in path.parents:
        require(not parent.is_symlink(), 'Refusing sharing compatibility state through a symbolic link')


def read_file(path):
    safe_parents(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == OWNER
                and info.st_mode & 0o022 == 0, 'Untrusted sharing compatibility file: ' + str(path))
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            return stream.read(), info
    finally:
        os.close(fd)


def secure_read(path):
    return read_file(path)[0]


def atomic(path, data, mode=0o600, gid=None):
    safe_parents(path)
    require(not path.is_symlink(), 'Refusing sharing compatibility symbolic link')
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as stream:
        temporary = Path(stream.name)
        try:
            os.fchmod(stream.fileno(), mode)
            if gid is not None:
                os.fchown(stream.fileno(), OWNER, gid)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
            temporary.replace(path)
            fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        finally:
            temporary.unlink(missing_ok=True)


def check_install():
    for path in JOURNALS:
        safe_parents(path)
        require(not path.exists() and not path.is_symlink(),
                'Recover the pending sharing transaction with the installed version before package changes')


def package_version(configuring=False):
    result = subprocess.run(['dpkg-query', '-W', '-f=${db:Status-Status} ${Version}',
                             'panasms-prototype'], check=True, capture_output=True, text=True)
    state, version = result.stdout.split()
    allowed = {'installed'}
    if configuring:
        allowed.update(('unpacked', 'half-configured'))
    elif os.environ.get('PANASMS_MAINTENANCE') == '1':
        allowed.update(('half-installed', 'half-configured'))
    require(state in allowed, 'The sharing compatibility preparation package is not configured')
    return version


def attest():
    return {str(path): hashlib.sha256(secure_read(path)).hexdigest() for path in ATTESTED}


def configure():
    check_install()
    value = {'schema': SCHEMA, 'packageVersion': package_version(configuring=True), 'files': attest(), 'native': True}
    atomic(MARKER, json.dumps(value, sort_keys=True).encode())
    if INSTALL_MODE.exists() or INSTALL_MODE.is_symlink():
        require(secure_read(INSTALL_MODE) == b'install\n', 'Invalid sharing install marker')
        unlink_sync(INSTALL_MODE)


def target_capabilities():
    version = package_version(configuring=True)
    attest()
    return {'schema': SCHEMA, 'packageVersion': version, 'pairedRestore': 1}


def capabilities():
    value = json.loads(secure_read(MARKER))
    require(value.get('schema') == SCHEMA and value.get('packageVersion') == package_version()
            and value.get('files') == attest(), 'Sharing compatibility preparation is not verified')
    return {'schema': SCHEMA, 'packageVersion': value['packageVersion'], 'pairedRestore': 1}


FILES = tuple(Path(p) for p in ('/etc/panasms/sharing.json', '/etc/samba/panasms-shares.conf',
                               '/etc/exports.d/panasms-shares.exports', '/etc/exports.d/panasms.exports'))
LOCKS = (Path('/var/lib/panasms-agent/sharing.lock'), Path('/run/panasms-agent/sharing.lock'))
GUARD = Path('/var/lib/panasms-agent/sharing-restore.json')
HELPER = '/usr/lib/panasms/panasms-system-helper'
ACTIVATION = Path('/var/lib/panasms-installer/sharing-activation-v1.json')
NATIVE = Path('/var/lib/panasms-installer/sharing-native-v1.json')
PACKAGE_STATE = Path('/var/lib/panasms-installer/sharing-package-state.json')
UPDATE_ROOT = Path('/var/lib/panasms-updates')
MAINTENANCE_LOCK = Path('/run/lock/panasms-maintenance.lock')


def valid_source(value):
    if not isinstance(value, dict):
        return False
    if value == {'fresh': True}:
        return True
    return (set(value) <= {'schema', 'packageVersion', 'pairedRestore', 'native', 'reinstall'}
            and value.get('schema') == 1 and value.get('pairedRestore') == 1
            and isinstance(value.get('packageVersion'), str) and bool(value['packageVersion'])
            and type(value.get('native', False)) is bool and type(value.get('reinstall', False)) is bool)


def valid_receipt(value):
    return (isinstance(value, dict) and set(value) == {'schema', 'packageVersion', 'nonce', 'source'}
            and value['schema'] == 1 and isinstance(value['packageVersion'], str)
            and isinstance(value['nonce'], str) and len(value['nonce']) == 32
            and all(c in '0123456789abcdef' for c in value['nonce']) and valid_source(value['source']))


def require_maintenance_ancestor():
    require(os.environ.get('PANASMS_MAINTENANCE') == '1', 'Native preparation requires exclusive maintenance')
    _, info = read_file(MAINTENANCE_LOCK)
    ancestors = set()
    process = os.getppid()
    while process > 1 and process not in ancestors:
        ancestors.add(process)
        process = int(Path('/proc', str(process), 'stat').read_text().rsplit(')', 1)[1].split()[1])
    for row in Path('/proc/locks').read_text().splitlines():
        fields = row.split()
        if len(fields) < 6 or fields[1:4] != ['FLOCK', 'ADVISORY', 'WRITE']:
            continue
        major, minor, inode = fields[5].split(':')
        if (int(fields[4]) in ancestors and int(major, 16) == os.major(info.st_dev)
                and int(minor, 16) == os.minor(info.st_dev) and int(inode) == info.st_ino):
            return
    raise Rejected('Native preparation requires exclusive maintenance')


def trusted_marker_parents():
    for parent in MARKER.parents:
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == OWNER and info.st_mode & 0o022 == 0,
                'Untrusted sharing compatibility directory')


def prepare_reinstall(target_version, old_version):
    require_maintenance_ancestor()
    require(subprocess.run(['dpkg', '--validate-version', target_version], capture_output=True).returncode == 0,
            'Invalid native target package version')
    status = subprocess.check_output(['dpkg-query', '-W', '-f=${db:Status-Status} ${Version} ${Config-Version}',
                                      'panasms-prototype'], text=True).split()
    require(status == ['half-installed', old_version, old_version] and bool(old_version),
            'Install the compatibility update in System updates before continuing.')
    trusted_marker_parents()
    raw, info = read_file(MARKER)
    marker = json.loads(raw)
    require(stat.S_IMODE(info.st_mode) == 0o600 and set(marker) <= {'schema', 'packageVersion', 'files', 'native'}
            and marker.get('schema') == 1 and marker.get('packageVersion') == old_version
            and type(marker.get('native', False)) is bool and isinstance(marker.get('files'), dict)
            and set(marker['files']) == {str(path) for path in ATTESTED}
            and all(isinstance(value, str) and len(value) == 64 and all(c in '0123456789abcdef' for c in value)
                    for value in marker['files'].values()), 'Sharing compatibility preparation is not verified')
    with locked():
        require(secure_read(MARKER) == raw, 'Sharing compatibility preparation changed')
        resume_check()
        state_path = UPDATE_ROOT / 'state.json'
        if state_path.exists() or state_path.is_symlink():
            state = json.loads(secure_read(state_path))
            require(isinstance(state, dict) and state.get('phase', '') in ('', 'checked', 'downloaded', 'complete', 'failed', 'rolled-back'),
                    'Complete the system update before reinstalling sharing')
        files = capture()
        require(files[str(FILES[0])]['exists'], 'Sharing setup is incomplete. Finish the system update before continuing.')
        activation = capture_activation()
        require(not activation[str(ACTIVATION)]['exists'], 'Native source activation is incomplete')
        receipt = None
        if activation[str(NATIVE)]['exists']:
            require(activation[str(NATIVE)]['mode'] == 0o600, 'Invalid native sharing receipt')
            receipt = json.loads(base64.b64decode(activation[str(NATIVE)]['data']))
            require(valid_receipt(receipt), 'Invalid native sharing receipt')
        native = bool(marker.get('native'))
        require(bool(receipt and receipt['packageVersion'] == old_version) == native,
                'Native sharing requires recovery before another package transition')
        source = {'schema': 1, 'packageVersion': old_version, 'pairedRestore': 1, 'native': native, 'reinstall': True}
        ticket = {'schema': 1, 'targetVersion': target_version, 'nonce': uuid.uuid4().hex,
                  'source': source, 'files': files, 'sourceActivation': activation}
        require(capture() == files and capture_activation() == activation,
                'Sharing changed during native transition preparation')
        atomic(ACTIVATION, json.dumps(ticket, sort_keys=True).encode())
    return ticket


@contextmanager
def locked():
    with ExitStack() as stack:
        for path in LOCKS:
            safe_parents(path)
            path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            stream = stack.enter_context(os.fdopen(fd, 'r+'))
            info = os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == OWNER and info.st_nlink == 1,
                    'Untrusted sharing lock')
            fcntl.flock(stream, fcntl.LOCK_EX)
        yield


def resume_check():
    safe_parents(GUARD)
    require(not GUARD.exists() and not GUARD.is_symlink(),
            'Sharing rollback is incomplete; recover the system update before resuming services')


def entry(path):
    try:
        data, info = read_file(path)
    except FileNotFoundError:
        require(not path.is_symlink(), 'Refusing dangling sharing symbolic link')
        return {'exists': False}
    return {'exists': True, 'data': base64.b64encode(data).decode(),
            'mode': stat.S_IMODE(info.st_mode), 'uid': info.st_uid, 'gid': info.st_gid}


def capture():
    check_install()
    return {str(path): entry(path) for path in FILES}


def capture_activation():
    return {str(path): entry(path) for path in (NATIVE, ACTIVATION)}


def validate_entries(entries, paths=None):
    paths = FILES if paths is None else paths
    require(isinstance(entries, dict) and set(entries) == {str(path) for path in paths},
            'Invalid paired sharing snapshot paths')
    for value in entries.values():
        require(isinstance(value, dict) and type(value.get('exists')) is bool, 'Invalid sharing snapshot')
        if not value['exists']:
            require(value == {'exists': False}, 'Invalid absent sharing snapshot')
            continue
        require(set(value) == {'exists', 'data', 'mode', 'uid', 'gid'} and value['uid'] == OWNER
                and type(value['gid']) is int and value['gid'] >= 0
                and type(value['mode']) is int and 0 <= value['mode'] <= 0o777
                and value['mode'] & 0o022 == 0, 'Invalid sharing snapshot ownership or mode')
        base64.b64decode(value['data'], validate=True)


def digest(path):
    safe_parents(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == OWNER and info.st_nlink == 1
                and info.st_mode & 0o022 == 0, 'Untrusted rollback archive')
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def save_pair(folder, before, activation_before):
    validate_entries(activation_before, (NATIVE, ACTIVATION))
    require(capture_activation() == activation_before, 'Sharing activation changed while the rollback archive was created')
    require(capture() == before, 'Sharing changed while the rollback archive was created')
    archive = folder / 'data.tar'
    with tarfile.open(archive, 'r:') as data:
        members = [member for member in data.getmembers()
                   if member.name.removeprefix('./') == str(FILES[0]).lstrip('/')]
        state = before[str(FILES[0])]
        require(len(members) == int(state['exists']), 'Sharing JSON does not match the rollback archive')
        if members:
            require(members[0].isfile(), 'Archived sharing JSON is not a regular file')
            require(data.extractfile(members[0]).read() == base64.b64decode(state['data']),
                    'Sharing JSON changed while the rollback archive was created')
    path = folder / 'sharing-pair.json'
    atomic(path, json.dumps({'schema': SCHEMA, 'archiveHash': digest(archive), 'files': before,
                             'activation': activation_before},
                           sort_keys=True).encode())
    return hashlib.sha256(secure_read(path)).hexdigest()


def load_snapshot(folder, expected_hash):
    raw = secure_read(folder / 'sharing-pair.json')
    require(hashlib.sha256(raw).hexdigest() == expected_hash, 'Sharing rollback snapshot changed')
    value = json.loads(raw)
    require(value.get('schema') == SCHEMA and value.get('archiveHash') == digest(folder / 'data.tar'),
            'Sharing snapshot and rollback archive do not match')
    validate_entries(value['files'])
    validate_entries(value.get('activation'), (NATIVE, ACTIVATION))
    return value


def load_pair(folder, expected_hash):
    return load_snapshot(folder, expected_hash)['files']


def converted(witness):
    result = json.loads(json.dumps(witness))
    smb = result[str(FILES[1])]
    if smb['exists']:
        data = base64.b64decode(smb['data'])
        data = data.replace(b'root preexec = /usr/lib/panasms/panasms-system-helper sharing check ',
                            b'root preexec = /usr/bin/python3 /usr/lib/panasms/management/sharing.py --check ')
        smb['data'] = base64.b64encode(data).decode()
    return result


def prepare_restore(source, source_hash, transaction, resume_units=(), source_activation=None):
    require(source_activation is not None, 'Missing paired activation rollback evidence')
    validate_entries(source_activation, (NATIVE, ACTIVATION))
    require(isinstance(transaction, str) and bool(transaction), 'Missing sharing rollback transaction')
    if GUARD.exists() or GUARD.is_symlink():
        guard = json.loads(secure_read(GUARD))
        require(guard.get('schema') == SCHEMA and guard.get('transaction') == transaction
                and guard.get('sourceHash') == source_hash and guard.get('source') == source
                and guard.get('sourceActivation') == source_activation,
                'Another sharing rollback requires recovery')
        require(isinstance(guard.get('resumeUnits'), list) and all(isinstance(unit, str) for unit in guard['resumeUnits']),
                'Invalid sharing rollback service state')
        validate_entries(guard['witness'])
        validate_entries(guard.get('witnessActivation'), (NATIVE, ACTIVATION))
        require(guard.get('phase') in ('prepared', 'restoring'), 'Invalid sharing rollback phase')
        return guard
    with locked():
        current = capture()
        current_activation = capture_activation()
    if current != source or current_activation != source_activation:
        result = subprocess.run([HELPER, 'sharing', 'rollback-check', '--source'],
                                input=json.dumps({'schema': SCHEMA, 'source': source}),
                                capture_output=True, text=True, timeout=60)
        require(result.returncode == 0, 'Sharing changed after the backup; verified native rollback is required')
        witness = json.loads(result.stdout)
        require(witness.get('schema') == SCHEMA and witness.get('journalsAbsent') is True, 'Unsupported sharing rollback witness')
        validate_entries(witness['files'])
        require(witness['files'] == current, 'Sharing changed during rollback validation')
    with locked():
        resume_check()
        require(capture() == current and capture_activation() == current_activation,
                'Sharing changed before rollback preparation')
        guard = {'schema': SCHEMA, 'transaction': transaction, 'phase': 'prepared',
                 'sourceHash': source_hash, 'source': source, 'witness': current, 'resumeUnits': list(resume_units),
                 'sourceActivation': source_activation, 'witnessActivation': current_activation}
        atomic(GUARD, json.dumps(guard, sort_keys=True).encode())
    return guard


def rollback_install(target_version, source_version=None):
    guard = json.loads(secure_read(GUARD))
    backup = json.loads(secure_read(UPDATE_ROOT / 'backup.json'))
    state = json.loads(secure_read(UPDATE_ROOT / 'state.json'))
    require(guard.get('schema') == SCHEMA and guard.get('phase') == 'prepared'
            and guard.get('transaction') == os.environ.get('PANASMS_UPDATE_TRANSACTION') == state.get('id')
            and state.get('phase') == 'rolling-back' and backup.get('complete') is True
            and backup.get('version') == target_version
            and (source_version is None or backup.get('toVersion') == source_version)
            and backup.get('sharingPairHash') == guard.get('sourceHash'),
            'The reverse package transition is not bound to the active rollback')
    snapshot = load_snapshot(Path(backup['folder']), backup['sharingPairHash'])
    require(guard.get('source') == snapshot['files'] and guard.get('sourceActivation') == snapshot['activation'],
            'The reverse package transition has mismatched sharing evidence')
    validate_entries(guard.get('witnessActivation'), (NATIVE, ACTIVATION))
    validate_entries(guard['witness'])
    require(isinstance(guard.get('resumeUnits'), list) and all(isinstance(unit, str) for unit in guard['resumeUnits']),
            'Invalid rollback service state')
    with locked():
        require(capture() in (guard['witness'], converted(guard['witness']))
                and capture_activation() == guard['witnessActivation'],
                'Sharing changed before reverse package transition')
    return guard


def rollback_timer_state(source_version, target_version):
    return 'panasms-sharing.timer' in rollback_install(target_version, source_version)['resumeUnits']


def package_stop(target_version):
    source_version = package_version()
    timer_active = None
    if PACKAGE_STATE.exists() or PACKAGE_STATE.is_symlink():
        previous = json.loads(secure_read(PACKAGE_STATE))
        require(previous.get('schema') == SCHEMA and type(previous.get('timerActive')) is bool,
                'Invalid sharing package service state')
        if previous.get('sourceVersion') == source_version and previous.get('targetVersion') == target_version:
            return
        require(previous.get('sourceVersion') == target_version and previous.get('targetVersion') == source_version,
                'Another sharing package transition requires recovery')
        timer_active = rollback_timer_state(source_version, target_version)
    if timer_active is None:
        result = subprocess.run(['systemctl', 'is-active', '--quiet', 'panasms-sharing.timer'])
        require(result.returncode in (0, 3, 4), 'Cannot determine the sharing timer state before replacement')
        timer_active = result.returncode == 0
    value = {'schema': SCHEMA, 'sourceVersion': source_version, 'targetVersion': target_version,
             'timerActive': timer_active}
    atomic(PACKAGE_STATE, json.dumps(value, sort_keys=True).encode())


def package_resume(abort=False):
    if not PACKAGE_STATE.exists() and not PACKAGE_STATE.is_symlink():
        return
    value = json.loads(secure_read(PACKAGE_STATE))
    require(value.get('schema') == SCHEMA and type(value.get('timerActive')) is bool,
            'Invalid sharing package service state')
    expected = value.get('sourceVersion' if abort else 'targetVersion')
    if expected != package_version(configuring=True):
        return
    if GUARD.exists() or GUARD.is_symlink() or os.environ.get('PANASMS_UPDATE_TRANSACTION'):
        unlink_sync(PACKAGE_STATE)
        return
    if value['timerActive']:
        subprocess.run(['systemctl', 'start', 'panasms-sharing.timer'], check=True)
    unlink_sync(PACKAGE_STATE)


def prepare_activation(target_version):
    require(os.environ.get('PANASMS_MAINTENANCE') == '1', 'Native preparation requires exclusive maintenance')
    result = subprocess.run(['dpkg', '--validate-version', target_version], capture_output=True, text=True)
    require(result.returncode == 0, 'Invalid native target package version')
    source = capabilities()
    marker = json.loads(secure_read(MARKER))
    require(type(marker.get('native', False)) is bool, 'Invalid sharing compatibility preparation')
    native = None
    if NATIVE.exists() or NATIVE.is_symlink():
        native = json.loads(secure_read(NATIVE))
        require(native.get('schema') == SCHEMA and isinstance(native.get('packageVersion'), str),
                'Invalid native sharing receipt')
    source['native'] = bool(native and native['packageVersion'] == source['packageVersion'])
    require(not marker.get('native') or source['native'], 'Native sharing requires recovery before another package transition')
    previous = None
    witness = None
    if source['native']:
        if ACTIVATION.exists() or ACTIVATION.is_symlink():
            previous = json.loads(secure_read(ACTIVATION))
            require(previous.get('schema') == SCHEMA and previous.get('targetVersion') == source['packageVersion']
                    and previous.get('nonce') == native.get('nonce'), 'Native source activation is incomplete')
            previous.pop('previous', None)
        result = subprocess.run([HELPER, 'sharing', 'rollback-check'], capture_output=True, text=True, timeout=60)
        require(result.returncode == 0, 'Native sharing requires recovery before another package transition')
        witness = json.loads(result.stdout)
        require(witness.get('schema') == SCHEMA and witness.get('journalsAbsent') is True,
                'Unsupported native sharing witness')
        validate_entries(witness['files'])
    with locked():
        resume_check()
        files = capture()
        if witness is not None:
            require(files == witness['files'], 'Sharing changed during native transition preparation')
        ticket = {'schema': SCHEMA, 'targetVersion': target_version, 'nonce': uuid.uuid4().hex,
                  'source': source, 'files': files}
        if previous is not None:
            ticket['previous'] = previous
        atomic(ACTIVATION, json.dumps(ticket, sort_keys=True).encode())
    return ticket


def retry_transaction(source_hash):
    if not GUARD.exists() and not GUARD.is_symlink():
        return None
    guard = json.loads(secure_read(GUARD))
    require(guard.get('schema') == SCHEMA and guard.get('sourceHash') == source_hash
            and isinstance(guard.get('transaction'), str) and bool(guard['transaction']),
            'Another sharing rollback requires recovery')
    return guard['transaction']


def begin_restore(guard):
    validate_activation_restore(guard, retry=guard['phase'] == 'restoring')
    current = capture()
    expected = converted(guard['witness'])
    if guard['phase'] == 'prepared':
        require(current == expected, 'Sharing changed during package rollback; current files were preserved')
        guard['phase'] = 'restoring'
        atomic(GUARD, json.dumps(guard, sort_keys=True).encode())
    else:
        require(all(current[name] in (value, guard['source'][name]) for name, value in expected.items()),
                'Sharing changed after interrupted rollback; current files were preserved')


def clear_config_directory():
    directory = FILES[0].parent
    require(not directory.is_symlink(), 'Refusing rollback through a symbolic link')
    if directory.exists():
        for child in directory.iterdir():
            if child.name == FILES[0].name:
                continue
            if child.is_dir() and not child.is_symlink():
                shutil.rmtree(child)
            else:
                child.unlink()


def restore_pair(guard):
    validate_activation_restore(guard, retry=True)
    expected = converted(guard['witness'])
    current = capture()
    require(all(current[name] in (value, guard['source'][name]) for name, value in expected.items()),
            'Sharing changed while restoring the archive; current files were preserved')
    for path in FILES:
        require(entry(path) in (expected[str(path)], guard['source'][str(path)]),
                'Sharing changed before restoring a publication; current file was preserved')
        value = guard['source'][str(path)]
        if value['exists']:
            atomic(path, base64.b64decode(value['data']), mode=value['mode'], gid=value['gid'])
        elif path.exists():
            require(not path.is_symlink(), 'Refusing sharing rollback symbolic link')
            path.unlink()
        if path.parent.exists():
            fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
    require(capture() == guard['source'], 'Sharing rollback verification failed')
    for path in (NATIVE, ACTIVATION):
        name = str(path)
        require(entry(path) in (guard['witnessActivation'][name], guard['sourceActivation'][name]),
                'Sharing activation changed during rollback; current file was preserved')
        value = guard['sourceActivation'][name]
        if value['exists']:
            atomic(path, base64.b64decode(value['data']), mode=value['mode'], gid=value['gid'])
        elif path.exists():
            unlink_sync(path)
    require(capture_activation() == guard['sourceActivation'], 'Sharing activation rollback verification failed')


def validate_activation_restore(guard, retry=False):
    validate_entries(guard.get('sourceActivation'), (NATIVE, ACTIVATION))
    validate_entries(guard.get('witnessActivation'), (NATIVE, ACTIVATION))
    current = capture_activation()
    require(all(current[name] in ((value, guard['sourceActivation'][name]) if retry else (value,))
                for name, value in guard['witnessActivation'].items()),
            'Sharing activation changed after rollback preparation; current files were preserved')


def unlink_sync(path):
    path.unlink()
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def finish_restore():
    unlink_sync(GUARD)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', choices=('capabilities', 'configure', 'check-install', 'resume-check', 'prepare-activation', 'package-stop', 'package-resume', 'package-abort', 'target-capabilities', 'rollback-install'))
    parser.add_argument('target_version', nargs='?')
    args = parser.parse_args()
    mode = args.mode
    if (mode in ('prepare-activation', 'package-stop', 'rollback-install')) != (args.target_version is not None):
        parser.error('prepare-activation, package-stop and rollback-install require a target package version')
    require(os.geteuid() == OWNER, 'Sharing compatibility requires root')
    if mode == 'capabilities':
        print(json.dumps(capabilities(), sort_keys=True))
    elif mode == 'target-capabilities':
        print(json.dumps(target_capabilities(), sort_keys=True))
    elif mode == 'configure':
        configure()
    elif mode == 'resume-check':
        resume_check()
    elif mode == 'prepare-activation':
        prepare_activation(args.target_version)
    elif mode == 'rollback-install':
        rollback_install(args.target_version)
    elif mode == 'package-stop':
        package_stop(args.target_version)
    elif mode in ('package-resume', 'package-abort'):
        package_resume(abort=mode == 'package-abort')
    else:
        check_install()
