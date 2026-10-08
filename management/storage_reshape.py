import json
import math
import os
from pathlib import Path
import shutil
import time
from common import Rejected, atomic, command, fingerprint, require

ACTIONS = {'raid.convert'}
ROOT = Path('/var/lib/panasms-agent/raid-reshape')
TRANSITIONS = {'raid1': {'5'}, 'raid5': {'6'}, 'raid6': {'5'}}


def context(params):
    import storage
    inv = storage.inventory()
    target = storage.device(params.get('target'), inv)
    storage.protected(target, inv)
    md = Path('/sys/class/block') / inv[target]['kname'] / 'md'
    require(md.is_dir(), 'The device is not an MD RAID array')
    state = {key: (md / key).read_text().strip() for key in
             ('uuid', 'level', 'metadata_version', 'raid_disks', 'degraded', 'sync_action', 'reshape_position', 'component_size', 'chunk_size')}
    require(state['metadata_version'] == '1.2', 'RAID conversion requires MD 1.2 metadata')
    require(state['degraded'] == '0' and state['sync_action'] == 'idle' and state['reshape_position'] == 'none',
            'Wait for RAID maintenance and recover missing members before changing its level')
    level = params.get('level')
    require(level in TRANSITIONS.get(state['level'], set()), 'Supported conversions: RAID1 to RAID5, RAID5 to RAID6, RAID6 to RAID5')
    members = sorted('/dev/' + x.name for x in (md.parent / 'slaves').iterdir())
    count = int(state['raid_disks'])
    require(len(members) == count, 'Remove or use existing spare disks before changing the RAID level')
    entries = list(md.glob('dev-*'))
    require(len(entries) == count and all('in_sync' in (entry / 'state').read_text().strip().split(',') for entry in entries),
            'All RAID members must be synchronized')
    extra = params.get('replacement')
    if level in ('5', '6') and state['level'] != 'raid6':
        require(state['level'] != 'raid1' or count == 2, 'RAID1 conversion requires a two-disk mirror')
        extra = storage.device(extra, inv)
        storage.protected(extra, inv)
        storage.unused(extra, inv)
        require(inv[extra]['type'] in ('disk', 'part', 'loop') and not inv[extra].get('fstype'), 'The new member must be empty')
        require(inv[extra]['size'] >= min(inv[m]['size'] for m in members), 'The new disk is smaller than the array members')
        new_count = count + 1
    else:
        require(not extra, 'This conversion does not need an additional disk')
        new_count = count - 1
    # Refuse a backup on this array, including indirect dm/partition ancestry.
    directory = ROOT
    while not directory.exists():
        directory = directory.parent
    source = command(['findmnt', '-n', '-o', 'MAJ:MIN', '-T', str(directory)]).strip()
    backing = (Path('/sys/dev/block') / source).resolve()
    def uses_array(node, seen=None):
        seen = set() if seen is None else seen
        if node in seen:
            return False
        seen.add(node)
        if node.name == inv[target]['kname']:
            return True
        if (node / 'partition').exists() and uses_array(node.parent, seen):
            return True
        return any(uses_array(child.resolve(), seen) for child in (node / 'slaves').glob('*'))
    require(backing.exists() and not uses_array(backing), 'RAID recovery data must be stored outside the array being changed')
    require(not any(p.is_symlink() for p in [ROOT, *ROOT.parents]), 'The configuration is a symbolic link')
    required = max(64 * 1024 * 1024, math.lcm(count, new_count) * max(int(state['chunk_size']), 65536) * 4)
    require(shutil.disk_usage(directory).free > required * 2, 'Not enough free space on the system disk for RAID recovery data')
    state['members'] = {m: inv[m] for m in members}
    state['extra'] = inv[extra] if extra else None
    return target, md, state, extra, new_count


def backup_path(uuid):
    require(all(c in '0123456789abcdefABCDEF:-' for c in uuid), 'Invalid RAID UUID')
    return ROOT / (uuid.replace(':', '-') + '.backup')


def plan(action, params, user=None):
    target, md, state, extra, count = context(params)
    backup = backup_path(state['uuid'])
    if backup.exists():
        record = backup.with_suffix('.json')
        require(record.exists(), 'An earlier RAID recovery file exists. Verify the previous conversion before starting another one')
        previous = json.loads(record.read_text())
        require(previous['uuid'] == state['uuid'] and state['level'] == 'raid' + previous['level'] and int(state['raid_disks']) == previous['members'],
                'An earlier RAID recovery file exists. Verify the previous conversion before starting another one')
    details = [target, state['level'].upper() + ' → RAID' + params['level'],
               f'Members: {state["raid_disks"]} → {count}',
               'File systems are not resized. Reshape continues in the background; do not remove member disks.',
               'Recovery data will be kept on the system disk until the conversion finishes.']
    if extra:
        details.append(extra)
    if params['level'] == '5' and state['level'] == 'raid6':
        details.append('Redundancy will decrease: RAID5 tolerates one failed disk instead of two. One member becomes a spare; usable capacity is preserved.')
    return {'target': target, 'details': details, 'confirmation': target, 'fingerprint': fingerprint(action, params, state)}


def execute(action, params, user=None):
    from filesystem_health import device_lock
    from disk_sleep import locked
    with locked(), device_lock(os.path.realpath(params.get("target", ""))):
        return execute_locked(action, params, user)


def execute_locked(action, params, user=None):
    plan(action, params, user)
    target, md, state, extra, count = context(params)
    ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
    ROOT.chmod(0o700)
    backup = backup_path(state['uuid'])
    record = backup.with_suffix('.json')
    if backup.exists():
        backup.rename(backup.with_name(backup.name + '.' + str(time.time_ns()) + '.completed'))
    atomic(record, json.dumps({'uuid': state['uuid'], 'target': target, 'level': params['level'], 'members': count, 'sourceCount': int(state['raid_disks']), 'backup': str(backup)}))
    if extra:
        command(['mdadm', '--manage', target, '--add', extra])
    args = ['systemd-run', '--scope', '--quiet', '--unit=panasms-raid-convert-' + str(time.time_ns()),
            '/usr/sbin/mdadm', '--grow', target, '--level=' + params['level'], '--raid-devices=' + str(count), '--backup-file=' + str(backup)]
    command(args, timeout=300)
    return {'target': target, 'message': 'RAID conversion started. Check progress on the array card before changing storage again.'}


def safe_to_resume(md):
    if (md / 'degraded').read_text().strip() == '0':
        return True
    uuid = (md / 'uuid').read_text().strip()
    record = backup_path(uuid).with_suffix('.json')
    if not record.exists():
        return False
    saved = json.loads(record.read_text())
    entries = list(md.glob('dev-*'))
    synchronized_slots = {(entry / 'slot').read_text().strip() for entry in entries if 'in_sync' in (entry / 'state').read_text().strip().split(',')}
    return (saved['uuid'] == uuid and len(entries) == saved['members']
            and {str(slot) for slot in range(saved.get('sourceCount', saved['members']))}.issubset(synchronized_slots)
            and all((entry / 'block').exists()
                    and not {'faulty', 'blocked', 'write_error'}.intersection((entry / 'state').read_text().strip().split(','))
                    for entry in entries))


def resume(target, md):
    uuid = (md / 'uuid').read_text().strip()
    backup = backup_path(uuid)
    record = backup.with_suffix('.json')
    if not record.exists():
        return False
    saved = json.loads(record.read_text())
    require(saved['uuid'] == uuid and saved['backup'] == str(backup), 'RAID recovery record does not match this array')
    if (md / 'sync_action').read_text().strip() == 'frozen':
        (md / 'sync_action').write_text('reshape')
        return True
    args = ['mdadm', '--grow', target, '--continue']
    if backup.exists():
        args += ['--backup-file=' + str(backup)]
    command(['systemd-run', '--scope', '--quiet', '--unit=panasms-raid-resume-' + str(time.time_ns()), *args], timeout=300)
    return True


def recover():
    if not ROOT.exists():
        return
    failures = []
    for record in ROOT.glob('*.json'):
        try:
            saved = json.loads(record.read_text())
            uuid = saved['uuid']
            backup = backup_path(uuid)
            require(record == backup.with_suffix('.json') and saved['backup'] == str(backup), 'Invalid RAID recovery record')
            md = next((p / 'md' for p in Path('/sys/class/block').glob('md*')
                       if (p / 'md/uuid').exists() and (p / 'md/uuid').read_text().strip() == uuid), None)
            if md is None:
                target = '/dev/md/panasms-recover-' + uuid.replace(':', '')[:16]
                args = ['mdadm', '--assemble', target, '--uuid=' + uuid]
                if backup.exists():
                    args += ['--backup-file=' + str(backup)]
                command(args, timeout=60)
                md = Path('/sys/class/block') / Path(os.path.realpath(target)).name / 'md'
            target = '/dev/' + md.parent.name
            if (md / 'reshape_position').read_text().strip() != 'none' and (md / 'sync_action').read_text().strip() != 'reshape':
                require(safe_to_resume(md), 'Recover missing or failed array members first')
                resume(target, md)
        except (Rejected, OSError, ValueError, KeyError) as error:
            failures.append(f'{record.name}: {error}')
    if failures:
        raise Rejected('\n'.join(failures))


def check_removal():
    if not ROOT.exists():
        return
    for record in ROOT.glob('*.json'):
        saved = json.loads(record.read_text())
        md = next((p / 'md' for p in Path('/sys/class/block').glob('md*')
                   if (p / 'md/uuid').exists() and (p / 'md/uuid').read_text().strip() == saved['uuid']), None)
        require(md is not None and (md / 'reshape_position').read_text().strip() == 'none'
                and (md / 'sync_action').read_text().strip() == 'idle'
                and (md / 'level').read_text().strip() == 'raid' + saved['level'],
                'Finish or recover the RAID conversion before removing PaNasMs')


if __name__ == '__main__':
    import sys
    require(sys.argv[1:] in (['--recover'], ['--check-removal']), 'Unknown operation')
    if sys.argv[1] == '--recover':
        recover()
    else:
        check_removal()
