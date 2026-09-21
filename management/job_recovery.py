from pathlib import Path
import grp
import pwd
from common import command, json_command, require


def inspect(request):
    action = request.get('action', '')
    params = request.get('params', {})
    require(isinstance(action, str) and isinstance(params, dict), 'Invalid recovery context')
    target = params.get('target', '')
    checks = []
    route = '/'
    recovery_action = None
    message = 'Review the current state below. The interrupted operation has not been repeated.'
    if action.startswith(('user.', 'group.')):
        route = '/users'
        try:
            account = grp.getgrnam(target) if action.startswith('group.') else pwd.getpwnam(target)
            checks.append({'label': 'Account', 'value': 'Present'})
            if not action.startswith('group.'):
                checks.append({'label': 'Home folder', 'value': account.pw_dir})
        except KeyError:
            checks.append({'label': 'Account', 'value': 'Absent'})
        if action == 'user.password':
            message = 'A password change cannot be verified from stored credentials. Sign in or set a new password through Users.'
    elif action.startswith('share.'):
        import sharing
        route = '/sharing'
        checks.append({'label':'Shared folders','value':sharing.read()['shares']})
        if sharing.JOURNAL.exists() or sharing.drift(sharing.read()): recovery_action = 'share.recover'
    elif action.startswith('homes.'):
        import homes
        route = '/settings/users'
        state = homes.query()
        checks.append({'label': 'Home recovery journal', 'value': 'Recovery required' if state.get('recovery') else 'No pending journal'})
        if state.get('recovery'): recovery_action = 'homes.recover'
        message = 'Open home-folder settings. Recover an existing transfer before attempting another move; destination copies may have been retained.'
    elif action.startswith('module.'):
        import module_manager
        route = '/modules'
        state = module_manager.registry()
        item = state.get(target)
        checks.append({'label': 'Module', 'value': ('Installed: ' + str(item.get('version', '')) if item else 'Not registered')})
        pending = (module_manager.transaction_path() / 'journal.json').exists()
        checks.append({'label': 'Recovery journal', 'value': 'Recovery required' if pending else 'No pending journal'})
        if pending: recovery_action = 'module.recover'
        message = 'Module transactions are recovered during agent startup. Review the installed version and enablement before installing again; upload credentials are not retained in the task.'
    elif action.startswith('network.'):
        route = '/network'
        output = command(['nmcli', '-t', '-f', 'DEVICE,STATE,CONNECTION', 'device'], timeout=10)
        checks.append({'label': 'Network interfaces', 'value': output[:8192]})
        message = 'Network watchdogs handle pending rollbacks. Review current connectivity and any pending confirmation in Network before applying a fresh configuration.'
    elif action.startswith(('service.', 'updates.', 'system.')):
        route = '/system/updates' if action.startswith('updates.') else '/system/services'
        if action.startswith('service.'):
            import host
            unit = host.service(target)
            output = command(['systemctl', 'show', '--property=ActiveState,SubState,UnitFileState', '--', unit], timeout=10)
            checks.append({'label': 'Service', 'value': output})
        elif action.startswith('updates.'):
            output = command(['dpkg', '--audit'], timeout=20)
            if output.strip(): recovery_action = 'updates.repair'
            checks.append({'label': 'Package database', 'value': output[:8192] or 'No incomplete packages reported'})
            message = 'Do not restart package installation blindly. Review package status and refresh the update list; incomplete packages require repair before another upgrade.'
        else:
            checks.append({'label': 'System', 'value': 'The system is reachable'})
            message = 'Power actions are never replayed automatically. System availability alone does not prove whether the previous reboot completed.'
    elif action.startswith(('file.', 'folder.')):
        route = '/files'
        for key in ('target', 'destination'):
            value = params.get(key)
            if not isinstance(value, str) or not value.startswith('/'):
                continue
            path = Path(value)
            try:
                stat = path.lstat()
                checks.append({'label': key, 'value': value + ': present, ' + str(stat.st_size) + ' bytes'})
            except FileNotFoundError:
                checks.append({'label': key, 'value': value + ': absent'})
        destination = params.get('destination')
        if isinstance(destination, str) and destination.startswith('/'):
            import itertools, json
            parent = Path(destination).parent
            for holder in itertools.islice(parent.glob('.panasms-copy-*'), 50):
                if holder.is_symlink(): continue
                journal = holder / 'transfer.json'
                if journal.is_symlink(): continue
                try:
                    if journal.stat().st_size > 16384: continue
                    state = json.loads(journal.read_text())
                    if state.get('destination') == destination and state.get('source') == target:
                        checks.append({'label': 'Retained transfer journal', 'value': str(holder) + ': ' + state.get('phase', 'unknown')})
                except (OSError, ValueError):
                    continue
        message = 'Compare source and destination before retrying. A partial copy may exist; do not delete either automatically. Presence or size alone does not prove a complete copy.'
    else:
        route = '/storage/disks' if action.startswith(('raid.', 'disk.', 'smart.')) else '/storage/mounts'
        inventory = json_command(['lsblk', '--json', '--bytes', '--output', 'NAME,PATH,TYPE,SIZE,FSTYPE,UUID,MOUNTPOINTS'], timeout=15)
        checks.append({'label': 'Storage state', 'value': inventory})
        if action.startswith('raid.'):
            checks.append({'label': 'RAID state', 'value': Path('/proc/mdstat').read_text()[:16384]})
            message = 'Check array members and maintenance progress. Use the array pause/resume controls for an existing operation; do not recreate or reformat the array.'
        elif action.startswith(('filesystem.', 'partition.', 'luks.', 'disk.')):
            message = 'Inspect the actual partition/filesystem state. Formatting and resizing cannot be safely rolled back by rerunning the command. Back up available data before repair.'
    return {'message': message, 'checks': checks, 'route': route, 'recoveryAction': recovery_action}
