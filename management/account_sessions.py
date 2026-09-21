from common import command, require, fingerprint


def sessions(username):
    result = []
    for line in command(['loginctl', 'list-sessions', '--no-legend', '--no-pager'], accepted=(0, 1), timeout=10).splitlines():
        fields = line.split()
        if len(fields) < 3 or fields[2] != username: continue
        try:
            raw = command(['loginctl', 'show-session', fields[0], '-p', 'Name', '-p', 'User', '-p', 'Service', '-p', 'RemoteHost', '-p', 'Leader', '-p', 'State', '-p', 'Timestamp'], timeout=5)
        except Exception:
            continue
        values = dict(line.split('=', 1) for line in raw.splitlines() if '=' in line)
        if values.get('Name') != username or values.get('Service') not in ('sshd', 'sshd-session'): continue
        result.append({'id': fields[0], 'user': username, 'uid': values.get('User'), 'address': values.get('RemoteHost', ''),
                       'leader': values.get('Leader'), 'state': values.get('State'), 'created': values.get('Timestamp'), 'kind': 'ssh'})
    return result


def terminate(username, session_id=None):
    selected = [s for s in sessions(username) if session_id is None or s['id'] == session_id]
    require(session_id is None or bool(selected), 'SSH session has already ended')
    for item in selected:
        command(['loginctl', 'terminate-session', item['id']], timeout=10)
    remaining = [s for s in sessions(username) if s['id'] in {i['id'] for i in selected} and s['state'] != 'closing']
    require(not remaining, 'Some SSH sessions could not be ended; account access restrictions are already applied')
