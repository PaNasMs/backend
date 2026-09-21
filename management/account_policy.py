import datetime
import json
import os
from pathlib import Path
import pwd
import secrets
from common import atomic, require

PATH = Path('/etc/panasms/accounts.json')


def read():
    return json.loads(PATH.read_text()) if PATH.exists() else {}


def entry(user):
    record = read().get(user.pw_name, {})
    return record if record.get('uid') == user.pw_uid else {}


def save(user, changes, revoke=False):
    data = read()
    record = entry(user)
    record.update(changes)
    record['uid'] = user.pw_uid
    if revoke: record['epoch'] = secrets.token_hex(16)
    data[user.pw_name] = record
    PATH.parent.mkdir(parents=True, exist_ok=True)
    atomic(PATH, json.dumps(data), 0o644)
    return record


def shadow(username):
    for line in Path('/etc/shadow').read_text().splitlines():
        fields = line.split(':')
        if fields[0] != username: continue
        fields += [''] * (9 - len(fields))
        def number(i): return int(fields[i]) if fields[i] else -1
        return {'passwordStatus': 'locked' if fields[1].startswith(('!', '*')) else 'empty' if not fields[1] else 'set',
                'lastChange': number(2), 'minDays': number(3), 'maxDays': number(4), 'warnDays': number(5),
                'inactiveDays': number(6), 'expiryDay': number(7), 'forcePasswordChange': number(2) == 0}
    return {'passwordStatus': 'unknown', 'expiryDay': -1}


def expired(state):
    return state.get('expiryDay', -1) >= 0 and state['expiryDay'] <= (datetime.date.today() - datetime.date(1970, 1, 1)).days


def password_inactive(state):
    last, maximum, inactive = (state.get(k, -1) for k in ('lastChange', 'maxDays', 'inactiveDays'))
    today = (datetime.date.today() - datetime.date(1970, 1, 1)).days
    return last > 0 and maximum >= 0 and inactive >= 0 and today > last + maximum + inactive


def expiry(value):
    require(isinstance(value, str), 'Enter an account expiry date or leave it empty')
    if not value: return -1
    try: result = (datetime.date.fromisoformat(value) - datetime.date(1970, 1, 1)).days
    except ValueError:
        require(False, 'Invalid account expiry date')
    require(result > 0, 'Invalid account expiry date')
    return result
