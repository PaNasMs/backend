"""Temporary GO-04 bridge: Samba remains owned by GO-06."""
import json
import os
import sys
from common import require, Rejected
import sharing


def main():
    require(os.geteuid() == 0, 'Administrator permissions required')
    raw = sys.stdin.buffer.read(1024 * 1024 + 1)
    require(len(raw) <= 1024 * 1024, 'Request too large')
    request = json.loads(raw)
    operation = request.get('operation')
    target = request.get('target')
    from common import name
    name(target)
    if operation != 'status':
        os.environ['PANASMS_OPERATION'] = '1'
    if operation == 'status':
        return sharing.account_status(target)
    if operation == 'sync-password':
        sharing.sync_password(target, request['password'])
    else:
        callbacks = {'disable': sharing.disable, 'disconnect': sharing.disconnect,
                     'remove': sharing.remove_account}
        require(operation in callbacks, 'Unknown account dependency operation')
        callbacks[operation](target)
    return {}


if __name__ == '__main__':
    try:
        print(json.dumps(main()))
    except Rejected as error:
        print(json.dumps({'error': str(error)}))
    except Exception:
        print(json.dumps({'error': 'SMB account update failed; review the shared-folder settings'}))
