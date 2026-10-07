import json
import sys
import network
from common import Rejected, require


def run(request):
    mode = request['mode']
    if mode == 'inventory':
        rows = request['params']['interfaces']
        try:
            adapter = network.Adapter()
        except (ImportError, Rejected):
            adapter = None
        with network.locked():
            if adapter:
                network.current(adapter)
        return {'interfaces': rows,
                'wifi': network.wifi.inventory(adapter, rows) if adapter else None,
                'sharing': network.sharing.inventory(adapter, rows)}
    require(mode in ('plan', 'execute'), 'Unknown network dependency operation')
    require(request['action'] in ('network.confirm', 'network.rollback') or request['action'] in network.wifi.ACTIONS or request['action'] in network.sharing.ACTIONS, 'Unknown network dependency action')
    return getattr(network, mode)(request['action'], request['params'], request['user'])


if __name__ == '__main__':
    try:
        raw = sys.stdin.read(1048577)
        require(len(raw) <= 1048576, 'Request too large')
        result = run(json.loads(raw))
    except Rejected as error:
        result = {'error': str(error)}
    print(json.dumps(result))
