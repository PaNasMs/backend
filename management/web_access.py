import argparse
import fcntl
import socket
import urllib.request
from contextlib import contextmanager
from common import Path, json, time, atomic, command, fingerprint, require, Rejected

ACTIONS = {'system.web-port'}
CONFIG = Path('/etc/panasms/web.env')
STATE = Path('/var/lib/panasms-agent/web-access.json')
# https://fetch.spec.whatwg.org/#port-blocking
BLOCKED_PORTS = {1,7,9,11,13,15,17,19,20,21,22,23,25,37,42,43,53,69,77,79,87,95,
    101,102,103,104,109,110,111,113,115,117,119,123,135,137,139,143,161,179,389,427,
    465,512,513,514,515,526,530,531,532,540,548,554,556,563,587,601,636,989,990,993,
    995,1719,1720,1723,2049,3659,4045,4190,5060,5061,6000,6566,6665,6666,6667,6668,
    6669,6679,6697,10080}
LOCK = Path('/var/lib/panasms-agent/web-access.lock')


def port_number(value):
    require(isinstance(value, int) and not isinstance(value, bool) and 1 <= value <= 65535,
            'Enter an HTTP port between 1 and 65535')
    require(value not in BLOCKED_PORTS, 'Browsers block this HTTP port. Choose another port.')
    return value


def current_port():
    if not CONFIG.exists():
        return 80
    value = CONFIG.read_text().strip().removeprefix('PANASMS_HTTP_PORT=')
    require(value.isascii() and value.isdecimal(), 'Invalid HTTP port configuration')
    return port_number(int(value))


@contextmanager
def locked():
    LOCK.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    with LOCK.open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        yield


def state():
    return json.loads(STATE.read_text()) if STATE.exists() else {}


def query():
    saved = state()
    return {'port': current_port(), 'pending': saved.get('phase') in ('scheduled', 'applying'),
            'error': saved.get('error', '')}


def available(port):
    sockets = []
    try:
        for family, address in ((socket.AF_INET, '0.0.0.0'), (socket.AF_INET6, '::')):
            if family == socket.AF_INET6 and not socket.has_ipv6:
                continue
            sock = socket.socket(family, socket.SOCK_STREAM)
            sockets.append(sock)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if family == socket.AF_INET6:
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            sock.bind((address, port))
    except OSError as error:
        import errno
        if error.errno not in (errno.EAFNOSUPPORT, errno.EADDRNOTAVAIL):
            raise Rejected('The HTTP port is occupied or unavailable. Choose another port.') from error
    finally:
        for sock in sockets:
            sock.close()


def validate(port):
    port_number(port)
    require(not query()['pending'], 'An HTTP port change is already in progress')
    if port != current_port():
        available(port)


def plan(action, params, user=None):
    port = params.get('port')
    validate(port)
    return {'target': str(port), 'confirmation': str(port),
            'details': ['The web interface will restart on the selected HTTP port'],
            'fingerprint': fingerprint(action, params, current_port())}


def execute(action, params, user=None):
    with locked():
        port = params.get('port')
        validate(port)
        old = current_port()
        if old == port:
            return {'port': port}
        saved = {'phase': 'scheduled', 'previous': old, 'port': port}
        atomic(STATE, json.dumps(saved))
        try:
            command(['systemd-run', '--collect', '--unit=panasms-web-access', '--on-active=3s',
                     '--timer-property=AccuracySec=1s', '--timer-property=RemainAfterElapse=no', '/usr/bin/python3',
                     '/usr/lib/panasms/management/web_access.py', '--apply'])
        except Exception:
            STATE.unlink(missing_ok=True)
            raise
    return {'port': port, 'message': 'HTTP port change scheduled'}


def write_port(port):
    atomic(CONFIG, f'PANASMS_HTTP_PORT={port_number(port)}\n', 0o644)


def healthy(port):
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(f'http://127.0.0.1:{port}/api/v1/health', timeout=1) as response:
            return json.load(response).get('status') == 'ok'
    except (OSError, ValueError):
        return False


def apply():
    with locked():
        saved = state()
        if saved.get('phase') != 'scheduled':
            return
        try:
            available(saved['port'])
            saved['phase'] = 'applying'
            atomic(STATE, json.dumps(saved))
            write_port(saved['port'])
            command(['systemctl', 'restart', 'panasms-core.service'], timeout=30)
            for _ in range(20):
                if healthy(saved['port']):
                    saved['phase'] = 'ready'
                    atomic(STATE, json.dumps(saved))
                    return
                time.sleep(1)
            raise Rejected('The web interface did not start on the new port. The previous port was restored.')
        except Exception:
            write_port(saved['previous'])
            saved['phase'] = 'failed'
            saved['error'] = 'The web interface did not start on the new port. The previous port was restored.'
            atomic(STATE, json.dumps(saved))
            command(['systemctl', 'restart', 'panasms-core.service'], timeout=30)
            raise


def recover():
    with locked():
        saved = state()
        if saved.get('phase') in ('scheduled', 'applying'):
            write_port(saved['previous'])
            saved.update(phase='failed', error='The interrupted HTTP port change was rolled back.')
            atomic(STATE, json.dumps(saved))


def configure(port):
    with locked():
        port = current_port() if port is None else port_number(port)
        validate(port)
        if not healthy(port):
            available(port)
        write_port(port)
        return port


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument('--apply', action='store_true')
    modes.add_argument('--recover', action='store_true')
    modes.add_argument('--configure', action='store_true')
    parser.add_argument('--port', type=int)
    args = parser.parse_args()
    try:
        if args.apply:
            apply()
        elif args.recover:
            recover()
        else:
            print(configure(args.port))
    except Rejected as error:
        parser.exit(1, str(error) + '\n')
