import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import struct
import tempfile
import time
import uuid
from contextlib import contextmanager
from common import Rejected, require, fingerprint, json_command, command

ACTIONS = {'network.configure', 'network.confirm', 'network.rollback'}
NM = 'org.freedesktop.NetworkManager'
NM_PATH = '/org/freedesktop/NetworkManager'
STATE_DIR = Path('/run/panasms-network')
TIMEOUT = 120

import wifi
ACTIONS |= wifi.ACTIONS
import network_sharing as sharing
ACTIONS |= sharing.ACTIONS


class Adapter:
    def __init__(self):
        import dbus
        self.dbus = dbus
        try:
            self.bus = dbus.SystemBus()
            available = self.bus.name_has_owner(NM)
        except dbus.DBusException:
            available = False
        require(available, 'NetworkManager is not running; network editing is unavailable')
        self.manager = self.interface(NM_PATH, NM)

    def interface(self, path, interface):
        return self.dbus.Interface(self.bus.get_object(NM, path), interface)

    def properties(self, path, interface):
        return self.interface(path, 'org.freedesktop.DBus.Properties').GetAll(interface)

    def devices(self):
        return self.manager.GetDevices()

    def device(self, name):
        require(isinstance(name, str) and re.fullmatch(r'[a-zA-Z0-9_.:-]{1,15}', name), 'Invalid network interface')
        path = self.manager.GetDeviceByIpIface(name)
        props = self.properties(path, NM + '.Device')
        require(str(props.get('Interface')) == name, 'Network interface changed')
        return str(path), props

    def active(self, name):
        path, props = self.device(name)
        require(props.get('Managed') and int(props.get('State', 0)) == 100, 'Select a connected interface managed by NetworkManager')
        active = self.properties(props['ActiveConnection'], NM + '.Connection.Active')
        profile = str(active['Connection'])
        settings = self.interface(profile, NM + '.Settings.Connection').GetSettings()
        require(settings['connection']['type'] in ('802-3-ethernet', '802-11-wireless'), 'This connection type is available for viewing only')
        applied, version = self.interface(path, NM + '.Device').GetAppliedConnection(0)
        return path, profile, settings, applied, version

    def checkpoints(self):
        return [str(p) for p in self.properties(NM_PATH, NM)['Checkpoints']]

    def create(self, device):
        return str(self.manager.CheckpointCreate([device], TIMEOUT, 0))

    def rollback(self, checkpoint):
        results = self.manager.CheckpointRollback(checkpoint)
        require(all(int(code) == 0 for code in results.values()), 'Network rollback could not restore every interface; check the local console')

    def extend(self, checkpoint):
        self.manager.CheckpointAdjustRollbackTimeout(checkpoint, 60)

    def destroy(self, checkpoint):
        self.manager.CheckpointDestroy(checkpoint)

    def apply(self, path, settings, version):
        self.interface(path, NM + '.Device').Reapply(settings, version, 0, timeout=30)

    def persist(self, profile, settings):
        # Only the reviewed IP/MTU fields are written; Wi-Fi secrets and other profile properties stay intact.
        args = ['nmcli', '--wait', '30', 'connection', 'modify', 'uuid', str(settings['connection']['uuid'])]
        for family in (4, 6):
            key = 'ipv' + str(family)
            values = public_ip(settings, family)
            for field, value in (
                ('method', values['method']), ('addresses', ','.join(values['addresses'])),
                ('gateway', values['gateway']), ('dns', ','.join(values['dns'])),
                ('ignore-auto-dns', 'yes' if values['ignoreAutoDns'] else 'no'),
                ('never-default', 'yes' if values['neverDefault'] else 'no'),
                ('route-metric', str(values['metric'])),
                ('routes', ','.join(route_text(route) for route in values['routes'])),
            ):
                args += [key + '.' + field, value]
        kind = str(settings['connection']['type'])
        args += [kind + '.mtu', str(settings.get(kind, {}).get('mtu', 0))]
        command(args, timeout=40)


def plain(value):
    if isinstance(value, dict):
        return {str(k): plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [plain(v) for v in value]
    if isinstance(value, (str, bool, int, float)):
        return value
    return str(value)


def signature(settings):
    data = plain(settings)
    data.get('connection', {}).pop('timestamp', None)
    return fingerprint('network-state', {}, data)


def public_ip(settings, family):
    data = settings.get('ipv' + str(family), {})
    dns = []
    for value in data.get('dns', []):
        raw = struct.pack('=I', int(value)) if family == 4 else bytes(value)
        dns.append(str(ipaddress.ip_address(raw)))
    return {
        'method': str(data.get('method', 'auto')),
        'addresses': [str(a['address']) + '/' + str(a['prefix']) for a in data.get('address-data', [])],
        'gateway': str(data.get('gateway', '')),
        'dns': dns,
        'ignoreAutoDns': bool(data.get('ignore-auto-dns', False)),
        'neverDefault': bool(data.get('never-default', False)),
        'metric': int(data.get('route-metric', -1)),
        'routes': [{'destination': str(r['dest']) + '/' + str(r['prefix']), 'gateway': str(r.get('next-hop', '')), 'metric': int(r.get('metric', -1))} for r in data.get('route-data', [])],
    }


def editable(settings):
    for family in (4, 6):
        data = settings.get('ipv' + str(family), {})
        if data.get('method', 'auto') not in ('auto', 'manual', 'disabled', 'ignore', 'link-local'):
            return False
        if any(set(a) - {'address', 'prefix'} for a in data.get('address-data', [])):
            return False
        if data.get('dns-data') or any(set(r) - {'dest', 'prefix', 'next-hop', 'metric'} for r in data.get('route-data', [])):
            return False
    return True


def config(settings):
    kind = str(settings['connection']['type'])
    return {'ipv4': public_ip(settings, 4), 'ipv6': public_ip(settings, 6), 'mtu': int(settings.get(kind, {}).get('mtu', 0))}


def ip(value, family, prefix=False):
    require(isinstance(value, str) and len(value) < 80 and '%' not in value, 'Invalid IP address or prefix')
    try:
        parsed = ipaddress.ip_interface(value) if prefix else ipaddress.ip_address(value)
    except ValueError:
        raise Rejected('Invalid IP address or prefix')
    require(parsed.version == family and (not prefix or '/' in value), 'IP address family or prefix does not match')
    address = parsed.ip if prefix else parsed
    require(not address.is_multicast and not address.is_unspecified, 'Use a unicast IP address')
    return str(parsed)


def validate(params):
    require(isinstance(params, dict), 'Invalid network settings')
    result = {}
    for family in (4, 6):
        key = 'ipv' + str(family)
        data = params.get(key)
        require(isinstance(data, dict), 'Invalid network settings')
        method = data.get('method')
        require(method in (('auto', 'manual', 'disabled', 'link-local') if family == 4 else ('auto', 'manual', 'disabled', 'ignore', 'link-local')), 'Unsupported IP configuration method')
        row = {'method': method}
        for field in ('addresses', 'dns'):
            values = data.get(field, [])
            require(isinstance(values, list) and len(values) <= 16, 'Too many network addresses')
            row[field] = list(dict.fromkeys(ip(v, family, field == 'addresses') for v in values))
        row['gateway'] = ip(data['gateway'], family) if data.get('gateway') else ''
        for field in ('ignoreAutoDns', 'neverDefault'):
            require(type(data.get(field)) is bool, 'Invalid network option')
            row[field] = data[field]
        metric = data.get('metric', -1)
        require(type(metric) is int and -1 <= metric <= 4294967295, 'Invalid route metric')
        row['metric'] = metric
        routes = data.get('routes', [])
        require(isinstance(routes, list) and len(routes) <= 64, 'Too many routes')
        row['routes'] = []
        for route in routes:
            require(isinstance(route, dict), 'Invalid route')
            require(isinstance(route.get('destination'), str), 'Route destination must be a network with a prefix')
            try:
                destination = ipaddress.ip_network(route['destination'], strict=True)
            except ValueError:
                raise Rejected('Route destination must be a network with a prefix')
            require(destination.version == family and '/' in route['destination'], 'IP address family or prefix does not match')
            metric = route.get('metric', -1)
            require(type(metric) is int and -1 <= metric <= 4294967295, 'Invalid route metric')
            row['routes'].append({'destination': str(destination), 'gateway': ip(route['gateway'], family) if route.get('gateway') else '', 'metric': metric})
        require(method != 'manual' or row['addresses'], 'A static configuration needs at least one address')
        require(not row['neverDefault'] or (not row['gateway'] and all(ipaddress.ip_network(r['destination']).prefixlen > 0 for r in row['routes'])), 'A local-only connection cannot have a default gateway or route')
        require(method not in ('disabled', 'ignore', 'link-local') or not (row['addresses'] or row['dns'] or row['gateway'] or row['routes']), 'Clear addresses, DNS and routes for the selected IP method')
        result[key] = row
    require(any(result[k]['method'] not in ('disabled', 'ignore') for k in ('ipv4', 'ipv6')), 'At least one IP protocol must remain enabled')
    mtu = params.get('mtu', 0)
    minimum = 1280 if result['ipv6']['method'] not in ('disabled', 'ignore') else 576
    require(type(mtu) is int and (mtu == 0 or minimum <= mtu <= 9000), 'MTU must be automatic or within the supported IP range')
    result['mtu'] = mtu
    return result


def patched(settings, params, dbus):
    result = dbus.Dictionary({str(key): dbus.Dictionary(dict(value), signature='sv') for key, value in settings.items()}, signature='sa{sv}')
    for family in (4, 6):
        key = 'ipv' + str(family)
        data = result.setdefault(key, dbus.Dictionary(signature='sv'))
        values = params[key]
        for legacy in ('addresses', 'routes', 'dns-data'):
            data.pop(legacy, None)
        data['method'] = dbus.String(values['method'])
        data['address-data'] = dbus.Array([dbus.Dictionary({'address': str(ipaddress.ip_interface(a).ip), 'prefix': dbus.UInt32(ipaddress.ip_interface(a).network.prefixlen)}, signature='sv') for a in values['addresses']], signature='a{sv}')
        data['route-data'] = dbus.Array([dbus.Dictionary({**{'dest': str(ipaddress.ip_network(r['destination']).network_address), 'prefix': dbus.UInt32(ipaddress.ip_network(r['destination']).prefixlen)}, **({'next-hop': r['gateway']} if r['gateway'] else {}), **({'metric': dbus.UInt32(r['metric'])} if r['metric'] >= 0 else {})}, signature='sv') for r in values['routes']], signature='a{sv}')
        data.pop('gateway', None)
        if values['gateway']:
            data['gateway'] = dbus.String(values['gateway'])
        data['dns'] = dbus.Array([dbus.UInt32(struct.unpack('=I', ipaddress.ip_address(a).packed)[0]) if family == 4 else dbus.ByteArray(ipaddress.ip_address(a).packed) for a in values['dns']], signature='u' if family == 4 else 'ay')
        data['ignore-auto-dns'] = dbus.Boolean(values['ignoreAutoDns'])
        data['never-default'] = dbus.Boolean(values['neverDefault'])
        data['route-metric'] = dbus.Int64(values['metric'])
    kind = str(result['connection']['type'])
    result.setdefault(kind, dbus.Dictionary(signature='sv'))['mtu'] = dbus.UInt32(params['mtu'])
    return result


def route_text(route):
    result = route['destination']
    if route['gateway'] or route['metric'] >= 0:
        family = ipaddress.ip_network(route['destination']).version
        result += ' ' + (route['gateway'] or ('0.0.0.0' if family == 4 else '::'))
    if route['metric'] >= 0:
        result += ' ' + str(route['metric'])
    return result


@contextmanager
def locked():
    STATE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    with (STATE_DIR / 'lock').open('a') as file:
        fcntl.flock(file, fcntl.LOCK_EX)
        yield


def read_state():
    path = STATE_DIR / 'change.json'
    return json.loads(path.read_text()) if path.exists() else None


def save_state(state):
    fd, path = tempfile.mkstemp(dir=STATE_DIR)
    try:
        with os.fdopen(fd, 'w') as file:
            json.dump(state, file)
        os.replace(path, STATE_DIR / 'change.json')
    finally:
        if os.path.exists(path):
            os.unlink(path)


def current(adapter):
    state = read_state()
    if state and state.get('kind', '').startswith('network.share.'):
        return sharing.current(adapter, state)
    if state and state.get('kind', '').startswith('network.wifi.'):
        return wifi.current(adapter, state)
    if state and state['status'] in ('applying', 'pending') and state['checkpoint'] not in adapter.checkpoints():
        state['status'] = 'expired'
        save_state(state)
    return state


def pending_info(state):
    if not state:
        return None
    return {k: state[k] for k in ('id', 'interface', 'user', 'status', 'deadline', 'addresses')}


def query():
    links = json_command(['ip', '-j', 'address', 'show'])
    routes = []
    for family in (4, 6):
        routes += [{**r, 'family': family} for r in json_command(['ip', '-j', '-'+str(family), 'route', 'show', 'table', 'all'])]
    rows = []
    try:
        adapter = Adapter()
    except (ImportError, Rejected):
        adapter = None
    for link in links:
        row = {'name': link['ifname'], 'index': link['ifindex'], 'state': link.get('operstate', 'UNKNOWN'), 'adminUp': 'UP' in link.get('flags', []), 'mac': link.get('address', ''), 'mtu': link['mtu'], 'addresses': [a['local']+'/'+str(a['prefixlen']) for a in link.get('addr_info', [])], 'editable': False, 'kind': link.get('link_type', 'unknown'), 'profile': '', 'config': None, 'dns': []}
        if adapter:
            try:
                path, props = adapter.device(row['name'])
                row.update(kind={1:'ethernet',2:'wifi',10:'bond',11:'vlan',13:'bridge',19:'vxlan',32:'loopback'}.get(int(props['DeviceType']), 'virtual'), nmState=int(props['State']), managed=bool(props['Managed']))
                if int(props['DeviceType']) == 1 and int(props.get('Capabilities', 0)) & 2:
                    wired = adapter.properties(path, NM+'.Device.Wired')
                    if 'Carrier' in wired: row['carrier'] = bool(wired['Carrier'])
                for family in (4,6):
                    ip_path = props.get('Ip'+str(family)+'Config', '/')
                    if ip_path != '/':
                        ip_props = adapter.properties(ip_path, NM+'.IP'+str(family)+'Config')
                        for entry in ip_props.get('NameserverData', []):
                            if entry.get('address'): row['dns'].append(str(entry['address']))
                if int(props['State']) == 100 and props['ActiveConnection'] != '/':
                    active = adapter.properties(props['ActiveConnection'], NM+'.Connection.Active')
                    profile = adapter.interface(active['Connection'], NM+'.Settings.Connection').GetSettings()
                    row['profile'] = str(profile['connection']['id'])
                    row['uuid'] = str(profile['connection']['uuid'])
                    row['editable'] = bool(props['Managed']) and profile['connection']['type'] in ('802-3-ethernet','802-11-wireless') and editable(profile)
                    if row['editable']: row['config'] = config(profile)
            except (Rejected, adapter.dbus.DBusException):
                row['editable'] = False
        rows.append(row)
    with locked():
        state = current(adapter) if adapter else read_state()
    return {'backend': 'NetworkManager' if adapter else 'readonly', 'interfaces': rows, 'routes': routes, 'change': pending_info(state), 'serverTime': time.time(), 'timeout': TIMEOUT, 'wifi': wifi.inventory(adapter, rows) if adapter else None, 'sharing': sharing.inventory(adapter, rows)}


def plan(action, params, user=None):
    require(action in ACTIONS, 'Unknown network operation')
    adapter = Adapter()
    with locked():
        state = current(adapter)
        if action in sharing.ACTIONS:
            return sharing.plan(adapter, action, params, user)
        if action == 'network.configure':
            require(not any(params.get('interface') in [g['source'], *g['outputs']] for g in sharing.load()), 'Edit this interface through its sharing group')
        if action in wifi.ACTIONS:
            return wifi.plan(adapter, action, params, user)
        if action == 'network.configure':
            require(not state or state['status'] not in ('applying', 'pending'), 'Confirm or roll back the pending network change first')
            target = params.get('interface')
            path, profile, settings, applied, version = adapter.active(target)
            require(editable(settings) and editable(applied), 'Advanced connection settings cannot be edited by this form')
            values = validate(params.get('config'))
            require(values != config(settings), 'Network settings have not changed')
            return {'target': target, 'confirmation': target, 'details': [target, 'Network changes require confirmation within two minutes'], 'fingerprint': fingerprint(action, params, [path, profile, signature(settings), signature(applied), int(version)])}
        require(state and state['status'] == 'pending' and params.get('id') == state['id'], 'This network change has expired or is no longer pending')
        require(user == state['user'], 'Only the administrator who applied the network change can confirm or undo it')
        return {'target': state['interface'], 'confirmation': state['id'], 'details': [state['interface']], 'fingerprint': fingerprint(action, params, [state['id'], state['checkpoint']])}


def execute(action, params, user=None):
    adapter = Adapter()
    with locked():
        state = current(adapter)
        if action in sharing.ACTIONS:
            return sharing.execute(adapter, action, params, user)
        if action in wifi.ACTIONS:
            return wifi.execute(adapter, action, params, user)
        if action == 'network.configure':
            require(not state or state['status'] not in ('applying','pending'), 'Confirm or roll back the pending network change first')
            path, profile, settings, applied, version = adapter.active(params['interface'])
            values = validate(params['config'])
            checkpoint = adapter.create(path)
            state = {'id':uuid.uuid4().hex,'interface':params['interface'],'user':user,'checkpoint':checkpoint,'profile':profile,'profileHash':signature(settings),'status':'applying','deadline':time.time()+TIMEOUT,'addresses':values['ipv4']['addresses']+values['ipv6']['addresses']}
            save_state(state)
            try:
                adapter.apply(path, patched(applied, values, adapter.dbus), version)
                effective, _ = adapter.interface(path, NM + '.Device').GetAppliedConnection(0)
                state.update(status='pending', appliedHash=signature(effective), config=values)
                save_state(state)
            except Exception:
                adapter.rollback(checkpoint)
                state['status']='rolled-back';save_state(state)
                raise Rejected('Could not apply network settings; previous settings were restored')
            return {'message':'Network changes await confirmation','change':pending_info(state)}
        require(state and state['status']=='pending' and params.get('id')==state['id'] and user==state['user'], 'This network change has expired or is no longer pending')
        if state.get('kind', '').startswith('network.share.'):
            if action == 'network.confirm': sharing.confirm(adapter, state)
            elif action == 'network.rollback': sharing.rollback(adapter, state)
            return {'message': 'Network settings confirmed' if state['status'] == 'confirmed' else 'Previous network settings restored'}
        if state.get('kind', '').startswith('network.wifi.'):
            if action == 'network.confirm':
                wifi.confirm(adapter, state)
            elif action == 'network.rollback':
                wifi.rollback(adapter, state)
                wifi.disarm(state)
            else:
                raise Rejected('Unknown network operation')
            return {'message':'Network settings confirmed' if state['status']=='confirmed' else 'Previous network settings restored'}
        if action == 'network.rollback':
            adapter.rollback(state['checkpoint']);state['status']='rolled-back'
        elif action == 'network.confirm':
            path, profile, settings, applied, version = adapter.active(state['interface'])
            require(profile==state['profile'] and signature(settings)==state['profileHash'] and signature(applied)==state['appliedHash'], 'Network configuration changed externally; roll back and review it again')
            require(state['checkpoint'] in adapter.checkpoints(), 'This network change has expired or is no longer pending')
            adapter.extend(state['checkpoint'])
            state['deadline'] = time.time() + 60
            save_state(state)
            adapter.persist(profile, patched(settings,state['config'],adapter.dbus))
            adapter.destroy(state['checkpoint']);state['status']='confirmed'
        else:
            raise Rejected('Unknown network operation')
        save_state(state)
        return {'message':'Network settings confirmed' if state['status']=='confirmed' else 'Previous network settings restored'}
