import fcntl
import json
import os
from pathlib import Path
import re
import tempfile
from contextlib import contextmanager
from common import Rejected, require, fingerprint

ACTIONS = set()
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
    if state and state.get('kind') in ('network.networkd', 'network.nm'):
        return state
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


def system_interface(name):
    require(isinstance(name, str) and re.fullmatch(r'[a-zA-Z0-9_.:-]{1,15}', name), 'Invalid network interface')
    path = Path('/sys/class/net') / name
    if name == 'lo' or name == 'docker0' or re.fullmatch(r'br-[0-9a-f]{12}', name) or name.startswith('veth'):
        return True
    return path.resolve().is_relative_to('/sys/devices/virtual/net') and not (path / 'phy80211').exists()


def access_interface(name):
    state = Path('/run/panasms-network-access.json')
    current = json.loads(state.read_text()) if state.exists() else {}
    path = str((Path('/sys/class/net') / str(name)).resolve())
    return bool(name) and (name == current.get('interface') or ('/gadget/net/' in path and Path('/etc/modules-load.d/panasms-usb.conf').exists()))


def plan(action, params, user=None):
    require(action in ACTIONS or action in ('network.confirm', 'network.rollback'), 'Unknown network operation')
    with locked():
        adapter = Adapter()
        state = current(adapter)
        if action in wifi.ACTIONS:
            require(not access_interface(params.get('interface')), 'Manage this connection in Network access settings')
            return wifi.plan(adapter, action, params, user)
        if action in sharing.ACTIONS:
            return sharing.plan(adapter, action, params, user)
        require(state and state['status'] == 'pending' and params.get('id') == state['id'], 'This network change has expired or is no longer pending')
        require(user == state['user'], 'Only the administrator who applied the network change can confirm or undo it')
        require(state.get('kind', '').startswith(('network.share.', 'network.wifi.')), 'This operation is managed by the native network handler')
        return {'target': state['interface'], 'confirmation': state['id'], 'details': [state['interface']], 'fingerprint': fingerprint(action, params, [state['id'], state['checkpoint']])}


def execute(action, params, user=None):
    with locked():
        adapter = Adapter()
        state = current(adapter)
        if action in wifi.ACTIONS:
            require(not access_interface(params.get('interface')), 'Manage this connection in Network access settings')
            return wifi.execute(adapter, action, params, user)
        if action in sharing.ACTIONS:
            return sharing.execute(adapter, action, params, user)
        require(state and state['status']=='pending' and params.get('id')==state['id'] and user==state['user'], 'This network change has expired or is no longer pending')
        if state.get('kind', '').startswith('network.share.'):
            if action == 'network.confirm': sharing.confirm(adapter, state)
            elif action == 'network.rollback': sharing.rollback(adapter, state)
        elif state.get('kind', '').startswith('network.wifi.'):
            if action == 'network.confirm': wifi.confirm(adapter, state)
            elif action == 'network.rollback':
                wifi.rollback(adapter, state)
                wifi.disarm(state)
        else:
            raise Rejected('This operation is managed by the native network handler')
        return {'message':'Network settings confirmed' if state['status']=='confirmed' else 'Previous network settings restored'}
