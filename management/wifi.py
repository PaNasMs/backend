import json
from pathlib import Path
import re
import sys
import time
import uuid
from common import Rejected, require, command, atomic

ACTIONS = {'network.wifi.scan', 'network.wifi.radio', 'network.wifi.connect', 'network.wifi.disconnect'}
import network as n
RECOVERY = Path('/var/lib/ostojaos-agent/network-wifi/pending.json')
HELPER = '/usr/lib/ostojaos/management/wifi.py'
CONFIG = Path('/etc/NetworkManager/conf.d')


def radio(adapter):
    props = adapter.properties(n.NM_PATH, n.NM)
    return {'enabled': bool(props['WirelessEnabled']), 'hardwareEnabled': bool(props['WirelessHardwareEnabled'])}


def set_radio(adapter, enabled):
    adapter.interface(n.NM_PATH, 'org.freedesktop.DBus.Properties').Set(n.NM, 'WirelessEnabled', adapter.dbus.Boolean(enabled))


def policy_file(adapter, name):
    path, _ = adapter.device(name)
    mac = str(adapter.properties(path, n.NM + '.Device.Wireless')['PermHwAddress']).lower()
    require(re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}', mac), 'Wi-Fi adapter has no stable hardware address')
    return CONFIG / ('90-ostojaos-wifi-' + mac.replace(':', '') + '.conf'), mac


def disabled(adapter, name):
    return policy_file(adapter, name)[0].exists()


def adapter_radio(adapter, name):
    result = radio(adapter)
    phy = Path('/sys/class/net') / name / 'phy80211'
    switches = list(phy.glob('rfkill*/hard'))
    if switches:
        result['hardwareEnabled'] = all(p.read_text().strip() == '0' for p in switches)
    result['enabled'] = result['enabled'] and not disabled(adapter, name)
    return result


def configure(adapter, name, enabled):
    path, props = adapter.device(name)
    file, mac = policy_file(adapter, name)
    require(props['Managed'] or file.exists(), 'Select a managed Wi-Fi adapter')
    if enabled:
        file.unlink(missing_ok=True)
    else:
        atomic(file, '[device-ostojaos-wifi-' + mac.replace(':', '') + ']\nmatch-device=mac:' + mac + '\nmanaged=0\n', mode=0o644)
    adapter.manager.Reload(1)
    adapter.interface(path, 'org.freedesktop.DBus.Properties').Set(n.NM + '.Device', 'Managed', adapter.dbus.Boolean(enabled))
    if not enabled:
        command(['ip', 'link', 'set', 'dev', name, 'down'], timeout=10)
    elif radio(adapter)['enabled'] and adapter_radio(adapter, name)['hardwareEnabled']:
        for _ in range(40):
            if int(adapter.device(name)[1]['State']) >= 30:
                break
            time.sleep(.25)
        else:
            raise Rejected('Wi-Fi adapter did not become available; check its hardware switch')


def snapshot(adapter):
    rows = []
    for path in adapter.devices():
        props = adapter.properties(path, n.NM + '.Device')
        if int(props['DeviceType']) == 2:
            name = str(props['Interface'])
            file, mac = policy_file(adapter, name)
            rows.append({'name': name, 'mac': mac, 'disabled': file.exists(), 'managed': bool(props['Managed'])})
    return {'global': radio(adapter)['enabled'], 'devices': rows}


def enable(adapter, name):
    require(adapter_radio(adapter, name)['hardwareEnabled'], 'Wi-Fi is blocked by a hardware switch')
    if not radio(adapter)['enabled']:
        # Preserve other adapters' off state when migrating the legacy global switch.
        for row in snapshot(adapter)['devices']:
            if row['managed'] and not row['disabled']:
                configure(adapter, row['name'], False)
        set_radio(adapter, True)
    if disabled(adapter, name):
        configure(adapter, name, True)


def restore_radios(adapter, before):
    for row in before['devices']:
        try:
            file, mac = policy_file(adapter, row['name'])
        except adapter.dbus.DBusException:
            file = CONFIG / ('90-ostojaos-wifi-' + row['mac'].replace(':', '') + '.conf')
            if not row['disabled']:
                file.unlink(missing_ok=True)
            else:
                atomic(file, '[device-ostojaos-wifi-' + row['mac'].replace(':', '') + ']\nmatch-device=mac:' + row['mac'] + '\nmanaged=0\n', mode=0o644)
            continue
        require(mac == row['mac'], 'A network adapter was replaced; check its settings')
        if row['disabled'] != file.exists():
            configure(adapter, row['name'], not row['disabled'])
    adapter.manager.Reload(1)
    if radio(adapter)['enabled'] != before['global']:
        set_radio(adapter, before['global'])


def device(adapter, name):
    path, props = adapter.device(name)
    require(int(props['DeviceType']) == 2 and (props['Managed'] or disabled(adapter, name)), 'Select a managed Wi-Fi adapter')
    return path, props


def security(props):
    flags = int(props.get('WpaFlags', 0)) | int(props.get('RsnFlags', 0))
    if flags & 0x400:
        return 'wpa3'
    if flags & 0x100:
        return 'wpa2'
    if flags & 0x800 or flags & 0x1000:
        return 'owe'
    if flags & 0x200 or flags & 0x2000:
        return 'enterprise'
    return 'unsupported' if int(props.get('Flags', 0)) & 1 else 'open'


def ssid(raw):
    return bytes(raw).decode('utf-8', errors='replace')


def points(adapter, path):
    rows = []
    wireless = adapter.interface(path, n.NM + '.Device.Wireless')
    for ap in wireless.GetAllAccessPoints():
        try:
            props = adapter.properties(ap, n.NM + '.AccessPoint')
            if not props['Ssid']:
                continue
            rows.append({'id': str(ap), 'ssid': ssid(props['Ssid']), 'ssidHex': bytes(props['Ssid']).hex(),
                         'security': security(props), 'signal': int(props['Strength']),
                         'frequency': int(props['Frequency']), 'bssid': str(props['HwAddress'])})
        except adapter.dbus.DBusException:
            continue
    return sorted(rows, key=lambda row: (-row['signal'], row['ssid']))


def saved(adapter, props):
    rows = []
    for path in props.get('AvailableConnections', []):
        settings = adapter.interface(path, n.NM + '.Settings.Connection').GetSettings()
        if settings.get('connection', {}).get('type') != '802-11-wireless' or settings.get('802-11-wireless', {}).get('mode') == 'ap':
            continue
        rows.append({'uuid': str(settings['connection']['uuid']), 'name': str(settings['connection']['id']),
                     'ssid': ssid(settings.get('802-11-wireless', {}).get('ssid', []))})
    return rows


def inventory(adapter, rows):
    result = {**radio(adapter), 'present': any(row['kind'] == 'wifi' for row in rows)}
    for row in rows:
        if row['kind'] != 'wifi':
            continue
        try:
            path, props = device(adapter, row['name'])
            wireless = adapter.properties(path, n.NM + '.Device.Wireless')
            row['wifi'] = {'networks': points(adapter, path), 'saved': saved(adapter, props),
                           'activeAP': str(wireless['ActiveAccessPoint']), 'lastScan': int(wireless['LastScan']), 'mode': int(wireless['Mode'])}
            if int(wireless['Mode']) == 3:
                stations = command(['iw', 'dev', row['name'], 'station', 'dump'], timeout=5)
                row['wifi']['clients'] = sum(line.startswith('Station ') for line in stations.splitlines())
        except (Rejected, adapter.dbus.DBusException):
            row['wifi'] = {'networks': [], 'saved': [], 'activeAP': '/', 'lastScan': -1}
        row['wifi'].update(adapter_radio(adapter, row['name']))
    return result


def selection(adapter, path, props, params):
    connection = params.get('connection')
    if connection:
        require(isinstance(connection, str), 'Invalid saved Wi-Fi connection')
        for profile in props.get('AvailableConnections', []):
            settings = adapter.interface(profile, n.NM + '.Settings.Connection').GetSettings()
            if settings.get('connection', {}).get('uuid') == connection and settings['connection']['type'] == '802-11-wireless':
                return {'profile': str(profile), 'hash': n.signature(settings)}
        raise Rejected('Saved Wi-Fi connection is no longer available')
    ap_id = params.get('accessPoint')
    if ap_id:
        found = next((row for row in points(adapter, path) if row['id'] == ap_id), None)
        require(found is not None and found['ssidHex'] == params.get('ssidHex'), 'Wi-Fi network changed; refresh the list')
        raw = bytes.fromhex(found['ssidHex'])
        kind = found['security']
    else:
        name = params.get('ssid')
        require(isinstance(name, str) and 1 <= len(name.encode('utf-8')) <= 32 and '\x00' not in name, 'Wi-Fi name must contain 1 to 32 bytes')
        raw = name.encode('utf-8')
        kind = params.get('security')
    require(kind in ('open', 'owe', 'wpa2', 'wpa3'), 'This Wi-Fi security type is not supported yet')
    password = params.get('password', '')
    require(isinstance(password, str) and '\x00' not in password, 'Invalid Wi-Fi password')
    if kind in ('wpa2', 'wpa3'):
        size = len(password.encode('utf-8'))
        require((8 if kind == 'wpa2' else 1) <= size <= 63 or (kind == 'wpa2' and re.fullmatch('[0-9a-fA-F]{64}', password)), 'Invalid Wi-Fi password length')
    else:
        require(not password, 'This Wi-Fi network does not use a password')
    return {'ssid': raw, 'security': kind, 'accessPoint': ap_id or '/', 'password': password, 'hidden': not bool(ap_id)}


def plan(adapter, action, params, user):
    state = n.current(adapter)
    require(not state or state['status'] not in ('applying', 'pending'), 'Confirm or roll back the pending network change first')
    name = params.get('interface')
    if action != 'network.wifi.scan':
        groups = n.sharing.load()
        if action != 'network.wifi.radio':
            require(not any(name in [g['source'], *g['outputs']] for g in groups), 'Edit this interface through its sharing group')
    path, props = device(adapter, name)
    radios = adapter_radio(adapter, name)
    extra = None
    if action == 'network.wifi.radio':
        require(type(params.get('enabled')) is bool, 'Invalid network option')
        require(params['enabled'] != radios['enabled'], 'Network settings have not changed')
        require(not params['enabled'] or radios['hardwareEnabled'], 'Wi-Fi is blocked by a hardware switch')
    else:
        require(radios['enabled'] and radios['hardwareEnabled'], 'Enable Wi-Fi before scanning or connecting')
        if action == 'network.wifi.connect':
            extra = selection(adapter, path, props, params)
            # The passphrase is transported only through stdin/D-Bus, never in task results or recovery state.
            extra = {key: value for key, value in extra.items() if key not in ('password', 'ssid')}
        elif action == 'network.wifi.disconnect':
            require(props['ActiveConnection'] != '/', 'Wi-Fi adapter is not connected')
    return {'target': name, 'confirmation': name, 'details': [name],
            'fingerprint': n.fingerprint(action, params, [path, radios, str(props['ActiveConnection']), extra])}


def resume_sharing(adapter, name):
    for group in n.sharing.load():
        if group['enabled'] and name in [group['source'], *group['outputs']]:
            ident = group['profiles'].get(name) or group['previous'].get(name)
            if ident:
                profiles = n.sharing.profiles(adapter)
                require(ident in profiles, 'Sharing configuration changed externally; review it again')
                adapter.manager.ActivateConnection(profiles[ident][0], adapter.device(name)[0], '/')


def remember(state):
    n.save_state(state)
    RECOVERY.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    import os
    import tempfile
    fd, temp = tempfile.mkstemp(dir=RECOVERY.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(state, stream)
        os.replace(temp, RECOVERY)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def arm(state):
    command(['systemd-run', '--quiet', '--collect', '--unit=ostojaos-wifi-rollback-' + state['id'],
             '--on-active=' + str(n.TIMEOUT) + 's', '--timer-property=AccuracySec=1s',
             '--property=Restart=on-failure', '--property=RestartSec=3s',
             '/usr/bin/python3', '-B', HELPER, '--rollback', state['id']], timeout=15)


def disarm(state):
    command(['systemctl', 'stop', 'ostojaos-wifi-rollback-' + state['id'] + '.timer'], accepted=(0, 5), timeout=15)


def rollback(adapter, state):
    if 'adaptersBefore' in state:
        restore_radios(adapter, state['adaptersBefore'])
    else:
        set_radio(adapter, state['radioBefore'])
    if state['radioBefore']:
        for _ in range(20):
            try:
                _, props = device(adapter, state['interface'])
            except (Rejected, adapter.dbus.DBusException):
                break
            if int(props['State']) >= 30:
                break
            time.sleep(.5)
    if state['checkpoint'] in adapter.checkpoints():
        adapter.rollback(state['checkpoint'])
    if state.get('newUUID'):
        settings_api = adapter.interface(n.NM_PATH + '/Settings', n.NM + '.Settings')
        for profile in settings_api.ListConnections():
            api = adapter.interface(profile, n.NM + '.Settings.Connection')
            settings = api.GetSettings()
            if settings['connection']['uuid'] == state['newUUID']:
                api.Delete()
    state['status'] = 'rolled-back'
    remember(state)


def current(adapter, state):
    if state['status'] in ('applying', 'pending') and (state['deadline'] <= time.time() or state['boot'] != Path('/proc/sys/kernel/random/boot_id').read_text().strip()):
        rollback(adapter, state)
        state['status'] = 'expired'
        remember(state)
    return state


def new_settings(adapter, choice, name, new_uuid):
    d = adapter.dbus
    fields = {
        'connection': {'id': ssid(choice['ssid']), 'uuid': new_uuid, 'type': '802-11-wireless', 'interface-name': name, 'autoconnect': d.Boolean(False)},
        '802-11-wireless': {'ssid': d.ByteArray(choice['ssid']), 'mode': 'infrastructure', 'hidden': d.Boolean(choice['hidden'])},
        'ipv4': {'method': 'auto', 'route-metric': d.Int64(600)},
        'ipv6': {'method': 'auto', 'route-metric': d.Int64(600)},
    }
    if choice['security'] != 'open':
        fields['802-11-wireless-security'] = {'key-mgmt': {'wpa2': 'wpa-psk', 'wpa3': 'sae', 'owe': 'owe'}[choice['security']]}
        if choice['password']:
            fields['802-11-wireless-security'].update(psk=choice['password'], **{'psk-flags': d.UInt32(0)})
    return d.Dictionary({key: d.Dictionary(value, signature='sv') for key, value in fields.items()}, signature='sa{sv}')


def execute(adapter, action, params, user):
    plan(adapter, action, params, user)
    path, props = device(adapter, params['interface'])
    if action == 'network.wifi.scan':
        wireless = adapter.interface(path, n.NM + '.Device.Wireless')
        previous = adapter.properties(path, n.NM + '.Device.Wireless')['LastScan']
        try:
            wireless.RequestScan(adapter.dbus.Dictionary(signature='sv'))
        except adapter.dbus.DBusException:
            raise Rejected('Wi-Fi scan is unavailable or was requested too recently; try again shortly')
        for _ in range(24):
            if adapter.properties(path, n.NM + '.Device.Wireless')['LastScan'] != previous:
                break
            time.sleep(.5)
        return {'message': 'Wi-Fi scan requested'}
    choice = selection(adapter, path, props, params) if action == 'network.wifi.connect' else None
    paths = [path]
    checkpoint = str(adapter.manager.CheckpointCreate(paths, n.TIMEOUT + 30, 0))
    state = {'id': uuid.uuid4().hex, 'kind': action, 'interface': params['interface'], 'user': user,
             'status': 'applying', 'checkpoint': checkpoint, 'deadline': time.time() + n.TIMEOUT, 'addresses': [],
             'radioBefore': radio(adapter)['enabled'], 'boot': Path('/proc/sys/kernel/random/boot_id').read_text().strip()}
    if action == 'network.wifi.radio':
        state['adaptersBefore'] = snapshot(adapter)
    if choice and 'profile' not in choice:
        state['newUUID'] = str(uuid.uuid4())
    remember(state)
    try:
        arm(state)
        if action == 'network.wifi.radio':
            if params['enabled']:
                enable(adapter, params['interface'])
                resume_sharing(adapter, params['interface'])
            else:
                configure(adapter, params['interface'], False)
            state['radioAfter'] = params['enabled']
        elif action == 'network.wifi.disconnect':
            adapter.interface(path, n.NM + '.Device').Disconnect()
        else:
            if 'profile' in choice:
                profile = choice['profile']
                active = adapter.manager.ActivateConnection(profile, path, '/')
            else:
                profile, active, _ = adapter.manager.AddAndActivateConnection2(new_settings(adapter, choice, params['interface'], state['newUUID']), path, choice['accessPoint'], adapter.dbus.Dictionary({'persist': 'memory'}, signature='sv'))
            for _ in range(90):
                active_state = int(adapter.properties(active, n.NM + '.Connection.Active')['State'])
                if active_state == 2:
                    break
                require(active_state not in (3, 4), 'Wi-Fi connection failed; check password, signal and router settings')
                time.sleep(.5)
            else:
                raise Rejected('Wi-Fi connection timed out; check password, signal and router settings')
            state['profile'] = str(profile)
            state['profileHash'] = n.signature(adapter.interface(profile, n.NM + '.Settings.Connection').GetSettings())
        state['status'] = 'pending'
        remember(state)
    except Exception as error:
        rollback(adapter, state)
        disarm(state)
        if isinstance(error, Rejected):
            raise
        raise Rejected('Wi-Fi operation failed; previous settings were restored') from None
    return {'message': 'Network changes await confirmation', 'change': n.pending_info(state)}


def confirm(adapter, state):
    require(state['checkpoint'] in adapter.checkpoints(), 'This network change has expired or is no longer pending')
    if state['kind'] == 'network.wifi.radio':
        require(adapter_radio(adapter, state['interface'])['enabled'] == state['radioAfter'], 'Network configuration changed externally; roll back and review it again')
    elif state['kind'] == 'network.wifi.connect':
        path, profile, settings, applied, version = adapter.active(state['interface'])
        require(profile == state['profile'] and n.signature(settings) == state['profileHash'], 'Network configuration changed externally; roll back and review it again')
        if state.get('newUUID'):
            api = adapter.interface(profile, n.NM + '.Settings.Connection')
            api.Save()
            command(['nmcli', 'connection', 'modify', 'uuid', state['newUUID'], 'connection.autoconnect', 'yes'], timeout=20)
    else:
        _, props = device(adapter, state['interface'])
        require(props['ActiveConnection'] == '/', 'Network configuration changed externally; roll back and review it again')
    adapter.destroy(state['checkpoint'])
    state['status'] = 'confirmed'
    remember(state)
    disarm(state)


def recover(expected=None):
    with n.locked():
        if not RECOVERY.exists():
            return
        state = json.loads(RECOVERY.read_text())
        if state['status'] not in ('applying', 'pending') or (expected and state['id'] != expected):
            return
        if not expected and state['boot'] == Path('/proc/sys/kernel/random/boot_id').read_text().strip() and state['deadline'] > time.time():
            return
        rollback(n.Adapter(), state)
        state['status'] = 'expired'
        remember(state)


if __name__ == '__main__':
    if sys.argv[1:] == ['--remove']:
        adapter = n.Adapter()
        for row in snapshot(adapter)['devices']:
            if row['disabled']: configure(adapter, row['name'], True)
        for file in CONFIG.glob('90-ostojaos-wifi-*.conf'): file.unlink()
        adapter.manager.Reload(1)
        raise SystemExit(0)
    require(sys.argv[1:] == ['--recover'] or (len(sys.argv) == 3 and sys.argv[1] == '--rollback' and re.fullmatch('[a-f0-9]{32}', sys.argv[2])), 'Invalid recovery request')
    recover(sys.argv[2] if len(sys.argv) == 3 else None)
