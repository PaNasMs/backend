import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import sys
import time
import uuid
from common import Rejected, require, command, json_command, atomic

ACTIONS = {'network.share.save', 'network.share.start', 'network.share.stop', 'network.share.delete', 'network.share.wifi', 'network.share.remove-port'}
import network as n
ROOT = Path('/var/lib/panasms-agent/network-sharing')
HELPER = '/usr/lib/panasms/management/network_sharing.py'


def load():
    path = ROOT / 'groups.json'
    return json.loads(path.read_text()) if path.exists() else []


def store(groups):
    atomic(ROOT / 'groups.json', json.dumps(groups))


def remember(state):
    n.save_state(state)
    atomic(ROOT / 'pending.json', json.dumps(state))


def profiles(a):
    result = {}
    for path in a.interface(n.NM_PATH + '/Settings', n.NM + '.Settings').ListConnections():
        settings = a.interface(path, n.NM + '.Settings.Connection').GetSettings()
        result[str(settings['connection']['uuid'])] = (str(path), settings)
    return result


def physical(name):
    path = Path('/sys/class/net') / name
    phy = path / 'phy80211'
    return {'identity': str((path / 'device').resolve()) if (path / 'device').exists() else name,
            'phy': phy.resolve().name if phy.exists() else ''}


def ap_channels(info):
    primary = set(range(36, 65, 4)) | set(range(100, 145, 4)) | set(range(149, 178, 4))
    channels = {}
    for line in info.splitlines():
        match = re.search(r'\* (\d+(?:\.\d+)?) MHz \[(\d+)\]', line)
        if not match or any(word in line for word in ('disabled', 'no IR', 'radar detection')):
            continue
        frequency, channel = float(match[1]), int(match[2])
        band = 'bg' if 2400 < frequency < 2500 and 1 <= channel <= 13 else 'a' if 5000 < frequency < 5900 and channel in primary else None
        if band:
            channels.setdefault(band, []).append(channel)
    return channels


def capabilities(a, name, props):
    result = physical(name)
    result.update(ap=False, bands=[], concurrent=False, channels={})
    if int(props['DeviceType']) != 2:
        return result
    wifi = a.properties(a.device(name)[0], n.NM + '.Device.Wireless')
    result['ap'] = bool(int(wifi.get('WirelessCapabilities', 0)) & 0x40)
    if result['phy'] and shutil.which('iw'):
        info = command(['iw', 'phy', result['phy'], 'info'], timeout=5)
        result['channels'] = ap_channels(info)
        result['bands'] = list(result['channels'])
        combos = info.split('valid interface combinations:')[-1].split('Device supports')[0]
        result['concurrent'] = any('managed' in block and re.search(r'\bAP\b', block) for block in combos.split('*'))
    return result


def inventory(a, rows):
    groups = load()
    used = {name: g['id'] for g in groups for name in [g['source'], *g['outputs']]}
    for row in rows:
        row['sharingGroup'] = used.get(row['name'])
        if a and row['kind'] in ('ethernet', 'wifi'):
            try:
                _, props = a.device(row['name'])
                row['sharing'] = capabilities(a, row['name'], props)
                row['sharing']['available'] = bool(props['Managed']) or int(props['DeviceType']) == 2 and n.wifi.disabled(a, row['name'])
            except (Rejected, a.dbus.DBusException):
                row['sharing'] = {'available': False, 'ap': False, 'bands': []}
    by_name = {r['name']: r for r in rows}
    visible = []
    for g in groups:
        active = g['enabled'] and by_name.get(g['bridge'], {}).get('nmState') == 100
        source = by_name.get(g['source'], {})
        ready = source.get('nmState') == 100 and (source.get('carrier', True) if g['mode'] == 'bridge' else any('.' in address for address in source.get('addresses', [])))
        visible.append({k: g[k] for k in ('id', 'name', 'source', 'outputs', 'mode', 'wifi', 'enabled', 'autostart', 'bridge')})
        failed = any(name not in by_name or by_name[name].get('nmState') == 120 or name in g['wifi'] and by_name[name].get('nmState') != 100 for name in g['outputs'])
        visible[-1].update(status='stopped' if not g['enabled'] else 'error' if failed else 'active' if active and ready else 'upstream' if active else 'error', addresses=by_name.get(g['bridge'], {}).get('addresses', []))
    return {'groups': visible, 'ready': all(shutil.which(tool) for tool in ('iw', 'dnsmasq', 'ip', 'nft'))}


def valid_name(value):
    require(isinstance(value, str) and 1 <= len(value.strip()) <= 64 and not any(ord(c) < 32 for c in value), 'Invalid sharing name')
    return value.strip()


def selected_channel(conf, channels):
    channel = conf.get('channel', 0)
    require(type(channel) is int and (channel == 0 or channel in channels), 'This Wi-Fi channel is not available for an access point')
    return channel or channels[0]


def wifi_params(params, old):
    require(old is not None, 'Sharing group no longer exists')
    name = params.get('interface')
    require(name in old['wifi'], 'Select a Wi-Fi access point from this sharing group')
    conf = params.get('wifi')
    require(isinstance(conf, dict), 'Invalid network option')
    return {**old, 'wifi': {**old['wifi'], name: conf}}


def without_port(old, name):
    require(old is not None and name in old['outputs'], 'Select a recipient interface from this sharing group')
    return {**old, 'outputs': [x for x in old['outputs'] if x != name],
            **{key: {k: v for k, v in old[key].items() if k != name}
               for key in ('wifi', 'profiles', 'identities', 'previous')}}


def matches_adapter(a, g, name, saved):
    ident = g.get('profiles', {}).get(name)
    if ident in saved:
        settings = saved[ident][1]
        kind = settings['connection']['type']
        bound = settings.get(kind, {}).get('mac-address')
        if bound:
            path, props = a.device(name)
            actual = a.properties(path, n.NM + '.Device.Wireless').get('PermHwAddress') if int(props['DeviceType']) == 2 else props.get('HwAddress')
            return bytes(bound).hex() == str(actual).replace(':', '').lower()
    return physical(name)['identity'] == g['identities'][name]


def detach_port(a, g, name):
    try: path, props = a.device(name)
    except a.dbus.DBusException: return
    require(matches_adapter(a, g, name, profiles(a)), 'A network adapter was replaced; recreate the sharing group')
    if props['ActiveConnection'] != '/':
        active = a.properties(props['ActiveConnection'], n.NM + '.Connection.Active')
        require(str(active['Uuid']) in (g['profiles'][name], g['previous'].get(name)), 'Sharing configuration changed externally; roll back and review it again')
        if str(active['Uuid']) == g['profiles'][name]:
            a.interface(path, n.NM + '.Device').Disconnect()
    if name in g['wifi']:
        command(['ip', 'link', 'set', 'dev', name, 'down'], timeout=10)
        command(['iw', 'dev', name, 'set', 'type', 'managed'], timeout=10)
        if not n.wifi.disabled(a, name):
            command(['ip', 'link', 'set', 'dev', name, 'up'], timeout=10)
    restore(a, {name: g['previous'].get(name)})


def review(a, params, old=None):
    source = params.get('source')
    outputs = params.get('outputs')
    require(isinstance(outputs, list) and 1 <= len(outputs) <= 16 and all(isinstance(x, str) for x in outputs), 'Select at least one destination interface')
    require(len(set(outputs)) == len(outputs) and source not in outputs, 'Source and destination interfaces must be different')
    names = [source, *outputs]
    groups = load()
    require(not any(set(names) & {g['source'], *g['outputs']} for g in groups if not old or g['id'] != old['id']), 'An interface is already used by another sharing group')
    mode = params.get('mode')
    require(mode in ('bridge', 'nat'), 'Invalid sharing mode')
    radios = []
    devices = {}
    aps = {}
    require(isinstance(params.get('wifi', {}), dict), 'Invalid network option')
    snapshot = []
    for name in names:
        path, props = a.device(name)
        require(int(props['DeviceType']) in (1, 2) and (props['Managed'] or int(props['DeviceType']) == 2 and n.wifi.disabled(a, name)), 'Select a managed Ethernet or Wi-Fi interface')
        cap = capabilities(a, name, props)
        if cap['phy']:
            require(cap['phy'] not in radios, 'These interfaces share one radio; choose a separate Wi-Fi adapter')
            radios.append(cap['phy'])
        if old and name in old['identities']:
            require(matches_adapter(a, old, name, profiles(a)), 'A network adapter was replaced; recreate the sharing group')
        devices[name] = (path, props, cap)
        active_hash = None
        if props['ActiveConnection'] != '/':
            active = a.properties(props['ActiveConnection'], n.NM + '.Connection.Active')
            active_hash = n.signature(a.interface(active['Connection'], n.NM + '.Settings.Connection').GetSettings())
        snapshot.append([name, cap, str(props['ActiveConnection']), active_hash])
        if name in outputs and int(props['DeviceType']) == 2:
            require(cap['ap'] and cap['bands'], 'This Wi-Fi adapter cannot create an access point on permitted channels')
            radio = n.wifi.adapter_radio(a, name)
            require(radio['hardwareEnabled'], 'Wi-Fi is blocked by a hardware switch')
            conf = params.get('wifi', {}).get(name, {})
            require(isinstance(conf, dict), 'Invalid network option')
            ssid = conf.get('ssid', '')
            require(isinstance(ssid, str) and 1 <= len(ssid.encode()) <= 32 and '\x00' not in ssid, 'Wi-Fi name must contain 1 to 32 bytes')
            password = conf.get('password', '')
            kept = old and name in old['wifi'] and not password
            require(kept or isinstance(password, str) and 8 <= len(password) <= 63 and all(32 <= ord(c) <= 126 for c in password), 'Use a Wi-Fi password of 8 to 63 printable ASCII characters')
            band = conf.get('band', 'bg')
            require(band in cap['bands'], 'This Wi-Fi band is not available for an access point')
            aps[name] = {'ssid': ssid, 'band': band, 'channel': selected_channel(conf, cap['channels'][band])}
    _, source_props, _ = devices[source]
    require(mode != 'bridge' or int(source_props['DeviceType']) == 1, 'Transparent Wi-Fi bridging is not verified with your router; use a separate network')
    if not old or not old['enabled']:
        require(int(source_props['State']) == 100, 'Connect the source interface before sharing')
    if mode == 'nat':
        if old and old.get('subnet'):
            routes = json_command(['ip', '-j', '-4', 'route', 'show', 'table', 'all'])
            require(not any(ipaddress.ip_network(old['subnet']).overlaps(ipaddress.ip_network(r['dst'], strict=False)) for r in routes if r.get('dst') not in (None, 'default') and r.get('dev') != old['bridge']), 'The sharing subnet now overlaps another network; recreate the sharing group')
        rules = json_command(['ip', '-j', '-4', 'rule', 'show'])
        require(not any(0 < r.get('priority', 0) < 18000 for r in rules), 'Existing policy routing requires manual review before sharing')
    if mode == 'bridge' and (not old or old['mode'] != 'bridge' or not old['enabled']):
        _, _, settings, applied, _ = a.active(source)
        require(n.editable(settings), 'Source uses advanced or unsaved settings; save a simple IP configuration first')
        require('802-1x' not in settings, 'Authenticated Ethernet bridging requires manual configuration')
        require(not settings['connection'].get('master') and not settings['connection'].get('controller'), 'Source already belongs to a bridge or bond')
    require(type(params.get('autostart')) is bool, 'Invalid network option')
    require(all(shutil.which(tool) for tool in ('dnsmasq', 'ip', 'nft', 'iw')), 'Install the network sharing dependencies first')
    return {'name': valid_name(params.get('name')), 'source': source, 'outputs': outputs, 'mode': mode, 'wifi': aps, 'autostart': params['autostart'], 'identities': {name: dev[2]['identity'] for name, dev in devices.items()}}, snapshot


def plan(a, action, params, user):
    state = n.current(a)
    require(not state or state['status'] not in ('applying', 'pending'), 'Confirm or roll back the pending network change first')
    old = next((g for g in load() if g['id'] == params.get('id')), None)
    require(not params.get('id') or old is not None, 'Sharing group no longer exists')
    if action in ('network.share.save', 'network.share.wifi'):
        conf, snapshot = review(a, wifi_params(params, old) if action == 'network.share.wifi' else params, old)
        target = conf['source']
    else:
        require(old is not None, 'Sharing group no longer exists')
        require(action != 'network.share.start' or not old['enabled'], 'Sharing is already enabled')
        require(action != 'network.share.stop' or old['enabled'], 'Sharing is already stopped')
        if action == 'network.share.remove-port':
            without_port(old, params.get('interface'))
        if action == 'network.share.start':
            review(a, old, old)
        target = old['source']
        snapshot = old
    return {'target': target, 'confirmation': target, 'details': [target], 'fingerprint': n.fingerprint(action, params, snapshot)}


def clone(d, settings):
    return d.Dictionary({key: d.Dictionary(dict(value), signature='sv') for key, value in settings.items()}, signature='sa{sv}')


def profile(a, fields):
    return a.dbus.Dictionary({key: a.dbus.Dictionary(value, signature='sv') for key, value in fields.items()}, signature='sa{sv}')


def new_profile(a, fields, state, role):
    d = a.dbus
    ident = str(uuid.uuid4())
    fields['connection'].update(uuid=ident, autoconnect=d.Boolean(False))
    state['newUUIDs'].append(ident)
    remember(state)
    path = a.interface(n.NM_PATH + '/Settings', n.NM + '.Settings').AddConnectionUnsaved(profile(a, fields))
    state['newProfiles'][role] = ident
    remember(state)
    return str(path)


def original(a, names):
    result = {}
    for name in names:
        try: _, props = a.device(name)
        except a.dbus.DBusException:
            result[name] = None
            continue
        if props['ActiveConnection'] != '/':
            active = a.properties(props['ActiveConnection'], n.NM + '.Connection.Active')
            result[name] = str(active['Uuid'])
        else: result[name] = None
    return result


def restore(a, previous):
    saved = profiles(a)
    for name, ident in previous.items():
        try: path, props = a.device(name)
        except a.dbus.DBusException: continue
        if int(props['DeviceType']) == 2 and n.wifi.disabled(a, name): continue
        if ident and ident in saved:
            if props['ActiveConnection'] != '/' and str(a.properties(props['ActiveConnection'], n.NM + '.Connection.Active')['Uuid']) == ident and int(props['State']) == 100:
                continue
            active = a.manager.ActivateConnection(saved[ident][0], path, '/')
            for _ in range(30):
                if int(a.properties(active, n.NM + '.Connection.Active')['State']) in (2, 4): break
                time.sleep(.5)
        elif props['ActiveConnection'] != '/':
            a.interface(path, n.NM + '.Device').Disconnect()


def activate(a, g, allow_missing=False):
    saved = profiles(a)
    if g['mode'] == 'nat': routing(g)
    active_ids = {str(a.properties(path, n.NM + '.Connection.Active')['Uuid']) for path in a.properties(n.NM_PATH, n.NM)['ActiveConnections']}
    if g['profiles']['bridge'] not in active_ids:
        a.manager.ActivateConnection(saved[g['profiles']['bridge']][0], '/', '/')
    for name in ([g['source']] if g['mode'] == 'bridge' else []) + g['outputs']:
        try:
            path, props = a.device(name)
            require(matches_adapter(a, g, name, saved), 'A network adapter was replaced; recreate the sharing group')
            if int(props['DeviceType']) == 2 and (n.wifi.disabled(a, name) or not n.wifi.adapter_radio(a, name)['enabled'] or not n.wifi.adapter_radio(a, name)['hardwareEnabled']): continue
            if not props.get('Managed', True): continue
            if g['profiles'][name] not in active_ids:
                a.manager.ActivateConnection(saved[g['profiles'][name]][0], path, '/')
        except (a.dbus.DBusException, Rejected):
            if not allow_missing: raise


def deactivate(a, g):
    saved = profiles(a)
    for active in a.properties(n.NM_PATH, n.NM)['ActiveConnections']:
        props = a.properties(active, n.NM + '.Connection.Active')
        if str(props['Uuid']) in g['profiles'].values(): a.manager.DeactivateConnection(active)
    restore(a, g['previous'])
    cleanup_routing(g)


def delete_profiles(a, ids):
    saved = profiles(a)
    for ident in ids:
        if ident in saved: a.interface(saved[ident][0], n.NM + '.Settings.Connection').Delete()


def choose_subnet(groups):
    routes = json_command(['ip', '-j', '-4', 'route', 'show', 'table', 'all'])
    used = [ipaddress.ip_network(r['dst'], strict=False) for r in routes if r.get('dst') not in (None, 'default')]
    used += [ipaddress.ip_network(g['subnet']) for g in groups if g.get('subnet')]
    for index in range(42, 250):
        candidate = ipaddress.ip_network(f'10.{index}.0.0/24')
        if not any(candidate.overlaps(net) for net in used): return str(candidate)
    raise Rejected('No free private subnet found for sharing')


def build(a, conf, params, old, state):
    d = a.dbus
    groups = load()
    slots = [i for i in range(100) if all(g.get('slot') != i for g in groups)]
    slot = next((i for i in slots if not json_command(['ip', '-j', '-4', 'route', 'show', 'table', str(28000 + i)], accepted=(0, 2)) and not any(r.get('priority') == 18000+i for r in json_command(['ip','-j','-4','rule','show']))), None)
    require(slot is not None, 'No free routing table available for sharing')
    g = {**conf, 'id': old['id'] if old else uuid.uuid4().hex[:12], 'enabled': True, 'slot': slot,
         'bridge': 'osbr' + uuid.uuid4().hex[:8], 'previous': original(a, [conf['source'], *conf['outputs']])}
    if old:
        g['previous'].update({k: v for k, v in old['previous'].items() if k in [conf['source'], *conf['outputs']]})
    conn = {'id': 'PaNasMs ' + g['name'], 'type': 'bridge', 'interface-name': g['bridge']}
    fields = {'connection': conn, 'bridge': {'stp': d.Boolean(True)}, 'ipv4': {'method': 'shared'}, 'ipv6': {'method': 'disabled'}}
    if g['mode'] == 'bridge':
        saved = profiles(a)
        source_settings = saved[g['previous'][g['source']]][1]
        for key in ('ipv4', 'ipv6'): fields[key] = dict(source_settings.get(key, {'method': 'auto'}))
        # Preserve the upstream MAC so DHCP reservations and the management address survive bridging.
        fields['bridge']['mac-address'] = d.ByteArray(bytes.fromhex(str(a.device(g['source'])[1]['HwAddress']).replace(':', '')))
    else:
        g['subnet'] = old['subnet'] if old and old.get('subnet') else choose_subnet(groups)
        address = str(next(ipaddress.ip_network(g['subnet']).hosts()))
        fields['ipv4']['address-data'] = d.Array([d.Dictionary({'address': address, 'prefix': d.UInt32(24)}, signature='sv')], signature='a{sv}')
    new_profile(a, fields, state, 'bridge')
    for name in ([g['source']] if g['mode'] == 'bridge' else []) + g['outputs']:
        _, props = a.device(name)
        kind = '802-11-wireless' if int(props['DeviceType']) == 2 else '802-3-ethernet'
        fields = {'connection': {'id': 'PaNasMs ' + g['name'] + ' ' + name, 'type': kind, 'interface-name': name, 'master': g['bridge'], 'slave-type': 'bridge'}, kind: {}}
        if re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', str(props.get('HwAddress', ''))):
            fields[kind]['mac-address'] = d.ByteArray(bytes.fromhex(str(props['HwAddress']).replace(':', '')))
        if kind == '802-11-wireless':
            ap = g['wifi'][name]
            fields[kind].update(ssid=d.ByteArray(ap['ssid'].encode()), mode='ap', band=ap['band'], channel=d.UInt32(ap['channel']))
            password = params.get('wifi', {}).get(name, {}).get('password')
            if not password:
                prior = profiles(a)[old['profiles'][name]][0]
                password = str(a.interface(prior, n.NM + '.Settings.Connection').GetSecrets('802-11-wireless-security')['802-11-wireless-security']['psk'])
            fields['802-11-wireless-security'] = {'key-mgmt': 'wpa-psk', 'proto': d.Array(['rsn'], signature='s'), 'psk': password, 'psk-flags': d.UInt32(0)}
        new_profile(a, fields, state, name)
    g['profiles'] = dict(state['newProfiles'])
    return g


def routing(g):
    if g['mode'] != 'nat': return
    table = 28000 + g['slot']
    priority = 18000 + g['slot']
    rules = json_command(['ip', '-j', '-4', 'rule', 'show'])
    ours = [r for r in rules if r.get('priority') == priority]
    require(not ours or all(str(r.get('table')) == str(table) and r.get('iif') == g['bridge'] for r in ours), 'Routing rule conflicts with sharing')
    # The terminal unreachable route prevents fallback to an unrelated uplink when the source disappears.
    command(['ip', '-4', 'route', 'replace', 'unreachable', 'default', 'metric', '42760', 'table', str(table)])
    if not ours: command(['ip', '-4', 'rule', 'add', 'priority', str(priority), 'iif', g['bridge'], 'lookup', str(table)])
    source_routes = [r for r in json_command(['ip', '-j', '-4', 'route', 'show', 'table', 'main']) if r.get('dev') == g['source']]
    wanted = []
    for r in source_routes:
        if r.get('type', 'unicast') != 'unicast': continue
        args = [r.get('dst', 'default')]
        if r.get('gateway'): args += ['via', r['gateway']]
        args += ['dev', g['source'], 'metric', str(r.get('metric', 0))]
        if r.get('prefsrc'): args += ['src', r['prefsrc']]
        wanted.append(args)
    current = json_command(['ip', '-j', '-4', 'route', 'show', 'table', str(table)])
    for r in current:
        if r.get('type') == 'unreachable': continue
        if not any(r.get('dst', 'default') == x.get('dst', 'default') and r.get('gateway') == x.get('gateway') and r.get('dev') == g['source'] for x in source_routes):
            command(['ip', '-4', 'route', 'del', r.get('dst', 'default'), 'table', str(table)])
    for args in sorted(wanted, key=lambda x: x[0] == 'default'):
        command(['ip', '-4', 'route', 'replace', *args, 'table', str(table)])


def cleanup_routing(g):
    if g['mode'] != 'nat': return
    priority = 18000 + g['slot']
    table = 28000 + g['slot']
    rules = json_command(['ip', '-j', '-4', 'rule', 'show'])
    for r in rules:
        if r.get('priority') == priority and str(r.get('table')) == str(table) and r.get('iif') == g['bridge']:
            command(['ip', '-4', 'rule', 'del', 'priority', str(priority), 'iif', g['bridge'], 'lookup', str(table)])
    command(['ip', '-4', 'route', 'flush', 'table', str(table)], accepted=(0, 2))


def wait_active(a, g, timeout=90):
    # STP forwarding takes 30 seconds before bridge DHCP can begin (normally up to 45 seconds).
    deadline = time.monotonic() + timeout
    started = time.monotonic()
    while True:
        states = {name: int(a.device(name)[1]['State']) for name in [g['bridge'], *g['outputs']]}
        failed = [name for name, state in states.items() if state == 120 or name in g['wifi'] and state <= 30 and time.monotonic() - started >= 5]
        require(not failed, 'Sharing activation failed for ' + ', '.join(failed) + '; previous settings will be restored')
        pending_wifi = [name for name in g['wifi'] if states[name] != 100]
        if states[g['bridge']] == 100 and not pending_wifi:
            return
        if time.monotonic() >= deadline:
            if pending_wifi:
                raise Rejected('Sharing activation timed out while starting Wi-Fi access points ' + ', '.join(pending_wifi) + '; previous settings will be restored')
            raise Rejected('Sharing activation timed out while waiting for bridge ' + g['bridge'] + ' to obtain network settings; previous settings will be restored')
        time.sleep(.5)


def execute(a, action, params, user):
    plan(a, action, params, user)
    groups = load()
    old = next((g for g in groups if g['id'] == params.get('id')), None)
    effective = wifi_params(params, old) if action == 'network.share.wifi' else params
    conf = review(a, effective, old)[0] if action in ('network.share.save', 'network.share.wifi') else old
    names = set([conf['source'], *conf['outputs']] + ([old['source'], *old['outputs']] if old else []))
    paths = []
    for name in names:
        try: paths.append(a.device(name)[0])
        except a.dbus.DBusException:
            require(action in ('network.share.stop', 'network.share.delete', 'network.share.remove-port'), 'A network adapter is disconnected')
    if old and old['enabled']:
        try: paths.append(a.device(old['bridge'])[0])
        except a.dbus.DBusException: pass
    checkpoint = str(a.manager.CheckpointCreate(paths, 180, 0)) if paths else ''
    state = {'id': uuid.uuid4().hex, 'kind': action, 'interface': conf['source'], 'user': user,
             'status': 'applying', 'checkpoint': checkpoint, 'deadline': time.time() + 150, 'addresses': [],
             'boot': Path('/proc/sys/kernel/random/boot_id').read_text().strip(), 'before': groups,
             'previous': original(a, list(names)), 'newUUIDs': [], 'newProfiles': {},
             'adaptersBefore': n.wifi.snapshot(a)}
    remember(state)
    try:
        command(['systemd-run', '--quiet', '--collect', '--unit=panasms-share-rollback-' + state['id'], '--on-active=150s', '--timer-property=AccuracySec=1s', '--property=Restart=on-failure', '--property=RestartSec=3s', '/usr/bin/python3', '-B', HELPER, '--rollback', state['id']], timeout=15)
        if action in ('network.share.save', 'network.share.wifi'):
            g = build(a, conf, effective, old, state)
            if action == 'network.share.wifi': g['enabled'] = old['enabled']
        elif action == 'network.share.remove-port': g = without_port(old, params['interface'])
        else: g = {**old, 'enabled': action == 'network.share.start'}
        state['after'] = [x for x in groups if not old or x['id'] != old['id']] + ([] if action == 'network.share.delete' or action == 'network.share.remove-port' and not g['outputs'] else [g])
        state['working'] = g
        remember(state)
        removing = action == 'network.share.remove-port'
        if removing:
            detach_port(a, old, params['interface'])
            if not g['outputs']:
                if old['enabled']: deactivate(a, old)
                g['enabled'] = False
        elif old and old['enabled']: deactivate(a, old)
        if g['enabled'] and not removing:
            for name in [g['source'], *g['outputs']]:
                if int(a.device(name)[1]['DeviceType']) == 2:
                    n.wifi.enable(a, name)
            activate(a, g)
            wait_active(a, g, timeout=min(90, max(0, state['deadline'] - time.time() - 30)))
        state['profileHashes'] = {ident: n.signature(settings) for ident, (_, settings) in profiles(a).items() if ident in g['profiles'].values()}
        state['status'] = 'pending'
        remember(state)
        store(state['after'])
        if removing and g['outputs']:
            confirm(a, state)
            return {'message': 'Sharing recipient removed'}
    except Exception as error:
        rollback(a, state)
        if isinstance(error, Rejected): raise
        raise Rejected('Sharing could not start; previous settings were restored') from None
    return {'message': 'Network changes await confirmation', 'change': n.pending_info(state)}


def rollback(a, state):
    if 'adaptersBefore' in state: n.wifi.restore_radios(a, state['adaptersBefore'])
    if state['checkpoint'] in a.checkpoints(): a.rollback(state['checkpoint'])
    delete_profiles(a, state['newUUIDs'])
    if state.get('working') and state['working'].get('mode') == 'nat': cleanup_routing(state['working'])
    restore(a, state['previous'])
    store(state['before'])
    for g in state['before']:
        if g['enabled']: activate(a, g, allow_missing=True)
    state['status'] = 'rolled-back'
    remember(state)
    disarm(state)


def disarm(state):
    command(['systemctl', 'stop', 'panasms-share-rollback-' + state['id'] + '.timer'], accepted=(0, 5), timeout=15)


def confirm(a, state):
    require(not state['checkpoint'] or state['checkpoint'] in a.checkpoints(), 'This network change has expired or is no longer pending')
    if state['checkpoint']: a.extend(state['checkpoint'])
    saved = profiles(a)
    for ident, signature in state.get('profileHashes', {}).items():
        require(ident in saved and n.signature(saved[ident][1]) == signature, 'Sharing configuration changed externally; roll back and review it again')
    for ident in state['newUUIDs']:
        require(ident in saved, 'Sharing configuration changed externally; roll back and review it again')
        a.interface(saved[ident][0], n.NM + '.Settings.Connection').Save()
    if state['checkpoint']: a.destroy(state['checkpoint'])
    state['status'] = 'confirmed'
    remember(state)
    disarm(state)
    keep = {ident for g in state['after'] for ident in g['profiles'].values()}
    delete_profiles(a, [ident for g in state['before'] for ident in g['profiles'].values() if ident not in keep])


def current(a, state):
    if state['status'] in ('applying', 'pending') and (time.time() >= state['deadline'] or state['boot'] != Path('/proc/sys/kernel/random/boot_id').read_text().strip() or state['checkpoint'] and state['checkpoint'] not in a.checkpoints()):
        rollback(a, state)
        state['status'] = 'expired'
        remember(state)
    return state


def recover(expected=None):
    with n.locked():
        path = ROOT / 'pending.json'
        if path.exists():
            state = json.loads(path.read_text())
            if state['status'] in ('applying', 'pending') and (not expected or state['id'] == expected): rollback(n.Adapter(), state)


def service():
    recover()
    with n.locked():
        a = n.Adapter()
        boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        previous_boot = ROOT / 'boot'
        groups = load()
        if not previous_boot.exists() or previous_boot.read_text() != boot:
            for g in groups:
                if not g['autostart']: g['enabled'] = False
            store(groups)
            atomic(previous_boot, boot)
        for g in groups:
            if g['enabled'] and g['autostart']:
                try: activate(a, g, allow_missing=True)
                except Exception as error: print('Sharing startup failed: ' + type(error).__name__, flush=True)
    while True:
        with n.locked():
            state = n.read_state()
            if not state or state['status'] not in ('applying', 'pending'):
                for g in load():
                    if g['enabled']:
                        try: activate(a, g, allow_missing=True)
                        except Exception as error: print('Sharing route refresh failed: ' + type(error).__name__, flush=True)
        time.sleep(5)


if __name__ == '__main__':
    if sys.argv[1:] == ['--service']: service()
    elif sys.argv[1:] == ['--recover']: recover()
    elif len(sys.argv) == 3 and sys.argv[1] == '--rollback' and re.fullmatch('[a-f0-9]{32}', sys.argv[2]): recover(sys.argv[2])
    elif sys.argv[1:] == ['--remove']:
        recover()
        with n.locked():
            a = n.Adapter()
            for g in load():
                if g['enabled']: deactivate(a, g)
                delete_profiles(a, g['profiles'].values())
            store([])
    else: raise SystemExit('Invalid sharing helper invocation')
