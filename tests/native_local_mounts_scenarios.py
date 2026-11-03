#!/usr/bin/env python3
"""Private-chroot GO09B scenarios; outer VM/loop isolation is mandatory."""
import errno, hashlib, json, os, signal, subprocess, time
from pathlib import Path

def command(*args):
    return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT).strip()

def require_namespace():
    nonce = os.environ.get('PANASMS_GO09_NONCE', '')
    assert os.geteuid() == 0 and os.getpid() == 1
    assert len(nonce) == 32 and Path('/fixture/nonce').read_text() == nonce
    expected = os.environ.get('PANASMS_ACCEPTANCE_VM_UUID', '')
    assert expected and Path('/sys/class/dmi/id/product_uuid').read_text().strip().lower() == expected.lower()
    assert not json.loads(command('ip', '-j', 'route'))
    assert not json.loads(command('ip', '-6', '-j', 'route'))
    assert Path('/fixture/devices.json').stat().st_uid == 0

def invoke(mode, action, params, user='admin', plan=None):
    body = {'action': action, 'params': params}
    if mode == 'execute':
        if plan is None:
            plan = invoke('plan', action, params, user)
        assert not plan.get('error'), plan
        body.update(fingerprint=plan['fingerprint'], confirmation=plan['confirmation'])
    result = subprocess.run(['/usr/lib/panasms/panasms-system-helper', mode, user],
                            input=json.dumps(body), text=True, capture_output=True, timeout=180)
    assert result.returncode == 0, result.stderr[-4000:]
    return json.loads(result.stdout)

def operation(action, params):
    result = invoke('execute', action, params)
    assert not result.get('error'), result
    return result

def denied(mode, action, params, **kwargs):
    result = invoke(mode, action, params, **kwargs)
    assert result.get('error'), result
    return result

def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def main():
    require_namespace()
    devices = json.loads(Path('/fixture/devices.json').read_text())
    disk, target = devices['disk'], devices['partition']
    assert disk.startswith('/dev/loop') and target.startswith(disk + 'p')
    helper = Path('/usr/lib/panasms/panasms-system-helper')
    assert digest(helper) == os.environ['PANASMS_GO09_HELPER_SHA256']
    stage = Path('/var/lib/panasms-agent/local-mounts')
    point = Path('/mnt/go09b-data')
    params = {'target': target, 'point': str(point), 'mountPolicy': 'manual'}
    for mode in ('plan', 'recover'):
        denied(mode, 'mount.attach', params, user='nobody')
    operation('mount.attach', params)
    payload = point / 'payload'
    payload.write_bytes(b'GO09B retained data\n' * 8192)
    original_hash = digest(payload)
    assert 'noauto' in Path('/etc/fstab').read_text()
    denied('plan', 'mount.attach', params)
    print('PASS actual attach, retained data, duplicate refusal and member denial', flush=True)
    for policy in ('boot', 'on-demand', 'manual'):
        operation('mount.settings', {**params, 'mountPolicy': policy})
        text = Path('/etc/fstab').read_text()
        assert ('x-systemd.automount' in text) == (policy == 'on-demand')
        assert ('noauto' in text) == (policy == 'manual')
        assert digest(payload) == original_hash
    print('PASS actual persistent policy edits preserve mounted data', flush=True)
    busy = subprocess.Popen(['/usr/bin/python3', '-c', 'import time; time.sleep(120)'], cwd=point)
    try:
        result = denied('plan', 'mount.detach', {'target': target})
        assert str(busy.pid) in result['error'], result
        assert digest(payload) == original_hash
    finally:
        busy.terminate(); busy.wait(timeout=5)
    nested = point / 'nested'
    nested.mkdir()
    command('mount', '-t', 'tmpfs', 'tmpfs', str(nested))
    try:
        denied('plan', 'mount.detach', {'target': target})
        assert digest(payload) == original_hash
    finally:
        command('umount', str(nested)); nested.rmdir()
    print('PASS concrete busy process and nested mount refusal', flush=True)
    shared = point / 'shared'; shared.mkdir()
    share_path = Path('/etc/panasms/sharing.json')
    original_sharing = share_path.read_bytes()
    share_path.write_text(json.dumps({'shares': [{'name': 'Fixture', 'path': str(shared),
                          'mountpoint': str(point), 'volume': 'fixture-volume', 'smb': True,
                          'nfs': False, 'readOnly': False, 'readers': [], 'writers': [], 'clients': []}], 'accounts': {}}))
    try:
        result = denied('plan', 'mount.detach', {'target': target})
        assert 'Fixture' in result['error']
    finally:
        share_path.write_bytes(original_sharing)
    print('PASS configured share blocks unmount without service mutations', flush=True)
    plan = invoke('plan', 'mount.settings', params)
    fstab = Path('/etc/fstab'); original_config = fstab.read_bytes()
    fstab.write_bytes(original_config + b'# foreign edit\n')
    try:
        denied('execute', 'mount.settings', params, plan=plan)
        assert fstab.read_bytes().endswith(b'# foreign edit\n')
    finally:
        fstab.write_bytes(original_config)
    result = operation('mount.open', {**params, 'mode': 'readonly'})
    assert result.get('readOnly') is True and digest(payload) == original_hash, result
    try:
        (point / 'must-not-write').write_text('no')
        raise AssertionError('read-only filesystem accepted write')
    except OSError as error:
        assert error.errno == errno.EROFS, error
    result = operation('mount.open', {**params, 'mode': 'auto'})
    assert result.get('needsChoice') is True, result
    operation('mount.detach', {'target': target})
    result = operation('mount.open', {**params, 'mode': 'repair-only'})
    assert result.get('repaired') is True, result
    result = operation('mount.open', {**params, 'mode': 'auto'})
    assert result.get('readOnly') is False and digest(payload) == original_hash, result
    print('PASS readonly choice, real EROFS, repair-only check and read-write reopen', flush=True)
    operation('mount.detach', {'target': target})
    operation('disk.prepare', {'target': disk})
    assert not command('wipefs', '--no-act', '--output', 'TYPE', '--noheadings', disk)
    assert not any(line.startswith('UUID=') for line in fstab.read_text().splitlines())
    journals = [json.loads(path.read_text()) for path in stage.glob('*.json')]
    assert journals and all(item['phase'] == 'complete' for item in journals), journals
    print(json.dumps({'result': 'PASS', 'helperSHA256': digest(helper), 'stages': 7,
                      'scope': 'native helper on owned loop and private accounts/config; inventory/cache fixture boundary; no physical eject or boot proof'}), flush=True)

if __name__ == '__main__':
    try:
        main()
    except Exception:
        columns = 'NAME,KNAME,PATH,TYPE,SIZE,MODEL,SERIAL,WWN,FSTYPE,UUID,LABEL,PARTUUID,PARTTYPE,MOUNTPOINTS,PKNAME,RO,PARTN,ROTA,TRAN,MAJ:MIN'
        info = subprocess.run(['/usr/bin/lsblk', '--json', '--bytes', '--output', columns], user=65534, group=65534, extra_groups=[], capture_output=True, text=True)
        print(json.dumps({'fixtureInventoryExit': info.returncode, 'fixtureInventory': info.stdout, 'fixtureInventoryError': info.stderr,
                          'privateCache': {p.name: p.read_text() for p in Path('/run/udev/data').iterdir()}}), flush=True)
        raise
