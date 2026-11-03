#!/usr/bin/env python3
"""Private-chroot GO09B scenarios; outer VM/loop isolation is mandatory."""
import hashlib, json, os, re, subprocess, uuid
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
    disk = devices['disk']
    assert re.fullmatch(r'/dev/loop[0-9]+', disk)
    helper = '/usr/lib/panasms/panasms-system-helper'
    assert digest(helper) == os.environ['PANASMS_GO09_HELPER_SHA256']
    command('parted', '--script', disk, 'mklabel', 'gpt', 'mkpart', 'first', '1MiB', '96MiB',
            'mkpart', 'second', '96MiB', '480MiB')
    command('udevadm', 'settle')
    first, second = disk + 'p1', disk + 'p2'
    shared_uuid = str(uuid.uuid4())
    for device in (first, second):
        command('mkfs.ext4', '-F', '-q', '-U', shared_uuid, device)
    command('udevadm', 'settle')
    fstab = Path('/etc/fstab')
    before = fstab.read_text()
    retained = Path('/mnt/retained-clone')
    retained.mkdir()
    command('mount', second, str(retained))
    marker = retained / 'payload'
    marker.write_text('retain the other volume')
    fstab.write_text(before + f'UUID={shared_uuid} {retained} ext4 noauto,x-systemd.device-timeout=30s 0 0\n')
    expected = fstab.read_bytes()
    for action in ('disk.prepare', 'mount.attach', 'mount.settings', 'mount.open'):
        result = denied('plan', action, {'target': first, 'point': '/mnt/selected-clone'})
        assert result['error'] == 'This file system UUID is present on another device. Review the mount configuration.', result
        assert fstab.read_bytes() == expected and marker.read_text() == 'retain the other volume'
    command('umount', str(retained))
    fstab.write_text(before)
    print('PASS cloned UUID cannot displace the other volume configuration or its data', flush=True)

    command('wipefs', '--all', first)
    command('mkfs.vfat', '-F', '32', first)
    command('udevadm', 'settle')
    fat = Path('/mnt/fat-access')
    operation('mount.attach', {'target': first, 'point': str(fat), 'mountPolicy': 'manual'})
    subprocess.run(['/usr/bin/python3', '-c', 'from pathlib import Path; Path("/mnt/fat-access/user-file").write_text("member data")'],
                   user=15000, group=15000, extra_groups=[100], check=True)
    metadata = (fat / 'user-file').stat()
    assert metadata.st_uid == 15000 and metadata.st_gid == 100 and metadata.st_mode & 0o777 == 0o664
    assert fat.stat().st_mode & 0o777 == 0o775
    operation('mount.detach', {'target': first})
    print('PASS FAT ownership, group and access masks for the actual dropped user', flush=True)

    command('wipefs', '--all', second)
    command('mkfs.btrfs', '-q', '-f', second)
    command('udevadm', 'settle')
    point = Path('/mnt/btrfs-access')
    params = {'target': second, 'point': str(point), 'mountPolicy': 'manual'}
    operation('mount.attach', params)
    marker = point / 'retained'
    marker.write_text('btrfs data')
    operation('mount.detach', {'target': second})
    operation('mount.attach', params)
    assert marker.read_text() == 'btrfs data'
    operation('mount.detach', {'target': second})
    print('PASS Btrfs attach and verified detach across separate helper processes', flush=True)

if __name__ == '__main__':
    main()
