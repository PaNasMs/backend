#!/usr/bin/python3
"""Exercise real systemd-generated mount/crypt units on disposable loop images."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'management'))
import storage
import storage_luks as luks


def run(*args):
    return subprocess.check_output(args, stderr=subprocess.PIPE).decode().strip()


assert os.geteuid() == 0
mapping = 'panasms_boot_test_' + str(os.getpid())
point = Path('/mnt') / mapping
point.mkdir()
loop = None
original_fstab = Path('/etc/fstab').read_bytes()
crypttab = Path('/etc/crypttab')
original_crypttab = crypttab.read_bytes() if crypttab.exists() else None
mount_unit = run('systemd-escape', '--path', '--suffix=mount', str(point))
auto_unit = run('systemd-escape', '--path', '--suffix=automount', str(point))
crypt_unit = 'systemd-cryptsetup@' + mapping + '.service'
with tempfile.TemporaryDirectory(prefix='panasms-boot-test-', dir='/var/tmp') as tmp:
    root = Path(tmp)
    try:
        image = root / 'disk.img'
        with image.open('wb') as f:
            f.truncate(128 * 1024 * 1024)
        loop = run('losetup', '--find', '--show', str(image))
        assert loop.startswith('/dev/loop')
        key = root / 'password'
        key.write_text('boot-policy-test-password')
        key.chmod(0o600)
        run('cryptsetup', 'luksFormat', '--batch-mode', '--type', 'luks2', '--pbkdf', 'pbkdf2', '--iter-time', '10', '--key-file', str(key), loop)
        run('udevadm', 'settle')
        with patch.object(luks, 'ROOT', root / 'keys'):
            p = {'target': loop, 'passphrase': key.read_text(), 'name': mapping}
            luks.execute('luks.auto-enable', p)
            run('systemctl', 'start', crypt_unit)
            decrypted = '/dev/mapper/' + mapping
            assert Path(decrypted).exists()
            run('mkfs.ext4', '-F', decrypted)
            run('udevadm', 'settle')
            uuid = run('blkid', '-s', 'UUID', '-o', 'value', decrypted)
            storage.fstab_change(uuid, f'UUID={uuid} {point} ext4 {storage.mount_options({"mountPolicy": "on-demand"})} 0 0')
            run('systemctl', 'start', auto_unit)
            assert run('findmnt', '-n', '-o', 'FSTYPE', '--mountpoint', str(point)) == 'autofs'
            (point / 'proof.txt').write_text('on-demand mount works')
            assert 'ext4' in run('findmnt', '-n', '-o', 'FSTYPE', '--mountpoint', str(point))
            print('PASS generated cryptsetup service unlocks with stored key; first access mounts ext4', flush=True)
            run('systemctl', 'stop', auto_unit)
            run('systemctl', 'stop', mount_unit)
            storage.fstab_change(uuid, f'UUID={uuid} {point} ext4 {storage.mount_options({"mountPolicy": "manual"})} 0 0')
            assert not subprocess.run(['mountpoint', '-q', str(point)]).returncode == 0
            run('systemctl', 'start', mount_unit)
            assert (point / 'proof.txt').read_text() == 'on-demand mount works'
            run('systemctl', 'stop', mount_unit)
            run('systemctl', 'stop', crypt_unit)
            assert not Path(decrypted).exists()
            luks.execute('luks.auto-disable', p)
            print('PASS remembered manual mount and clean cryptsetup stop/revocation', flush=True)
    finally:
        for unit in [auto_unit, mount_unit, crypt_unit]:
            subprocess.run(['systemctl', 'stop', unit], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        Path('/etc/fstab').write_bytes(original_fstab)
        if original_crypttab is None:
            crypttab.unlink(missing_ok=True)
        else:
            crypttab.write_bytes(original_crypttab)
        run('systemctl', 'daemon-reload')
        for unit in [auto_unit, mount_unit, crypt_unit]:
            subprocess.run(['systemctl', 'reset-failed', unit], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if Path('/dev/mapper/' + mapping).exists():
            run('cryptsetup', 'close', mapping)
        if loop:
            run('losetup', '--detach', loop)
        point.rmdir()
        assert Path('/etc/fstab').read_bytes() == original_fstab
        assert (crypttab.read_bytes() if crypttab.exists() else None) == original_crypttab
        print('PASS original host fstab/crypttab restored byte-for-byte', flush=True)
