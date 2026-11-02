#!/usr/bin/env python3
"""Destructive package acceptance for an explicitly selected, disconnected VM.

The operator must hold the VM ownership token and a restorable stopped snapshot.
This tests the old updater already loaded in memory: the real package is installed,
then the old updater's exact restore function reinstalls its repacked packages and
extracts its real archive. No dpkg, tar, service or health calls are mocked. Restore
the operator snapshot after the scenario; updater evidence remains inside the VM.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import uuid

FILES = tuple(Path(path) for path in ('/etc/panasms/sharing.json', '/etc/samba/panasms-shares.conf',
                                     '/etc/exports.d/panasms-shares.exports', '/etc/exports.d/panasms.exports'))


def command(*args):
    return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT).strip()


def prove_guest(expected_uuid):
    assert os.environ.get('PANASMS_TEST_ALLOW_PACKAGE_RESTORE') == '1', 'Explicit package-restore fixture opt-in required'
    assert os.geteuid() == 0
    assert Path('/sys/class/dmi/id/product_uuid').read_text().strip().lower() == expected_uuid.lower()
    assert command('systemd-detect-virt', '--vm') in ('kvm', 'qemu')
    assert not any(row['ifname'] != 'lo' and 'LOWER_UP' in row['flags'] for row in json.loads(command('ip', '-j', 'link')))
    assert not json.loads(command('ip', '-j', 'route'))
    assert not json.loads(command('ip', '-6', '-j', 'route'))
    mounts = subprocess.run(['findmnt', '-J', '-t', 'virtiofs,9p,nfs,nfs4,cifs,fuse.sshfs'], capture_output=True, text=True)
    assert mounts.returncode in (0, 1)
    assert not json.loads(mounts.stdout or '{}').get('filesystems')
    for path in ('/var/lib/panasms-agent/sharing-transaction.json', '/var/lib/panasms-agent/sharing-restore.json', '/var/lib/panasms-agent/sharing-legacy-nfs-transaction.json'):
        assert not Path(path).exists() and not Path(path).is_symlink(), 'Fixture requires an idle baseline'


def capture():
    result = {}
    for path in FILES:
        assert not path.is_symlink()
        if path.exists():
            info = path.stat()
            assert stat.S_ISREG(info.st_mode) and info.st_uid == 0
            result[str(path)] = (path.read_bytes(), stat.S_IMODE(info.st_mode), info.st_uid, info.st_gid)
        else:
            result[str(path)] = None
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--vm-uuid', required=True)
    parser.add_argument('--old-version', required=True)
    parser.add_argument('--old-updater-sha256', required=True)
    parser.add_argument('--package', type=Path, required=True)
    parser.add_argument('--package-sha256', required=True)
    parser.add_argument('--expect-configure-failure', action='store_true')
    args = parser.parse_args()
    prove_guest(args.vm_uuid)
    assert args.package.is_file() and not args.package.is_symlink()
    assert hashlib.sha256(args.package.read_bytes()).hexdigest() == args.package_sha256
    assert command('dpkg-deb', '-f', str(args.package), 'Package') == 'panasms-prototype'
    target = command('dpkg-deb', '-f', str(args.package), 'Version')
    assert command('dpkg-query', '-W', '-f=${db:Status-Status} ${Version}', 'panasms-prototype') == 'installed ' + args.old_version
    source = Path('/usr/lib/panasms/management/system_updates.py')
    assert hashlib.sha256(source.read_bytes()).hexdigest() == args.old_updater_sha256
    sys.path.insert(0, str(source.parent))
    spec = importlib.util.spec_from_file_location('preloaded_old_updater', source)
    old = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(old)
    assert 'sharing_compat' not in old.__dict__, 'Select the released pre-preparation updater'
    assert old.read('state.json', {}).get('phase') not in old.ACTIVE | {'recovery-required'}
    baseline = capture()
    units = old.services()
    transaction = uuid.uuid4().hex
    old.save('state.json', {'id': transaction, 'operation': 'install', 'phase': 'preparing', 'version': target})
    old.save('active-units.json', units)
    old.stop_terminals(units)
    old.module_idle()
    with old.maintenance():
        old.stop(units)
        old.backup(units)
        old.phase('installing')
        os.environ['PANASMS_UPDATE_TRANSACTION'] = transaction
        installed = subprocess.run(['dpkg', '--force-confold', '-i', str(args.package)], capture_output=True, text=True)
        assert (installed.returncode != 0) == args.expect_configure_failure, 'Unexpected package result; restore operator snapshot'
        assert capture() == baseline, 'Preparation changed sharing policy before rollback'
        assert 'sharing_compat' not in old.__dict__, 'The in-memory updater changed unexpectedly'
        assert hashlib.sha256(source.read_bytes()).hexdigest() != args.old_updater_sha256
        old.restore()
        assert command('dpkg-query', '-W', '-f=${db:Status-Status} ${Version}', 'panasms-prototype') == 'installed ' + args.old_version
        assert capture() == baseline, 'Old in-memory rollback changed the original sharing policy'
        assert not Path('/var/lib/panasms-agent/sharing-transaction.json').exists()
        old.finish('rolled-back', 'Explicit disposable-VM preparation acceptance')
    print(json.dumps({'result': 'PASS', 'scenario': 'old-in-memory-worker-to-preparation-and-back',
                      'oldVersion': args.old_version, 'targetVersion': target,
                      'configureFailureInjected': args.expect_configure_failure,
                      'packageSHA256': args.package_sha256, 'updaterSHA256': args.old_updater_sha256,
                      'sharingPairUnchanged': True, 'realDpkgTarAndServiceHealth': True}, sort_keys=True))


if __name__ == '__main__':
    main()
