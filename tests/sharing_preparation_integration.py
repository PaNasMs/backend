#!/usr/bin/env python3
"""Destructive package acceptance for an explicitly selected, disconnected VM.

The operator must hold the VM ownership token and a restorable stopped snapshot.
This tests the old updater already loaded in memory: the real package is installed,
then the old updater's exact restore function reinstalls its repacked packages and
extracts its real archive. No dpkg, tar, service or health calls are mocked. Restore
the operator snapshot after the scenario; updater evidence remains inside the VM.
"""
import argparse
from contextlib import ExitStack
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import shutil
import subprocess
import sys
import tempfile
import uuid

FILES = tuple(Path(path) for path in ('/etc/panasms/sharing.json', '/etc/samba/panasms-shares.conf',
                                     '/etc/exports.d/panasms-shares.exports', '/etc/exports.d/panasms.exports',
                                     '/var/lib/panasms-installer/sharing-native-v1.json',
                                     '/var/lib/panasms-installer/sharing-activation-v1.json'))


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


def service_states():
    states = {}
    for unit in ('panasms-sharing.timer', 'smbd.service', 'nfs-server.service'):
        active = subprocess.run(['systemctl', 'is-active', unit], capture_output=True, text=True)
        enabled = subprocess.run(['systemctl', 'is-enabled', unit], capture_output=True, text=True)
        assert active.stdout.strip() in ('active', 'inactive'), 'Select an idle, healthy protocol service baseline'
        assert enabled.stdout.strip() in ('enabled', 'disabled', 'static', 'indirect', 'alias'), 'Unexpected protocol unit enable state'
        states[unit] = {'active': active.stdout.strip(), 'enabled': enabled.stdout.strip()}
    return states


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--vm-uuid', required=True)
    parser.add_argument('--old-version', required=True)
    parser.add_argument('--old-updater-sha256', required=True)
    parser.add_argument('--package', type=Path, required=True)
    parser.add_argument('--package-sha256', required=True)
    parser.add_argument('--expect-configure-failure', action='store_true')
    parser.add_argument('--updater-kind', choices=('legacy', 'prepared'), default='legacy')
    parser.add_argument('--interrupt-paired-restore', action='store_true')
    parser.add_argument('--reupgrade-after-rollback', action='store_true')
    parser.add_argument('--root-retry-after-interruption', action='store_true')
    parser.add_argument('--native-activation', action='store_true')
    args = parser.parse_args()
    prove_guest(args.vm_uuid)
    with tempfile.TemporaryDirectory(prefix='panasms-go06-package-', dir='/run') as folder:
        run(args, Path(folder))


def pin_package(source, expected_hash, folder):
    assert source.is_file() and not source.is_symlink()
    data = source.read_bytes()
    package = folder / 'verified.deb'
    fd = os.open(package, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)
    assert hashlib.sha256(package.read_bytes()).hexdigest() == expected_hash
    return package


def run(args, folder):
    args.package = pin_package(args.package, args.package_sha256, folder)
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
    prepared = args.updater_kind == 'prepared'
    assert ('sharing_compat' in old.__dict__) == prepared, 'The installed updater does not match the selected fixture kind'
    assert old.read('state.json', {}).get('phase') not in old.ACTIVE | {'recovery-required'}
    assert not args.interrupt_paired_restore or prepared
    assert not args.reupgrade_after_rollback or ((not prepared or args.native_activation) and not args.expect_configure_failure)
    assert not args.root_retry_after_interruption or (prepared and args.interrupt_paired_restore)
    assert not args.native_activation or prepared
    if args.root_retry_after_interruption:
        assert 'retry' in old.recover.__code__.co_varnames, 'The source worker must support explicit root recovery'
        worker = old.ROOT / 'worker'
        worker.mkdir(mode=0o700, exist_ok=True)
        for name in ('system_updates.py', 'common.py', 'sharing_compat.py'):
            shutil.copy2(source.parent / name, worker / name)
            with (worker / name).open('rb') as stream:
                os.fsync(stream.fileno())
    baseline = capture()
    baseline_services = service_states()
    units = old.services()
    transaction = uuid.uuid4().hex
    old.save('state.json', {'id': transaction, 'operation': 'install', 'phase': 'preparing', 'version': target})
    old.save('active-units.json', units)
    old.stop_terminals(units)
    old.module_idle()
    with ExitStack() as maintenance_guard:
        maintenance_guard.enter_context(old.maintenance())
        old.stop(units)
        old.backup(units)
        old.phase('installing')
        os.environ['PANASMS_UPDATE_TRANSACTION'] = transaction
        installed = subprocess.run(['dpkg', '--force-confold', '-i', str(args.package)], capture_output=True, text=True)
        assert (installed.returncode != 0) == args.expect_configure_failure, 'Unexpected package result; restore operator snapshot'
        if args.native_activation:
            if not args.expect_configure_failure:
                receipt = json.loads(FILES[4].read_bytes())
                assert receipt['schema'] == 1 and receipt['packageVersion'] == target and len(receipt['nonce']) == 32
                assert not FILES[5].exists(), 'Native activation did not consume its committed ticket'
                capability = json.loads(command('python3', '/usr/lib/panasms/management/sharing_compat.py', 'capabilities'))
                assert capability['packageVersion'] == target and capability['pairedRestore'] == 1
                witness = json.loads(command('/usr/lib/panasms/panasms-system-helper', 'sharing', 'rollback-check'))
                assert witness['schema'] == 1 and witness['journalsAbsent'] is True
            else:
                assert FILES[5].exists(), 'The fixture did not reach native activation preparation'
        else:
            assert capture() == baseline, 'Preparation changed sharing policy before rollback'
        assert ('sharing_compat' in old.__dict__) == prepared, 'The in-memory updater changed unexpectedly'
        if prepared and args.expect_configure_failure:
            package_state = Path('/var/lib/panasms-installer/sharing-package-state.json')
            assert package_state.exists(), 'Inject failure before target package-resume for this reverse-transition test'
            record = json.loads(package_state.read_text())
            assert record['sourceVersion'] == args.old_version and record['targetVersion'] == target
        assert command('dpkg-query', '-W', '-f=${Version}', 'panasms-prototype') == target
        if not prepared:
            assert hashlib.sha256(source.read_bytes()).hexdigest() != args.old_updater_sha256
        if args.interrupt_paired_restore:
            class InjectedRestoreInterruption(Exception):
                pass
            real_run = old.run
            def interrupted_run(arguments, **kwargs):
                result = real_run(arguments, **kwargs)
                if arguments[:2] == ['tar', '-xpf']:
                    raise InjectedRestoreInterruption('After real tar extraction, before paired file restore')
                return result
            old.run = interrupted_run
            try:
                old.restore()
            except InjectedRestoreInterruption:
                guard = json.loads(Path('/var/lib/panasms-agent/sharing-restore.json').read_text())
                assert guard['phase'] == 'restoring'
                assert all(value['active'] == 'inactive' for value in service_states().values())
            else:
                raise AssertionError('The paired restore interruption was not exercised')
            finally:
                old.run = real_run
        if args.root_retry_after_interruption:
            old.finish('recovery-required', 'Injected after real tar extraction')
            maintenance_guard.close()
            subprocess.run([sys.executable, str(old.ROOT / 'worker/system_updates.py'), 'retry-rollback'],
                           check=True, capture_output=True)
        else:
            old.restore()
        assert command('dpkg-query', '-W', '-f=${db:Status-Status} ${Version}', 'panasms-prototype') == 'installed ' + args.old_version
        assert capture() == baseline, 'In-memory rollback changed the original sharing policy'
        assert service_states() == baseline_services, 'Rollback did not preserve prior protocol/timer active and enabled states'
        assert not Path('/var/lib/panasms-agent/sharing-transaction.json').exists()
        assert not Path('/var/lib/panasms-agent/sharing-restore.json').exists()
        old.finish('rolled-back', 'Explicit disposable-VM preparation acceptance')
        if args.reupgrade_after_rollback:
            old.stop(units)
            old.phase('installing')
            subprocess.run(['dpkg', '--force-confold', '-i', str(args.package)], check=True, capture_output=True)
            if args.native_activation:
                receipt = json.loads(FILES[4].read_bytes())
                assert receipt['packageVersion'] == target and not FILES[5].exists()
            else:
                assert capture() == baseline
            assert not Path('/var/lib/panasms-installer/sharing-package-state.json').exists(), 'Historical old-target package state survived reupgrade'
            capability = json.loads(command('python3', '/usr/lib/panasms/management/sharing_compat.py', 'capabilities'))
            assert capability['packageVersion'] == target and capability['pairedRestore'] == 1
            old.start(units)
            old.healthy()
            assert service_states() == baseline_services
            old.finish('complete', 'Explicit disposable-VM old-target reupgrade acceptance')
    print(json.dumps({'result': 'PASS', 'scenario': args.updater_kind + '-in-memory-worker-to-' + ('native' if args.native_activation else 'preparation') + '-and-back',
                      'oldVersion': args.old_version, 'targetVersion': target,
                      'configureFailureInjected': args.expect_configure_failure,
                      'pairedRestoreInterruptionAndRetry': args.interrupt_paired_restore,
                      'reupgradeAfterOldRollback': args.reupgrade_after_rollback,
                      'rootRetryWithoutAgent': args.root_retry_after_interruption,
                      'finalInstalledVersion': command('dpkg-query', '-W', '-f=${Version}', 'panasms-prototype'),
                      'protocolServiceStatePreserved': True,
                      'packageSHA256': args.package_sha256, 'updaterSHA256': args.old_updater_sha256,
                      'sharingPairUnchanged': True, 'activationMetadataUnchanged': True,
                      'realDpkgTarAndServiceHealth': True}, sort_keys=True))


if __name__ == '__main__':
    main()
