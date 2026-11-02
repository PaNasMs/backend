import json
import os
from pathlib import Path
import sys
import subprocess
import tempfile
import tarfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parents[1] / 'management'))
import sharing_compat as compat
from common import Rejected


class Preparation(unittest.TestCase):
    def setUp(self):
        self.package_version = compat.package_version
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.files = (self.root / 'updater', self.root / 'compat', self.root / 'prerm')
        for path in self.files:
            path.write_bytes(b'installed package source')
            path.chmod(0o644)
        for name, value in (('OWNER', os.getuid()), ('MARKER', self.root / 'marker'), ('INSTALL_MODE', self.root / 'install-mode'),
                            ('JOURNALS', (self.root / 'journal', self.root / 'legacy-journal')),
                            ('ATTESTED', self.files), ('PACKAGE_STATE', self.root / 'package-state'),
                            ('GUARD', self.root / 'restore-guard'), ('package_version', lambda configuring=False: '1.0')):
            guard = patch.object(compat, name, value)
            guard.start()
            self.addCleanup(guard.stop)

    def test_capability_requires_configured_version_and_exact_installed_code(self):
        with self.assertRaises(FileNotFoundError):
            compat.capabilities()
        compat.configure()
        self.assertEqual(compat.capabilities(), {'schema': 1, 'packageVersion': '1.0', 'pairedRestore': 1})
        self.files[0].write_bytes(b'changed updater')
        with self.assertRaises(Rejected):
            compat.capabilities()
        compat.configure()
        with patch.object(compat, 'package_version', return_value='2.0'):
            with self.assertRaises(Rejected):
                compat.capabilities()

    def test_protocol_guard_precedes_vendor_pre_start_export_reload(self):
        dropin = (Path(__file__).parents[1] / 'packaging/panasms-sharing-restore.conf').read_text()
        self.assertIn('ExecCondition=/usr/bin/python3 /usr/lib/panasms/management/sharing_compat.py resume-check', dropin)
        self.assertNotIn('ExecStartPre=', dropin)

    def test_failed_upgrade_target_never_overrides_installed_prerm_failure(self):
        script = Path(__file__).parents[1] / 'packaging/prerm'
        result = subprocess.run(['sh', str(script), 'failed-upgrade', '1.0', '2.0'],
                                capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('preserving its failure', result.stderr)

    def test_preparation_upgrade_and_nonpurge_reinstall_remain_distinct(self):
        script = (Path(__file__).parents[1] / 'packaging/postinst').read_text()
        begin = script.index('  if [ -z "${2:-}" ]')
        end = script.index('  fi\n', begin) + len('  fi\n')
        hook = script[begin:end]
        begin = script.index('  if [ -z "${2:-}" ]', end)
        end = script.index('  fi\n', begin) + len('  fi\n')
        timer = script[begin:end]
        marker = self.root / 'install-marker'
        command = (hook + '\n' + timer).replace('python3 ', 'echo python3 ').replace('systemctl ', 'echo systemctl ')
        command = command.replace('/var/lib/panasms-installer/sharing-package-install', str(marker))
        for previous, reinstall in (('1.0', False), ('', False), ('1.0', True)):
            with self.subTest(previous=previous, reinstall=reinstall):
                marker.unlink(missing_ok=True)
                if reinstall:
                    marker.touch()
                result = subprocess.run(['sh', '-c', command, 'postinst', 'configure', previous],
                                        capture_output=True, text=True, check=True)
                initializes = not previous or reinstall
                self.assertEqual('sharing-install.py' in result.stdout, initializes)
                self.assertEqual('systemctl enable --now panasms-sharing.timer' in result.stdout, initializes)
                self.assertEqual('package-resume' in result.stdout, not initializes)

    def test_direct_package_upgrade_resumes_only_previously_active_timer(self):
        for active in (True, False):
            with self.subTest(active=active):
                with patch.object(compat.subprocess, 'run', return_value=SimpleNamespace(returncode=0 if active else 3)):
                    compat.package_stop('2.0')
                with patch.object(compat, 'package_version', return_value='2.0'):
                    with patch.dict(os.environ, {'PANASMS_UPDATE_TRANSACTION': ''}):
                        with patch.object(compat.subprocess, 'run') as run:
                            compat.package_resume()
                self.assertEqual(run.call_args_list, [unittest.mock.call(['systemctl', 'start', 'panasms-sharing.timer'], check=True)] if active else [])
                self.assertFalse(compat.PACKAGE_STATE.exists())

    def test_package_abort_resumes_source_timer_but_restore_guard_defers_to_updater(self):
        with patch.object(compat.subprocess, 'run', return_value=SimpleNamespace(returncode=0)):
            compat.package_stop('2.0')
        compat.GUARD.write_bytes(b'rollback in progress')
        with patch.dict(os.environ, {'PANASMS_UPDATE_TRANSACTION': ''}):
            with patch.object(compat.subprocess, 'run') as run:
                compat.package_resume(abort=True)
                run.assert_not_called()
            self.assertTrue(compat.PACKAGE_STATE.exists())
            compat.GUARD.unlink()
            with patch.object(compat.subprocess, 'run') as run:
                compat.package_resume(abort=True)
                run.assert_called_once_with(['systemctl', 'start', 'panasms-sharing.timer'], check=True)

    def test_pre_unpack_capability_requires_maintenance_and_previously_configured_files(self):
        for state, maintenance, allowed in (('installed', '', True), ('half-installed', '', False),
                                            ('half-installed', '1', True), ('unpacked', '1', False)):
            with self.subTest(state=state, maintenance=maintenance):
                with patch.object(compat.subprocess, 'run', return_value=SimpleNamespace(stdout=state + ' 1.0')):
                    with patch.dict(os.environ, {'PANASMS_MAINTENANCE': maintenance}):
                        if allowed:
                            self.assertEqual(self.package_version(), '1.0')
                        else:
                            with self.assertRaises(Rejected):
                                self.package_version()

    def test_successful_configure_consumes_reinstall_intent(self):
        compat.atomic(compat.INSTALL_MODE, b'install\n')
        compat.configure()
        self.assertFalse(compat.INSTALL_MODE.exists())
        self.assertEqual(compat.capabilities()['pairedRestore'], 1)

    def test_pending_journals_are_neither_recovered_nor_deleted(self):
        for path in compat.JOURNALS:
            path.write_bytes(b'pending before upgrade')
            with self.assertRaises(Rejected):
                compat.configure()
            self.assertEqual(path.read_bytes(), b'pending before upgrade')
            self.assertFalse(compat.MARKER.exists())
            path.unlink()

    def test_untrusted_marker_and_attested_paths_rejected(self):
        compat.configure()
        compat.MARKER.chmod(0o666)
        with self.assertRaises(Rejected):
            compat.capabilities()
        compat.MARKER.chmod(0o600)
        alias = self.root / 'alias'
        os.link(compat.MARKER, alias)
        with self.assertRaises(Rejected):
            compat.capabilities()
        alias.unlink()
        compat.MARKER.unlink()
        compat.MARKER.symlink_to(self.files[0])
        with self.assertRaises(OSError):
            compat.capabilities()
        with self.assertRaises(Rejected):
            compat.configure()
        self.assertEqual(self.files[0].read_bytes(), b'installed package source')


class PairedRollback(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        paths = tuple(self.root / name for name in ('state', 'smb', 'managed-nfs', 'legacy-nfs'))
        for name, value in (('OWNER', os.getuid()), ('FILES', paths),
                            ('LOCKS', (self.root / 'lock', self.root / 'old-lock')),
                            ('GUARD', self.root / 'restore-guard'),
                            ('ACTIVATION', self.root / 'activation'), ('NATIVE', self.root / 'native'),
                            ('JOURNALS', (self.root / 'journal', self.root / 'legacy-journal'))):
            guard = patch.object(compat, name, value)
            guard.start()
            self.addCleanup(guard.stop)
        paths[0].write_bytes(b'{"shares":[],"accounts":{}}')
        paths[0].chmod(0o600)
        paths[1].write_bytes(b'original SMB policy')
        paths[1].chmod(0o640)
        paths[2].write_bytes(b'')
        paths[2].chmod(0o644)
        self.source = compat.capture()
        self.folder = self.root / 'backup'
        self.folder.mkdir()
        with tarfile.open(self.folder / 'data.tar', 'w') as archive:
            archive.add(paths[0], arcname=str(paths[0]).lstrip('/'))
        (self.folder / 'data.tar').chmod(0o600)
        self.source_hash = compat.save_pair(self.folder, self.source)

    def candidate(self):
        for path in compat.FILES:
            path.write_bytes(b'new policy ' + path.name.encode())
            path.chmod(0o600)
        return compat.capture()

    def prepare(self):
        current = compat.capture()
        reply = SimpleNamespace(returncode=0, stdout=json.dumps({'schema': 1, 'files': current, 'journalsAbsent': True}))
        with patch.object(compat.subprocess, 'run', return_value=reply):
            return compat.prepare_restore(self.source, self.source_hash, 'transaction')

    def test_activation_ticket_attests_old_source_without_mutating_publications(self):
        before = compat.capture()
        source = {'schema': 1, 'packageVersion': '1.0', 'pairedRestore': 1}
        with patch.object(compat, 'capabilities', side_effect=lambda: dict(source)):
            with patch.object(compat.subprocess, 'run', return_value=SimpleNamespace(returncode=0)):
                with patch.dict(os.environ, {'PANASMS_MAINTENANCE': '1'}):
                    first = compat.prepare_activation('2.0')
                    second = compat.prepare_activation('2.0')
        self.assertNotEqual(first['nonce'], second['nonce'])
        self.assertFalse(second['source']['native'])
        self.assertEqual(second['files'], before)
        self.assertEqual(compat.capture(), before)
        self.assertFalse(compat.NATIVE.exists())

    def test_native_upgrade_keeps_optional_previous_ticket_and_checks_witness(self):
        source = {'schema': 1, 'packageVersion': '1.0', 'pairedRestore': 1}
        native = {'schema': 1, 'packageVersion': '1.0', 'nonce': 'old-nonce'}
        compat.atomic(compat.NATIVE, json.dumps(native).encode())
        before = compat.capture()
        def run(args, **kwargs):
            return SimpleNamespace(returncode=0, stdout=json.dumps({'schema': 1, 'files': before, 'journalsAbsent': True}))
        previous = {'schema': 1, 'targetVersion': '1.0', 'nonce': 'old-nonce', 'previous': {'older': True}}
        for had_ticket in (False, True):
            with self.subTest(had_ticket=had_ticket):
                compat.ACTIVATION.unlink(missing_ok=True)
                if had_ticket:
                    compat.atomic(compat.ACTIVATION, json.dumps(previous).encode())
                with patch.object(compat, 'capabilities', side_effect=lambda: dict(source)):
                    with patch.object(compat.subprocess, 'run', side_effect=run):
                        with patch.dict(os.environ, {'PANASMS_MAINTENANCE': '1'}):
                            ticket = compat.prepare_activation('2.0')
                self.assertTrue(ticket['source']['native'])
                self.assertEqual('previous' in ticket, had_ticket)
                if had_ticket:
                    self.assertNotIn('previous', ticket['previous'])
                self.assertEqual(compat.capture(), before)

    def test_real_archive_binding_and_exact_absence_empty_file_mode_restore(self):
        self.assertEqual(compat.load_pair(self.folder, self.source_hash), self.source)
        self.candidate()
        guard = self.prepare()
        with self.assertRaises(Rejected):
            compat.resume_check()
        with compat.locked():
            compat.begin_restore(guard)
            compat.restore_pair(guard)
            compat.finish_restore()
        self.assertEqual(compat.capture(), self.source)
        self.assertFalse(compat.FILES[3].exists())
        self.assertTrue(compat.FILES[2].exists())
        self.assertEqual(compat.FILES[2].read_bytes(), b'')
        self.assertEqual(compat.FILES[1].stat().st_mode & 0o777, 0o640)
        compat.resume_check()

    def test_refuses_legacy_unverified_changes_and_pending_journal(self):
        self.candidate()
        with patch.object(compat.subprocess, 'run', return_value=SimpleNamespace(returncode=1)):
            with self.assertRaises(Rejected):
                compat.prepare_restore(self.source, self.source_hash, 'transaction')
        self.assertFalse(compat.GUARD.exists())
        compat.JOURNALS[0].write_bytes(b'native journal with legacy NFS snapshot')
        with self.assertRaises(Rejected):
            self.prepare()
        self.assertEqual(compat.JOURNALS[0].read_bytes(), b'native journal with legacy NFS snapshot')

    def test_foreign_edit_after_check_or_during_package_install_is_preserved(self):
        self.candidate()
        current = compat.capture()
        def changed(*args, **kwargs):
            compat.FILES[3].write_bytes(b'foreign edit')
            return SimpleNamespace(returncode=0, stdout=json.dumps({'schema': 1, 'files': current, 'journalsAbsent': True}))
        with patch.object(compat.subprocess, 'run', side_effect=changed):
            with self.assertRaises(Rejected):
                compat.prepare_restore(self.source, self.source_hash, 'transaction')
        self.assertFalse(compat.GUARD.exists())
        guard = self.prepare()
        compat.FILES[3].write_bytes(b'later foreign edit')
        with self.assertRaises(Rejected):
            compat.begin_restore(guard)
        self.assertEqual(compat.FILES[3].read_bytes(), b'later foreign edit')
        self.assertTrue(compat.GUARD.exists())

    def test_interrupted_restore_retries_only_expected_or_restored_files(self):
        self.candidate()
        guard = self.prepare()
        compat.begin_restore(guard)
        original = compat.atomic
        def fail(path, data, **kwargs):
            if path == compat.FILES[1]:
                raise OSError('injected write failure')
            return original(path, data, **kwargs)
        with patch.object(compat, 'atomic', side_effect=fail):
            with self.assertRaises(OSError):
                compat.restore_pair(guard)
        self.assertTrue(compat.GUARD.exists())
        retry = compat.prepare_restore(self.source, self.source_hash, 'transaction')
        compat.begin_restore(retry)
        compat.restore_pair(retry)
        self.assertEqual(compat.capture(), self.source)
        compat.FILES[3].write_bytes(b'foreign after failure')
        with self.assertRaises(Rejected):
            compat.begin_restore(retry)
        self.assertEqual(compat.FILES[3].read_bytes(), b'foreign after failure')

    def test_real_tar_restore_never_deletes_or_overwrites_live_sharing_json(self):
        fake_root = self.root / 'guest'
        directory = fake_root / 'etc/panasms'
        directory.mkdir(parents=True)
        state = directory / 'sharing.json'
        other = directory / 'other.json'
        state.write_bytes(b'archive A')
        other.write_bytes(b'other A')
        archive = self.root / 'restore.tar'
        with tarfile.open(archive, 'w') as stream:
            stream.add(directory, arcname='etc/panasms')
        state.write_bytes(b'live B')
        other.write_bytes(b'other B')
        with patch.object(compat, 'FILES', (state, *compat.FILES[1:])):
            compat.clear_config_directory()
        self.assertEqual(state.read_bytes(), b'live B')
        self.assertFalse(other.exists())
        subprocess.run(['tar', '-xpf', str(archive), '-C', str(fake_root),
                        '--exclude=etc/panasms/sharing.json', '--exclude=./etc/panasms/sharing.json'], check=True)
        self.assertEqual(state.read_bytes(), b'live B')
        self.assertEqual(other.read_bytes(), b'other A')

    def test_foreign_edit_during_archive_restore_is_not_overwritten(self):
        self.candidate()
        guard = self.prepare()
        compat.begin_restore(guard)
        compat.FILES[3].write_bytes(b'foreign while tar was restoring')
        before = compat.capture()
        with self.assertRaises(Rejected):
            compat.restore_pair(guard)
        self.assertEqual(compat.capture(), before)
        self.assertTrue(compat.GUARD.exists())

    def test_archive_tampering_and_snapshot_changed_are_rejected(self):
        with (self.folder / 'data.tar').open('ab') as archive:
            archive.write(b'changed')
        with self.assertRaises(Rejected):
            compat.load_pair(self.folder, self.source_hash)
        snapshot = self.folder / 'sharing-pair.json'
        snapshot.write_bytes(b'{}')
        with self.assertRaises(Rejected):
            compat.load_pair(self.folder, self.source_hash)

    def test_only_known_native_hook_conversion_is_allowed(self):
        compat.FILES[1].write_bytes(b'root preexec = /usr/lib/panasms/panasms-system-helper sharing check Media\n')
        guard = self.prepare()
        compat.FILES[1].write_bytes(b'root preexec = /usr/bin/python3 /usr/lib/panasms/management/sharing.py --check Media\n')
        compat.begin_restore(guard)
        compat.restore_pair(guard)
        self.assertEqual(compat.capture(), self.source)


if __name__ == '__main__':
    unittest.main()
