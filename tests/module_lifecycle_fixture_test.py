import argparse
import importlib.util
import contextlib
import hashlib
import json
from types import SimpleNamespace
from pathlib import Path
import unittest
from unittest.mock import patch, MagicMock


source = Path(__file__).with_name('module_lifecycle_helper_integration.py')
spec = importlib.util.spec_from_file_location('lifecycle_fixture', source)
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


class FixtureSafety(unittest.TestCase):
    def test_missing_opt_in_or_guest_root_cannot_reach_commands_or_files(self):
        for opt_in, uid in [(False, 0), (False, 1000), (True, 1000)]:
            with self.subTest(opt_in=opt_in, uid=uid), patch.object(fixture.os, 'geteuid', return_value=uid), \
                    patch.object(fixture.Path, 'read_text') as read, \
                    patch.object(fixture.Path, 'mkdir') as mkdir, \
                    patch.object(fixture.subprocess, 'run') as run, \
                    patch.object(fixture.subprocess, 'check_output') as command:
                with self.assertRaisesRegex(RuntimeError, 'Explicit isolated guest root opt-in'):
                    fixture.prove_guest(argparse.Namespace(allow_disposable_vm=opt_in))
                read.assert_not_called()
                mkdir.assert_not_called()
                run.assert_not_called()
                command.assert_not_called()

    def test_wrong_guest_identity_cannot_reach_commands_or_writes(self):
        with patch.object(fixture.os, 'geteuid', return_value=0), \
                patch.dict(fixture.os.environ, {}, clear=True), \
                patch.object(fixture.Path, 'read_text', return_value='unrelated-computer'), \
                patch.object(fixture.Path, 'mkdir') as mkdir, \
                patch.object(fixture.subprocess, 'run') as run, \
                patch.object(fixture.subprocess, 'check_output') as command:
            with self.assertRaisesRegex(RuntimeError, 'VM identity refused'):
                fixture.prove_guest(argparse.Namespace(allow_disposable_vm=True,
                                                     vm_uuid='00000000-0000-0000-0000-000000000001'))
            mkdir.assert_not_called()
            run.assert_not_called()
            command.assert_not_called()

    def test_borrowed_control_pipe_cannot_be_consumed(self):
        with patch.object(fixture.os, 'geteuid', return_value=0), \
                patch.dict(fixture.os.environ, {'PANASMS_CONTROL_FD': '123'}), \
                patch.object(fixture.Path, 'read_text') as read, \
                patch.object(fixture.subprocess, 'run') as run:
            with self.assertRaisesRegex(RuntimeError, 'Borrowed cancellation control refused'):
                fixture.prove_guest(argparse.Namespace(allow_disposable_vm=True))
            read.assert_not_called()
            run.assert_not_called()

    def test_cleanup_refuses_mounts_and_does_not_confuse_sibling_paths(self):
        path = Path('/var/lib/private fixture')
        rows = [('41 1 8:1 / /var/lib/private\\040fixture rw - ext4 /dev/test rw', True),
                ('41 1 8:1 / /var/lib/private\\040fixture/child rw - ext4 /dev/test rw', True),
                ('41 1 8:1 / /var/lib/private\\040fixture-sibling rw - ext4 /dev/test rw', False)]
        for row, blocked in rows:
            with self.subTest(row=row), patch.object(fixture.Path, 'read_text', return_value=row):
                if blocked:
                    with self.assertRaisesRegex(RuntimeError, 'Fixture contains mounted data'):
                        fixture.no_mounts(path)
                else:
                    fixture.no_mounts(path)
        with patch.object(fixture.Path, 'read_text', return_value='broken'):
            with self.assertRaisesRegex(RuntimeError, 'Invalid mount inventory'):
                fixture.no_mounts(path)


class FixtureChildLifecycle(unittest.TestCase):
    def child(self):
        process = MagicMock()
        process.pid = 12345
        process.poll.return_value = None
        process.wait.return_value = -fixture.signal.SIGKILL
        return process

    def patches(self, process, helper):
        stack = contextlib.ExitStack()
        stack.enter_context(patch.object(fixture.subprocess, 'Popen', return_value=process))
        stack.enter_context(patch.object(fixture, 'helper', side_effect=helper))
        stack.enter_context(patch.object(fixture.Path, 'exists', lambda path: str(path).endswith('/ui/blob')))
        stack.enter_context(patch.object(fixture, 'owned', return_value=SimpleNamespace(st_size=1)))
        stack.enter_context(patch.object(fixture, 'registry', return_value={}))
        return stack

    def test_interruption_reaches_kill_inspection_recovery_and_reaps_child(self):
        process = self.child()
        responses = [{'fingerprint': 'plan', 'confirmation': fixture.ID},
                     {'recoveryAction': 'module.recover', 'route': '/modules'}]
        with self.patches(process, responses), \
                patch.object(fixture.os, 'pidfd_open', return_value=222) as opened, \
                patch.object(fixture.signal, 'pidfd_send_signal') as kill, \
                patch.object(fixture.os, 'close') as close, \
                patch.object(fixture.Path, 'read_bytes', return_value=b'child binary'), \
                patch.object(fixture, 'read', return_value=json.dumps({'before': {}, 'affected': [fixture.ID],
                                  'phase': 'staging', 'committed': False}).encode()), \
                patch.object(fixture, 'execute') as recover:
            fixture.interrupted_copy(SimpleNamespace(actor='admin', helper_sha256=hashlib.sha256(b'child binary').hexdigest()), {}, 'token')
            opened.assert_called_once_with(process.pid)
            kill.assert_called_once_with(222, fixture.signal.SIGKILL)
            process.wait.assert_called_once_with(timeout=15)
            recover.assert_called_once_with(unittest.mock.ANY, 'module.recover', {})
            close.assert_called_once_with(222)
            process.stdout.close.assert_called_once()
            process.stderr.close.assert_called_once()
            process.stdin.write.assert_called_once()

    def test_pidfd_failure_cannot_leave_a_waiting_helper(self):
        process = self.child()
        with self.patches(process, [{'fingerprint': 'plan', 'confirmation': fixture.ID}]), \
                patch.object(fixture.os, 'pidfd_open', side_effect=OSError('no pidfd')):
            with self.assertRaisesRegex(OSError, 'no pidfd'):
                fixture.interrupted_copy(SimpleNamespace(actor='admin'), {}, 'token')
            process.kill.assert_called_once()
            process.wait.assert_called_once_with(timeout=15)
            process.stdin.close.assert_called_once()
            process.stdout.close.assert_called_once()
            process.stderr.close.assert_called_once()

    def test_cancel_finishes_normally_and_closes_owned_pipes(self):
        process = self.child()
        stdin = process.stdin
        def communicate():
            process.returncode = 0
            process.poll.return_value = 0
            return '{"cancelled":true}', ''
        process.communicate.side_effect = communicate
        with self.patches(process, [{'fingerprint': 'plan', 'confirmation': fixture.ID}]), \
                patch.object(fixture.os, 'pipe', return_value=(333, 334)), \
                patch.object(fixture.os, 'set_blocking'), \
                patch.object(fixture.os, 'write') as write, \
                patch.object(fixture.os, 'close') as close:
            fixture.cancelled_copy(SimpleNamespace(actor='admin'), {}, 'token')
            write.assert_called_once_with(334, b'cancel')
            self.assertEqual(close.call_args_list, [unittest.mock.call(333), unittest.mock.call(334)])
            stdin.write.assert_called_once()
            stdin.close.assert_called_once()
            process.communicate.assert_called_once()
            process.stdout.close.assert_called_once()
            process.stderr.close.assert_called_once()
            process.kill.assert_not_called()

    def test_popen_failure_still_closes_cancellation_pipes(self):
        with patch.object(fixture, 'helper', return_value={'fingerprint': 'plan', 'confirmation': fixture.ID}), \
                patch.object(fixture.os, 'pipe', return_value=(333, 334)), \
                patch.object(fixture.os, 'set_blocking'), \
                patch.object(fixture.subprocess, 'Popen', side_effect=OSError('spawn failed')), \
                patch.object(fixture.os, 'close') as close:
            with self.assertRaisesRegex(OSError, 'spawn failed'):
                fixture.cancelled_copy(SimpleNamespace(actor='admin'), {}, 'token')
            self.assertEqual(close.call_args_list, [unittest.mock.call(333), unittest.mock.call(334)])


if __name__ == '__main__':
    unittest.main()
