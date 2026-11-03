import argparse
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch


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


if __name__ == '__main__':
    unittest.main()
