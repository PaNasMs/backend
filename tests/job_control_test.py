import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'management'))
import job_control
import job_recovery

class JobControlTest(unittest.TestCase):
    def test_requested_and_disconnected_parent_cancel(self):
        for disconnected in (False, True):
            read, write = os.pipe()
            try:
                with patch.dict(os.environ, {'PANASMS_CONTROL_FD': str(read)}):
                    job_control.checkpoint()
                    if disconnected:
                        os.close(write); write = None
                    else: os.write(write, b'1')
                    with self.assertRaises(job_control.Cancelled): job_control.checkpoint()
            finally:
                os.close(read)
                if write is not None: os.close(write)

    def test_copy_command_is_stopped_on_cancellation(self):
        with patch.object(job_control, 'checkpoint', side_effect=job_control.Cancelled):
            with self.assertRaises(job_control.Cancelled):
                job_control.copying([sys.executable, '-c', 'import time;time.sleep(120)'])

    def test_recovery_only_inspects_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / 'source'; source.write_text('original')
            destination = Path(tmp) / 'destination'; destination.write_text('partial')
            report = job_recovery.inspect({'action': 'file.move', 'params': {'target': str(source), 'destination': str(destination)}})
            self.assertEqual(source.read_text(), 'original')
            self.assertEqual(destination.read_text(), 'partial')
            self.assertEqual(len(report['checks']), 2)
            self.assertIsNone(report['recoveryAction'])

    def test_destructive_recovery_is_read_only_and_never_replays(self):
        for action in ('raid.delete', 'raid.grow', 'disk.wipe', 'filesystem.format', 'filesystem.resize', 'partition.delete', 'luks.format', 'mount.detach'):
            with self.subTest(action=action), patch.object(job_recovery, 'json_command', return_value={'blockdevices': []}) as query, patch.object(job_recovery, 'command') as mutation, patch.object(Path, 'read_text', return_value='Personalities : [raid1]'):
                report = job_recovery.inspect({'action':action,'params':{'target':'/dev/example'}})
                self.assertEqual(query.call_args.args[0][0], 'lsblk')
                mutation.assert_not_called()
                self.assertIsNone(report['recoveryAction'])
                self.assertTrue(report['checks'])
