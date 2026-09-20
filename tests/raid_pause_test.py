import sys, tempfile, unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "management"))
import storage


class ReshapeControlTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.md = Path(self.tmp.name)
        for k, v in {
            "uuid": "test",
            "level": "raid5",
            "metadata_version": "1.2",
            "sync_action": "reshape",
            "reshape_position": "12345",
            "degraded": "0",
            "array_state": "clean",
        }.items():
            self.put(k, v)

    def put(self, key, value):
        (self.md / key).write_text(value)

    def test_pause_preserves_position(self):
        storage.control_reshape(self.md, "/dev/mdtest", "raid.pause")
        self.assertEqual((self.md / "sync_action").read_text(), "frozen")
        self.assertEqual((self.md / "reshape_position").read_text(), "12345")

    def test_resume_read_auto_starts_without_restarting_completed_work(self):
        self.put("sync_action", "idle")
        self.put("array_state", "read-auto")

        def run(args, **kwargs):
            self.assertEqual(args, ["mdadm", "--readwrite", "/dev/mdtest"])
            self.put("sync_action", "reshape")

        with patch.object(storage, "command", side_effect=run) as command:
            storage.control_reshape(self.md, "/dev/mdtest", "raid.resume")
            self.assertEqual(command.call_count, 1)

    def test_idle_resume_uses_mdadm_continue(self):
        self.put("sync_action", "idle")

        def run(args, **kwargs):
            self.assertEqual(args[-4:], ["/usr/sbin/mdadm", "--grow", "/dev/mdtest", "--continue"])
            self.put("sync_action", "reshape")

        with patch.object(storage, "command", side_effect=run):
            storage.control_reshape(self.md, "/dev/mdtest", "raid.resume")

    def test_frozen_resume_unfreezes_kernel(self):
        self.put("sync_action", "frozen")
        with patch.object(storage, "command") as command:
            storage.control_reshape(self.md, "/dev/mdtest", "raid.resume")
            command.assert_not_called()
        self.assertEqual((self.md / "sync_action").read_text(), "reshape")

    def test_reject_resume_when_running_degraded_or_finished(self):
        with self.assertRaises(storage.Rejected):
            storage.reshape_control_state(self.md, "raid.resume")
        self.put("sync_action", "idle")
        self.put("degraded", "1")
        with self.assertRaises(storage.Rejected):
            storage.reshape_control_state(self.md, "raid.resume")
        self.put("degraded", "0")
        self.put("reshape_position", "none")
        with self.assertRaises(storage.Rejected):
            storage.reshape_control_state(self.md, "raid.resume")

    def test_progress_does_not_invalidate_pause_plan(self):
        before = storage.reshape_control_state(self.md, "raid.pause")
        self.put("reshape_position", "23456")
        self.assertEqual(before, storage.reshape_control_state(self.md, "raid.pause"))

    def test_command_failure_is_not_reported_as_success(self):
        self.put("sync_action", "idle")
        self.put("array_state", "read-auto")
        with patch.object(storage, "command", side_effect=storage.Rejected("Ошибка mdadm")):
            with self.assertRaisesRegex(storage.Rejected, "Ошибка mdadm"):
                storage.control_reshape(self.md, "/dev/mdtest", "raid.resume")


if __name__ == "__main__":
    unittest.main()
