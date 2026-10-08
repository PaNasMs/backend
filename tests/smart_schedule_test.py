import datetime, json, sys, tempfile, unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "management"))
import smart_schedule, storage


class SmartScheduleTest(unittest.TestCase):
    def setUp(self):
        lock = patch.object(smart_schedule, "locked")
        lock.start()
        self.addCleanup(lock.stop)

    def test_fortnight_crosses_year_without_iso_week_reset(self):
        start = datetime.date(2026, 12, 28)
        for offset, expected in [(-7, False), (0, True), (7, False), (14, True), (21, False), (28, True)]:
            self.assertEqual(smart_schedule.due(start + datetime.timedelta(days=offset), start, 2), expected)

    def test_next_slot_skips_alternate_week_and_crosses_year(self):
        schedule = {"weekday": 0, "hour": 2, "weeks": 2, "startDate": "2026-12-28"}
        result = smart_schedule.next_scheduled(schedule, datetime.datetime(2026, 12, 28, 2))
        self.assertEqual(datetime.datetime.fromisoformat(result).replace(tzinfo=None), datetime.datetime(2027, 1, 11, 2))

    def test_legacy_weekly_slot_and_future_anchor(self):
        schedule = {"weekday": 0, "hour": 2}
        result = smart_schedule.next_scheduled(schedule, datetime.datetime(2026, 9, 30))
        self.assertEqual(datetime.datetime.fromisoformat(result).replace(tzinfo=None), datetime.datetime(2026, 10, 5, 2))
        schedule.update(startDate="2027-01-04", weeks=2)
        self.assertTrue(smart_schedule.next_scheduled(schedule, datetime.datetime(2026, 9, 30)).startswith("2027-01-04T02:"))

    def test_both_schedules_are_read_independently(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            base = "panasms-smart-" + storage.hashlib.sha256(b"disk").hexdigest()[:16]
            for test, weeks in [("short", 1), ("long", 2)]:
                cfg = {"test": test, "weeks": weeks, "weekday": 0, "hour": 2, "startDate": "2026-09-21"}
                (root / (base + "-" + test + ".service")).write_text(
                    "# PaNasMs schedule: " + json.dumps(cfg) + "\n"
                )
                (root / (base + "-" + test + ".timer")).touch()
            self.assertEqual(
                {s["test"]: s["weeks"] for s in storage.smart_schedules("disk", root)},
                {"short": 1, "long": 2},
            )

    def test_busy_raid_does_not_probe_or_start_test(self):
        today = datetime.date.today().isoformat()
        with (
            patch.object(storage, "inventory", return_value={"/dev/test": {"type": "disk", "kname": "test"}}),
            patch.object(smart_schedule, "busy_arrays", return_value=["md0"]),
            patch.object(smart_schedule, "command") as command,
        ):
            smart_schedule.run("/dev/test", "long", 2, today)
            command.assert_not_called()

    def test_existing_test_not_interrupted(self):
        today = datetime.date.today().isoformat()
        with (
            patch.object(storage, "inventory", return_value={"/dev/test": {"type": "disk", "kname": "test"}}),
            patch.object(smart_schedule, "busy_arrays", return_value=[]),
            patch.object(
                smart_schedule,
                "command",
                return_value=json.dumps({"ata_smart_data": {"self_test": {"status": {"value": 249}}}}),
            ) as command,
        ):
            smart_schedule.run("/dev/test", "short", 1, today)
            self.assertEqual(command.call_count, 1)


if __name__ == "__main__":
    unittest.main()
