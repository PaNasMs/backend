from pathlib import Path
import runpy
import subprocess
import tempfile
import unittest
from unittest.mock import patch

m = runpy.run_path(str(Path(__file__).resolve().parents[1] / "cooling/controller.py"))
duty = m["duty"]
disk_read = m["disk_read"]


class CoolingTest(unittest.TestCase):
    def test_fail_safe_and_sleep(self):
        self.assertEqual(duty("quiet", [], 50)[0], 1)
        self.assertEqual(duty("quiet", [{"state": "unknown"}], 50)[0], 1)
        self.assertEqual(duty("quiet", [{"state": "sleeping"}] * 4, 50)[0], 0)
        self.assertEqual(duty("quiet", [{"state": "sleeping"}, {"state": "unknown"}], 50)[0], 1)
        self.assertEqual(duty("quiet", [{"state": "sleeping"}] * 4, 71)[0], 1)
        self.assertEqual(duty("quiet", [{"state": "sleeping"}] * 4, None)[0], 1)

    def test_curves(self):
        for profile, expected in [("quiet", 0.25), ("balanced", 0.5), ("performance", 0.75)]:
            self.assertEqual(duty(profile, [{"state": "active", "temperature": 36}], 50)[0], expected)
        self.assertEqual(duty("quiet", [{"state": "active", "temperature": 50}], 50)[0], 1)
        self.assertEqual(duty("quiet", [{"state": "active", "temperature": None}], 50)[0], 1)

    def test_cpu_profiles_keep_critical_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "type").write_text("cpu-thermal")
            (root / "trip_point_0_temp").write_text("110000")
            for i in range(1, 5):
                (root / f"trip_point_{i}_type").write_text("active")
                (root / f"trip_point_{i}_temp").write_text("75000")
            m["apply_cpu_profile"]("balanced", root)
            self.assertEqual((root / "trip_point_1_temp").read_text(), "45000")
            self.assertEqual((root / "trip_point_4_temp").read_text(), "70000")
            self.assertEqual((root / "trip_point_0_temp").read_text(), "110000")
            (root / "trip_point_4_type").write_text("critical")
            with self.assertRaises(ValueError):
                m["apply_cpu_profile"]("quiet", root)

    def test_smart_failure_is_not_sleep(self):
        for code, output, expected in [
            (3, "{}", "unknown"),
            (3, '{"smartctl":{"messages":[{"string":"Device is in STANDBY mode"}]}}', "sleeping"),
            (5, "{}", "unknown"),
            (0, '{"temperature":{"current":35}}', "active"),
            (8, '{"temperature":{"current":35}}', "active"),
            (0, "{}", "unknown"),
        ]:
            with patch("subprocess.run", return_value=subprocess.CompletedProcess([], code, output)):
                self.assertEqual(disk_read("/dev/test")["state"], expected)
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("smartctl", 10)):
            self.assertEqual(disk_read("/dev/test")["state"], "unknown")


if __name__ == "__main__":
    unittest.main()
