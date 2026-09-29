from pathlib import Path
import runpy
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "cooling"))
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

    def test_cold_disks_stop_fan_in_every_profile(self):
        for profile in ("quiet", "balanced", "performance"):
            self.assertEqual(duty(profile, [{"state": "active", "temperature": 29}], 50), (0, "disks-cool"))
            self.assertGreater(duty(profile, [{"state": "active", "temperature": 30}], 50)[0], 0)
            self.assertGreater(duty(profile, [{"state": "active", "temperature": 29}], 65)[0], 0)
        self.assertGreater(duty("quiet", [{"state": "active", "temperature": 29},
                                          {"state": "active", "temperature": 35}], 50)[0], 0)

    def test_startup_is_bounded_and_fail_safe_is_preserved(self):
        target = m["control_target"]
        unknown = [{"state": "unknown", "temperature": None}]
        self.assertEqual(target("quiet", [], 50, True, 0, stale=True), (0.5, "initializing-sensors"))
        self.assertEqual(target("quiet", unknown, 50, True, 119)[0], 0.5)
        self.assertEqual(target("quiet", unknown, 50, True, 120)[0], 1)
        self.assertEqual(target("quiet", unknown, 50, False, 10)[0], 1)
        self.assertEqual(target("quiet", unknown, 70, True, 0)[0], 1)
        self.assertEqual(target("quiet", unknown, 50, True, 0, invalid=True)[0], 1)
        hot = unknown + [{"state": "active", "temperature": 50}]
        self.assertEqual(target("quiet", hot, 50, True, 0)[0], 1)
        cold = [{"state": "active", "temperature": 29}]
        self.assertEqual(target("quiet", cold, 50, False, 10, stale=True)[0], 1)

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


class CoolingHardwareTest(unittest.TestCase):
    def test_legacy_and_four_wire_defaults(self):
        import hardware
        legacy = hardware.normalize({})
        self.assertEqual(hardware.signature(legacy), {'hardwareMode':'external-pwm','controlGPIO':27,'tachGPIO':None})
        new = hardware.normalize({'hardwareMode':'internal-pwm'})
        self.assertEqual((new['controlGPIO'], new['tachGPIO']), (18,24))
        hardware.validate(new)
        for pin in [2,14,24,27]:
            with self.assertRaises(ValueError): hardware.validate({**new,'controlGPIO':pin})
        with self.assertRaises(ValueError): hardware.validate({**new,'tachGPIO':18})

    def test_disabled_never_claims_gpio(self):
        import hardware
        with patch.object(hardware, 'gpio_chip', side_effect=AssertionError('GPIO accessed')):
            driver = hardware.Hardware(hardware.normalize({'hardwareMode':'none'}))
            driver.close()
            self.assertIsNone(driver.request)
            self.assertIsNone(driver.rpm)

    def test_failsafe_uses_active_pins_not_changed_configuration(self):
        import hardware,json
        with tempfile.TemporaryDirectory() as tmp:
            marker=Path(tmp)/'hardware.json'
            marker.write_text(json.dumps({'hardwareMode':'external-pwm','controlGPIO':22,'tachGPIO':None}))
            with patch.object(hardware,'MARKER',marker), patch.object(hardware.subprocess,'run') as run:
                hardware.failsafe()
                self.assertEqual(run.call_args.args[0],['pinctrl','set','22','op','dh'])
                self.assertFalse(marker.exists())

    def test_tach_counts_cycles_not_both_transitions(self):
        import hardware
        from types import SimpleNamespace
        edges=[SimpleNamespace(event_type=SimpleNamespace(name=name)) for name in
               ['RISING_EDGE','FALLING_EDGE','RISING_EDGE','FALLING_EDGE']]
        self.assertEqual(hardware.tach_pulses(edges),2)
        self.assertEqual(hardware.tach_pulses([]),0)
