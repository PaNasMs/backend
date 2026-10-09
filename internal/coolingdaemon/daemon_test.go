package coolingdaemon

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func ptr(v float64) *float64 { return &v }
func readSleep(v float64) []Disk {
	return []Disk{{State: "sleeping", Temperature: ptr(v), SleepTemperature: true}}
}
func TestCoolingPolicy(t *testing.T) {
	unknown := []Disk{{State: "unknown"}}
	sleep := []Disk{{State: "sleeping"}}
	cold := []Disk{{State: "active", Temperature: ptr(29)}}
	warm := []Disk{{State: "active", Temperature: ptr(36)}}
	for _, tc := range []struct {
		name, profile  string
		disks          []Disk
		sensor         *float64
		starting       bool
		elapsed        time.Duration
		stale, invalid bool
		running        bool
		want           float64
	}{
		{name: "startup no disks", profile: "quiet", sensor: ptr(50), starting: true, stale: true, want: .5},
		{name: "startup unknown", profile: "quiet", disks: unknown, sensor: ptr(50), starting: true, elapsed: 119 * time.Second, want: .5},
		{name: "startup bounded", profile: "quiet", disks: unknown, sensor: ptr(50), starting: true, elapsed: 120 * time.Second, want: 1},
		{name: "lost sensor", profile: "quiet", disks: unknown, sensor: ptr(50), want: 1},
		{name: "hot CPU overrides startup", profile: "quiet", disks: unknown, sensor: ptr(70), starting: true, want: 1},
		{name: "invalid overrides startup", profile: "quiet", disks: unknown, sensor: ptr(50), starting: true, invalid: true, want: 1},
		{name: "hot disk overrides unknown", profile: "quiet", disks: append(unknown, Disk{State: "active", Temperature: ptr(50)}), sensor: ptr(50), starting: true, want: 1},
		{name: "sleep stops fan", profile: "quiet", disks: sleep, sensor: ptr(50), want: 0},
		{name: "sleep hot CPU", profile: "quiet", disks: sleep, sensor: ptr(65), want: .75},
		{name: "sleep warm CPU starts fan", profile: "quiet", disks: sleep, sensor: ptr(57), want: .25},
		{name: "sleep CPU below start threshold", profile: "quiet", disks: sleep, sensor: ptr(51), want: 0},
		{name: "sleep CPU hysteresis keeps fan", profile: "quiet", disks: sleep, sensor: ptr(51), running: true, want: .25},
		{name: "sleep CPU cools down", profile: "quiet", disks: sleep, sensor: ptr(49), running: true, want: 0},
		{name: "sleep CPU 60-65", profile: "quiet", disks: sleep, sensor: ptr(62), want: .5},
		{name: "sleeping disk read cool", profile: "balanced", disks: readSleep(34), sensor: ptr(57), want: 0},
		{name: "sleeping disk read below start", profile: "balanced", disks: readSleep(36), sensor: ptr(57), want: 0},
		{name: "sleeping disk read starts fan", profile: "balanced", disks: readSleep(37), sensor: ptr(57), want: .5},
		{name: "sleeping disk read hysteresis", profile: "balanced", disks: readSleep(36), sensor: ptr(57), running: true, want: .5},
		{name: "sleeping disk read off below 35", profile: "balanced", disks: readSleep(34.9), sensor: ptr(57), running: true, want: 0},
		{name: "sleeping disk read curve", profile: "balanced", disks: readSleep(44), sensor: ptr(40), want: .75},
		{name: "sleeping disk read hot", profile: "balanced", disks: readSleep(46), sensor: ptr(40), want: 1},
		{name: "one unreadable sleeping disk uses CPU", profile: "balanced", disks: append(readSleep(30), Disk{State: "sleeping"}), sensor: ptr(57), want: .25},
		{name: "sleeping reading counts with active disks", profile: "balanced", disks: append(readSleep(44), Disk{State: "active", Temperature: ptr(31)}), sensor: ptr(40), want: .75},
		{name: "missing system sensor", profile: "quiet", disks: sleep, want: 1},
		{name: "cold", profile: "balanced", disks: cold, sensor: ptr(50), want: 0},
		{name: "stale cold", profile: "quiet", disks: cold, sensor: ptr(50), stale: true, want: 1},
		{name: "quiet curve", profile: "quiet", disks: warm, sensor: ptr(50), want: .25},
		{name: "balanced curve", profile: "balanced", disks: warm, sensor: ptr(50), want: .5},
		{name: "performance curve", profile: "performance", disks: warm, sensor: ptr(50), want: .75},
		{name: "missing temperature", profile: "quiet", disks: []Disk{{State: "active"}}, sensor: ptr(50), want: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := target(tc.profile, tc.disks, tc.sensor, tc.starting, tc.elapsed, tc.stale, tc.invalid, tc.running)
			if got != tc.want {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
	for name := range profiles {
		if v, _ := target(name, cold, ptr(65), false, 0, false, false, false); v == 0 {
			t.Fatalf("%s stopped with hot CPU", name)
		}
	}
}
func TestSMARTExitStatusAndHealth(t *testing.T) {
	for _, tc := range []struct {
		code               int
		raw, state, health string
	}{
		{3, `{}`, "unknown", "unknown"},
		{3, `{"smartctl":{"messages":[{"string":"Device is in STANDBY mode"}]}}`, "sleeping", "unknown"},
		{5, `{}`, "unknown", "unknown"},
		{0, `{"temperature":{"current":35},"smart_status":{"passed":true}}`, "active", "passed"},
		{8, `{"temperature":{"current":35}}`, "active", "failed"},
		{16, `{"temperature":{"current":35},"smart_status":{"passed":true}}`, "active", "warning"},
		{0, `{"temperature":{"current":150}}`, "unknown", "unknown"},
		{0, `{}`, "unknown", "unknown"},
		{0, `not json`, "unknown", "unknown"},
	} {
		d := parseDisk("/dev/test", []byte(tc.raw), tc.code)
		if d.State != tc.state || d.Health != tc.health {
			t.Fatalf("%+v: %+v", tc, d)
		}
	}
	d := parseDisk("x", []byte(`{"ata_smart_attributes":{"table":[{"id":194,"raw":{"value":35}},{"id":197,"name":"Current_Pending_Sector","raw":{"value":2}}]},"smart_status":{"passed":true}}`), 0)
	if d.Temperature == nil || *d.Temperature != 35 || d.Health != "warning" || len(d.Warnings) != 1 {
		t.Fatalf("%+v", d)
	}
}
func TestSleepingDiskRetainsStaleHealth(t *testing.T) {
	path := filepath.Join(t.TempDir(), "disk")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	old := parseDisk(path, []byte(`{"temperature":{"current":35},"smart_status":{"passed":true}}`), 0)
	got := cachedDisk(Disk{Path: path, State: "sleeping"}, old)
	if got.Health != "passed" || !got.Stale || got.State != "sleeping" || got.Temperature == nil || *got.Temperature != 35 {
		t.Fatalf("%+v", got)
	}
	got = cachedDisk(Disk{Path: path + "-missing", State: "unknown"}, old)
	if got.State != "unavailable" || !got.Stale {
		t.Fatalf("%+v", got)
	}
}
func TestCPUProfilePreservesCriticalTrip(t *testing.T) {
	root := t.TempDir()
	for name, value := range map[string]string{"type": "cpu-thermal", "trip_point_0_temp": "110000"} {
		if err := writeValue(filepath.Join(root, name), value); err != nil {
			t.Fatal(err)
		}
	}
	for i := 1; i <= 4; i++ {
		_ = writeValue(filepath.Join(root, fmt.Sprintf("trip_point_%d_type", i)), "active")
		_ = writeValue(filepath.Join(root, fmt.Sprintf("trip_point_%d_temp", i)), "75000")
	}
	if _, err := applyCPU("balanced", root); err != nil {
		t.Fatal(err)
	}
	if readText(filepath.Join(root, "trip_point_0_temp")) != "110000" || readText(filepath.Join(root, "trip_point_1_temp")) != "45000" || readText(filepath.Join(root, "trip_point_4_temp")) != "70000" {
		t.Fatal("wrong thresholds")
	}
	_ = writeValue(filepath.Join(root, "trip_point_4_type"), "critical")
	if _, err := applyCPU("quiet", root); err == nil {
		t.Fatal("accepted critical mapping")
	}
	if readText(filepath.Join(root, "trip_point_1_temp")) != "45000" {
		t.Fatal("partial update")
	}
}
func TestDisabledHardwareDoesNotAccessGPIO(t *testing.T) {
	h, err := openHardware(Wiring{Mode: "none"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err = h.tick(ctx, .5); err != nil {
		t.Fatal(err)
	}
	if h.control != nil || h.tach != nil || h.rpm != nil {
		t.Fatal("claimed GPIO")
	}
	if err = h.close(); err != nil {
		t.Fatal(err)
	}
}
func TestAtomicStatus(t *testing.T) {
	p := filepath.Join(t.TempDir(), "status.json")
	if err := atomicJSON(p, map[string]any{"dutyPercent": 50}); err != nil {
		t.Fatal(err)
	}
	if readText(p) != `{"dutyPercent":50}` {
		t.Fatal(readText(p))
	}
	info, _ := os.Stat(p)
	if info.Mode().Perm() != 0644 {
		t.Fatal(info.Mode())
	}
}

func TestLegacyConfigAndExplicitTachDisable(t *testing.T) {
	for _, tc := range []struct {
		extra   string
		mode    string
		control int
		tach    bool
	}{
		{``, "external-pwm", 27, false},
		{`,"hardwareMode":"internal-pwm"`, "internal-pwm", 18, true},
		{`,"hardwareMode":"internal-pwm","tachGPIO":null`, "internal-pwm", 18, false},
		{`,"hardwareMode":"none"`, "none", 27, false},
	} {
		c, err := decodeConfig([]byte(`{"profile":"balanced","sampleSeconds":60,"disks":[]` + tc.extra + `}`))
		if err != nil || c.HardwareMode != tc.mode || c.ControlGPIO != tc.control || (c.TachGPIO != nil) != tc.tach {
			t.Fatalf("%+v %v", c, err)
		}
	}
	for _, raw := range []string{`{"profile":"bad"}`, `{"profile":"balanced","sampleSeconds":1}`, `{"profile":"balanced","sampleSeconds":60,"hardwareMode":"internal-pwm","controlGPIO":27}`} {
		if _, err := decodeConfig([]byte(raw)); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
}

func TestKernelPinmuxRejectsPeripheralAndUnknownPins(t *testing.T) {
	for _, state := range []string{"gpio", "none"} {
		if err := freePinFunction("pin 18 (gpio18) 18:pinctrl-rp1 function "+state+" ("+state+") in lo", 18); err != nil {
			t.Fatal(err)
		}
	}
	for _, raw := range []string{"pin 18 (gpio18) 18:pinctrl-rp1 function pwm0 (alt3) out hi", "pin 19 (gpio19) 19:pinctrl-rp1 function gpio (gpio) in lo", "unknown"} {
		if err := freePinFunction(raw, 18); err == nil {
			t.Fatal("accepted " + raw)
		}
	}
}

func TestSleepTemperatureParsing(t *testing.T) {
	if v := sleepTemperature([]byte(`{"temperature":{"current":44}}`)); v == nil || *v != 44 {
		t.Fatalf("current temperature: %v", v)
	}
	if v := sleepTemperature([]byte(`{"ata_smart_attributes":{"table":[{"id":194,"raw":{"value":41}}]}}`)); v == nil || *v != 41 {
		t.Fatalf("attribute 194: %v", v)
	}
	for _, raw := range []string{`{}`, `{"temperature":{"current":120}}`, `not json`} {
		if v := sleepTemperature([]byte(raw)); v != nil {
			t.Fatalf("%s gave %v", raw, *v)
		}
	}
}

func TestCachedSleepingDisk(t *testing.T) {
	now := 100.0
	previous := Disk{State: "active", Temperature: ptr(38), Health: "passed", ObservedAt: &now}
	stale := cachedDisk(Disk{Path: "/dev/null", State: "sleeping"}, previous)
	if !stale.Stale || stale.Temperature == nil || *stale.Temperature != 38 || stale.Health != "passed" {
		t.Fatalf("stale cache: %+v", stale)
	}
	later := 200.0
	fresh := cachedDisk(Disk{Path: "/dev/null", State: "sleeping", Temperature: ptr(43), ObservedAt: &later, SleepTemperature: true}, previous)
	if fresh.Stale || *fresh.Temperature != 43 || *fresh.ObservedAt != 200 || fresh.Health != "passed" {
		t.Fatalf("fresh standby reading: %+v", fresh)
	}
}
