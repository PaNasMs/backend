package cooling

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestCapabilities(t *testing.T) {
	root := t.TempDir()
	put := func(path, value string) {
		t.Helper()
		target := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, []byte(value), 0644); err != nil {
			t.Fatal(err)
		}
	}
	if got := DetectCapabilities(root); got.CPU || got.Disk {
		t.Fatal(got)
	}
	put("sys/class/hwmon/hwmon0/temp1_input", "40000")
	if got := DetectCapabilities(root); got.CPU || got.Disk {
		t.Fatal("temperature is not fan control", got)
	}
	put("sys/class/thermal/thermal_zone0/type", "cpu-thermal\n")
	for i := 1; i <= 4; i++ {
		put(fmt.Sprintf("sys/class/thermal/thermal_zone0/trip_point_%d_type", i), "active\n")
		put(fmt.Sprintf("sys/class/thermal/thermal_zone0/trip_point_%d_temp", i), "50000")
	}
	if got := DetectCapabilities(root); !got.CPU || got.Disk {
		t.Fatal(got)
	}
	put("sys/class/thermal/thermal_zone0/trip_point_4_type", "critical")
	if DetectCapabilities(root).CPU {
		t.Fatal("unsupported trip mapping")
	}
	put("proc/device-tree/model", "Raspberry Pi 5 Model B Rev 1.0\x00")
	put("sys/class/gpio/gpiochip571/label", "pinctrl-rp1\n")
	if DetectCapabilities(root).Disk {
		t.Fatal("missing character device")
	}
	put("dev/gpiochip0", "")
	if !DetectCapabilities(root).Disk {
		t.Fatal("RP1 not detected before fan configuration")
	}
	dir := cpuPolicies + "/policy0/"
	put(dir+"scaling_min_freq", "1500000")
	put(dir+"cpuinfo_max_freq", "2400000")
	put(dir+"scaling_max_freq", "2400000")
	put(dir+"scaling_available_frequencies", "1500000 1800000 2400000")
	for _, tc := range []struct {
		selected int
		expected string
	}{{1800000, "1800000"}, {0, "2400000"}} {
		if err := ApplyFrequency(root, tc.selected); err != nil {
			t.Fatal(err)
		}
		raw, _ := os.ReadFile(filepath.Join(root, dir, "scaling_max_freq"))
		if string(raw) != tc.expected {
			t.Fatal(string(raw))
		}
	}
	if ApplyFrequency(root, 1700000) == nil {
		t.Fatal("unadvertised clock accepted")
	}
	put("proc/device-tree/model", "Other board")
	if len(cpuFrequencies(root)) != 0 || ApplyFrequency(root, 1800000) == nil {
		t.Fatal("non-Pi clock control enabled")
	}
	if DetectCapabilities(root).Disk {
		t.Fatal("unsupported board")
	}
}

func TestUnsupportedControlChanges(t *testing.T) {
	old := Settings{HardwareMode: "none", CPUProfile: "balanced", Profile: "balanced", SampleSeconds: 60}
	next := old
	next.SampleSeconds = 90
	if err := validateCapabilities(old, next, Capabilities{}); err != nil {
		t.Fatal(err)
	}
	next.HardwareMode = "internal-pwm"
	if validateCapabilities(old, next, Capabilities{}) == nil {
		t.Fatal("allowed unsupported disk control")
	}
	next = old
	next.CPUProfile = "quiet"
	if validateCapabilities(old, next, Capabilities{}) == nil {
		t.Fatal("allowed unsupported CPU control")
	}
	if err := validateCapabilities(old, next, Capabilities{CPU: true}); err != nil {
		t.Fatal(err)
	}
	old.HardwareMode = "internal-pwm"
	next = old
	next.HardwareMode = "none"
	if err := validateCapabilities(old, next, Capabilities{}); err != nil {
		t.Fatal("cannot disable missing hardware", err)
	}
}

func TestReadWithoutOptionalController(t *testing.T) {
	state, err := readState(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	data := state.(map[string]any)
	if data["configured"] != false || data["available"] != false {
		t.Fatal(data)
	}
	if caps := data["capabilities"].(Capabilities); caps.CPU || caps.Disk {
		t.Fatal(caps)
	}
	if settings := data["config"].(Settings); settings.HardwareMode != "none" {
		t.Fatal(settings)
	}
}

func TestReadPreservesLegacyWiring(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, configPath)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"profile":"balanced","sampleSeconds":60}`), 0644); err != nil {
		t.Fatal(err)
	}
	state, err := readState(root)
	if err != nil {
		t.Fatal(err)
	}
	cfg := state.(map[string]any)["config"].(Settings)
	if cfg.HardwareMode != "external-pwm" || cfg.ControlGPIO != 27 {
		t.Fatal(cfg)
	}
}
