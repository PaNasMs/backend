package powercontrol

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, path string, raw []byte) {
	t.Helper()
	if e := os.MkdirAll(filepath.Dir(path), 0755); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(path, raw, 0644); e != nil {
		t.Fatal(e)
	}
}
func TestRenderPreservesBootSettingsAndIsIdempotent(t *testing.T) {
	original := []byte("# existing\n[pi5]\ndtoverlay=nospi10\n[all]\ndtparam=pciex1\n")
	for _, s := range []Settings{{true, 25}, {true, 26}, {false, 26}} {
		next, e := render(original, s)
		if e != nil {
			t.Fatal(e)
		}
		if !bytes.HasPrefix(next, original) {
			t.Fatal("changed existing boot settings")
		}
		parsed, _, e := parse(next)
		if e != nil || parsed != s {
			t.Fatalf("round trip: %+v %v", parsed, e)
		}
		again, e := render(next, s)
		if e != nil || !bytes.Equal(next, again) {
			t.Fatalf("not idempotent: %s", again)
		}
		count := strings.Count(string(next), "dtoverlay=gpio-poweroff,")
		if (s.Enabled && count != 1) || (!s.Enabled && count != 0) {
			t.Fatal("incorrect overlay count")
		}
	}
	enabled, _ := render(original, Settings{true, 25})
	disabled, _ := render(enabled, Settings{false, 26})
	if bytes.Contains(disabled, []byte("gpiopin=25")) {
		t.Fatal("old pin retained")
	}
}
func TestRejectMalformedBlocks(t *testing.T) {
	for _, raw := range []string{begin, end, begin + "\n# GPIO=25\n" + begin + "\n" + end, begin + "\n# GPIO=25\ndtoverlay=gpio-poweroff,gpiopin=26\n" + end, begin + "\n# GPIO=25\ndtoverlay=gpio-poweroff,gpiopin=25,active_low=1\n" + end, begin + "\n# GPIO=25\ndtparam=i2c_arm=on\n" + end} {
		if _, e := render([]byte(raw), Defaults()); e == nil {
			t.Fatalf("accepted %q", raw)
		}
	}
	for _, pin := range []int{-1, 0, 1, 28, 40} {
		if (Settings{GPIO: pin}).Validate() == nil {
			t.Fatalf("accepted GPIO%d", pin)
		}
	}
}
func TestConfiguredConsumers(t *testing.T) {
	root := t.TempDir()
	if e := checkConfigured(root, 25); e != nil {
		t.Fatal(e)
	}
	write(t, filepath.Join(root, "etc/panasms-cooling/config.json"), []byte(`{"hardwareMode":"internal-pwm","controlGPIO":18,"tachGPIO":24}`))
	write(t, filepath.Join(root, "etc/panasms/oled.json"), []byte(`{"enabled":true}`))
	for _, pin := range []int{2, 3, 18, 24} {
		if checkConfigured(root, pin) == nil {
			t.Fatalf("accepted busy GPIO%d", pin)
		}
	}
	if e := checkConfigured(root, 25); e != nil {
		t.Fatal(e)
	}
	write(t, filepath.Join(root, "etc/panasms-cooling/config.json"), []byte(`{"profile":"balanced"}`))
	if checkConfigured(root, 27) == nil {
		t.Fatal("legacy cooling pin not reserved")
	}
	write(t, filepath.Join(root, "etc/panasms-cooling/config.json"), []byte(`{"hardwareMode":"none","controlGPIO":25}`))
	if e := checkConfigured(root, 25); e != nil {
		t.Fatal(e)
	}
}
func TestIncludedOverlayConflict(t *testing.T) {
	root := t.TempDir()
	main := filepath.Join(root, "config.txt")
	write(t, main, []byte("include extra.txt\n"))
	write(t, filepath.Join(root, "extra.txt"), []byte("[pi5]\ndtoverlay=gpio-poweroff,gpiopin=26\n"))
	if checkIncludes(main, root, map[string]bool{}, true) == nil {
		t.Fatal("accepted included overlay")
	}
	write(t, filepath.Join(root, "extra.txt"), []byte("# dtoverlay=gpio-poweroff\n"))
	if e := checkIncludes(main, root, map[string]bool{}, true); e != nil {
		t.Fatal(e)
	}
}
func TestPendingStateReservesOldAndNewPins(t *testing.T) {
	root := t.TempDir()
	boot := filepath.Join(root, bootPath)
	raw, _ := render(nil, Settings{true, 25})
	write(t, boot, raw)
	state, e := readState(root, true)
	if e != nil || !state.RebootRequired || state.ActiveGPIO != nil {
		t.Fatalf("before reboot: %+v %v", state, e)
	}
	driver := filepath.Join(root, "sys/bus/platform/drivers/poweroff-gpio/power_ctrl/of_node/gpios")
	gpio := make([]byte, 12)
	binary.BigEndian.PutUint32(gpio[4:8], 25)
	write(t, driver, gpio)
	state, e = readState(root, true)
	if e != nil || state.RebootRequired || *state.ActiveGPIO != 25 {
		t.Fatalf("after reboot: %+v %v", state, e)
	}
	raw, _ = render(raw, Settings{true, 26})
	write(t, boot, raw)
	state, e = readState(root, true)
	if e != nil || !state.RebootRequired {
		t.Fatalf("pin change: %+v %v", state, e)
	}
	for _, pin := range []int{25, 26} {
		if state.checkPins(pin) == nil {
			t.Fatalf("released reserved pin %d", pin)
		}
	}
	raw, _ = render(raw, Settings{false, 26})
	write(t, boot, raw)
	state, e = readState(root, true)
	if e != nil || !state.RebootRequired || state.checkPins(25) == nil || state.checkPins(26) != nil {
		t.Fatalf("disable pending: %+v %v", state, e)
	}
	gpio[11] = 1
	write(t, driver, gpio)
	if _, e = readState(root, true); e == nil {
		t.Fatal("accepted active-low configuration")
	}
}

func TestDecodeRequiresExplicitSettings(t *testing.T) {
	for _, raw := range []string{`null`, `{}`, `{"enabled":true}`, `{"gpio":25}`, `{"enabled":null,"gpio":25}`, `{"enabled":true,"gpio":25,"activeLow":true}`, `{"enabled":true,"gpio":40}`, `{"enabled":true,"gpio":25} {}`} {
		if _, e := Decode(strings.NewReader(raw)); e == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
	s, e := Decode(strings.NewReader(`{"enabled":true,"gpio":25}`))
	if e != nil || s != (Settings{true, 25}) {
		t.Fatalf("%+v %v", s, e)
	}
}
