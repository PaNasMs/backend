package powercontrol

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

const bootPath = "/boot/firmware/config.txt"
const begin = "# PaNasMs power control"
const end = "# End PaNasMs power control"

type Settings struct {
	Enabled bool `json:"enabled"`
	GPIO    int  `json:"gpio"`
}
type State struct {
	Config         Settings `json:"config"`
	Supported      bool     `json:"supported"`
	ActiveGPIO     *int     `json:"activeGPIO"`
	RebootRequired bool     `json:"rebootRequired"`
}

func Defaults() Settings { return Settings{GPIO: 25} }
func (s Settings) Validate() error {
	if s.GPIO < 2 || s.GPIO > 27 {
		return errors.New("Power control GPIO must be between 2 and 27")
	}
	return nil
}
func Lock() (func(), error) {
	f, e := os.OpenFile("/run/lock/panasms-gpio-settings.lock", os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	if e = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); e != nil {
		f.Close()
		return nil, errors.New("GPIO settings are already being applied")
	}
	return func() { unix.Flock(int(f.Fd()), unix.LOCK_UN); f.Close() }, nil
}
func parse(raw []byte) (Settings, string, error) {
	s := Defaults()
	text := string(raw)
	start, finish := strings.Index(text, begin), strings.Index(text, end)
	if start < 0 && finish < 0 {
		return s, text, nil
	}
	if start < 0 || finish < start || strings.Count(text, begin) != 1 || strings.Count(text, end) != 1 {
		return s, "", errors.New("Invalid managed power control block in boot configuration")
	}
	if strings.TrimSpace(text[finish+len(end):]) != "" {
		return s, "", errors.New("Managed power control block must be last in boot configuration")
	}
	block := text[start+len(begin) : finish]
	var declared *int
	overlays := 0
	for _, line := range strings.Split(block, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line == "[all]" {
			continue
		}
		if !strings.HasPrefix(line, "# GPIO=") && !strings.HasPrefix(line, "dtoverlay=") {
			return s, "", errors.New("Unexpected content in managed power control block")
		}
		if strings.HasPrefix(line, "# GPIO=") {
			n, e := strconv.Atoi(strings.TrimPrefix(line, "# GPIO="))
			if e != nil {
				return s, "", e
			}
			if declared != nil {
				return s, "", errors.New("Duplicate GPIO in managed power control block")
			}
			declared = &n
			if !s.Enabled {
				s.GPIO = n
			}
		}
		if strings.HasPrefix(line, "dtoverlay=") {
			value, ok := strings.CutPrefix(line, "dtoverlay=gpio-poweroff,gpiopin=")
			if !ok {
				return s, "", errors.New("Unexpected overlay in managed power control block")
			}
			n, e := strconv.Atoi(value)
			if e != nil {
				return s, "", e
			}
			overlays++
			if overlays > 1 {
				return s, "", errors.New("Duplicate overlay in managed power control block")
			}
			s.Enabled = true
			s.GPIO = n
		}
	}
	if declared == nil || s.GPIO != *declared {
		return s, "", errors.New("Inconsistent GPIO in managed power control block")
	}
	return s, text[:start] + text[finish+len(end):], s.Validate()
}
func render(raw []byte, s Settings) ([]byte, error) {
	_, outside, e := parse(raw)
	if e != nil {
		return nil, e
	}
	block := fmt.Sprintf("\n%s\n[all]\n# GPIO=%d\n", begin, s.GPIO)
	if s.Enabled {
		block += fmt.Sprintf("dtoverlay=gpio-poweroff,gpiopin=%d\n", s.GPIO)
	}
	return []byte(strings.TrimRight(outside, "\n") + "\n" + block + end + "\n"), nil
}
func supported() bool {
	model, e := os.ReadFile("/proc/device-tree/model")
	if e != nil || !strings.Contains(string(model), "Raspberry Pi 5") {
		return false
	}
	_, e = os.Stat("/boot/firmware/overlays/gpio-poweroff.dtbo")
	return e == nil
}
func active(root string) (*int, error) {
	paths, e := filepath.Glob(filepath.Join(root, "sys/bus/platform/drivers/poweroff-gpio/*/of_node/gpios"))
	if e != nil {
		return nil, e
	}
	if len(paths) == 0 {
		return nil, nil
	}
	if len(paths) != 1 {
		return nil, errors.New("Multiple power-off GPIO drivers are active")
	}
	raw, e := os.ReadFile(paths[0])
	if e != nil {
		return nil, e
	}
	if len(raw) != 12 || binary.BigEndian.Uint32(raw[8:]) != 0 {
		return nil, errors.New("Unsupported active power-off GPIO configuration")
	}
	pin := int(binary.BigEndian.Uint32(raw[4:8]))
	return &pin, nil
}
func Read() (State, error) {
	return readState("/", supported())
}
func readState(root string, supported bool) (State, error) {
	state := State{Config: Defaults(), Supported: supported}
	raw, e := os.ReadFile(filepath.Join(root, bootPath))
	if os.IsNotExist(e) && !state.Supported {
		return state, nil
	}
	if e != nil {
		return state, e
	}
	state.Config, _, e = parse(raw)
	if e != nil {
		return state, e
	}
	state.ActiveGPIO, e = active(root)
	if e != nil {
		return state, e
	}
	state.RebootRequired = state.Config.Enabled != (state.ActiveGPIO != nil) || state.ActiveGPIO != nil && state.Config.Enabled && *state.ActiveGPIO != state.Config.GPIO
	return state, nil
}
func CheckPins(pins ...int) error {
	state, e := Read()
	if e != nil {
		return e
	}
	return state.checkPins(pins...)
}
func (state State) checkPins(pins ...int) error {
	for _, pin := range pins {
		if state.Config.Enabled && pin == state.Config.GPIO || state.ActiveGPIO != nil && pin == *state.ActiveGPIO {
			return fmt.Errorf("GPIO%d is reserved for power control", pin)
		}
	}
	return nil
}
func readJSON(path string, v any) error {
	raw, e := os.ReadFile(path)
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	return json.Unmarshal(raw, v)
}
func checkConfigured(root string, pin int) error {
	c := struct {
		HardwareMode string `json:"hardwareMode"`
		ControlGPIO  int    `json:"controlGPIO"`
		TachGPIO     *int   `json:"tachGPIO"`
	}{}
	if _, e := os.Stat(filepath.Join(root, "etc/panasms-cooling/config.json")); os.IsNotExist(e) {
		c.HardwareMode = "none"
	}
	if e := readJSON(filepath.Join(root, "etc/panasms-cooling/config.json"), &c); e != nil {
		return e
	}
	if c.HardwareMode == "" {
		c.HardwareMode = "external-pwm"
		c.ControlGPIO = 27
	}
	if c.HardwareMode != "none" && (pin == c.ControlGPIO || c.TachGPIO != nil && pin == *c.TachGPIO) {
		return fmt.Errorf("GPIO%d is assigned to cooling", pin)
	}
	d := struct {
		Enabled bool `json:"enabled"`
		SDA     int  `json:"sda"`
		SCL     int  `json:"scl"`
	}{SDA: 2, SCL: 3}
	if e := readJSON(filepath.Join(root, "etc/panasms/oled.json"), &d); e != nil {
		return e
	}
	if d.Enabled && (pin == d.SDA || pin == d.SCL) {
		return fmt.Errorf("GPIO%d is assigned to the OLED display", pin)
	}
	return nil
}
func checkUnmanaged(path string, seen map[string]bool) error {
	firmware := filepath.Dir(bootPath)
	return checkIncludes(path, firmware, seen, true)
}
func checkIncludes(path, firmware string, seen map[string]bool, main bool) error {
	path = filepath.Clean(path)
	if seen[path] {
		return nil
	}
	seen[path] = true
	raw, e := os.ReadFile(path)
	if e != nil {
		return e
	}
	if !main && strings.Contains(string(raw), begin) {
		return errors.New("Power control block must be in the main boot configuration")
	}
	_, outside, e := parse(raw)
	if e != nil {
		return e
	}
	for _, line := range strings.Split(outside, "\n") {
		line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		if strings.HasPrefix(line, "dtoverlay=gpio-poweroff") {
			return errors.New("An unmanaged gpio-poweroff overlay already exists in boot configuration")
		}
		if strings.HasPrefix(line, "include ") {
			name := strings.TrimSpace(strings.TrimPrefix(line, "include "))
			p := filepath.Join(filepath.Dir(path), name)
			if !strings.HasPrefix(p, firmware+string(os.PathSeparator)) {
				return errors.New("Cannot verify GPIO configuration outside the firmware directory")
			}
			if e := checkIncludes(p, firmware, seen, false); e != nil {
				return e
			}
		}
	}
	return nil
}
func Decode(in io.Reader) (Settings, error) {
	var body struct {
		Enabled *bool `json:"enabled"`
		GPIO    *int  `json:"gpio"`
	}
	d := json.NewDecoder(io.LimitReader(in, 4097))
	d.DisallowUnknownFields()
	if d.Decode(&body) != nil || d.Decode(new(any)) != io.EOF || body.Enabled == nil || body.GPIO == nil {
		return Settings{}, errors.New("Invalid power control settings")
	}
	s := Settings{Enabled: *body.Enabled, GPIO: *body.GPIO}
	return s, s.Validate()
}
func Configure(in io.Reader) error {
	s, e := Decode(in)
	if e != nil {
		return e
	}
	unlock, e := Lock()
	if e != nil {
		return e
	}
	defer unlock()
	if !supported() {
		return errors.New("Power control requires Raspberry Pi 5 and the gpio-poweroff overlay")
	}
	if e = checkUnmanaged(bootPath, map[string]bool{}); e != nil {
		return e
	}
	state, e := Read()
	if e != nil {
		return e
	}
	if s.Enabled {
		if e = checkConfigured("/", s.GPIO); e != nil {
			return e
		}
		if state.ActiveGPIO == nil || *state.ActiveGPIO != s.GPIO {
			if e = checkAvailable(s.GPIO); e != nil {
				return e
			}
		}
	}
	raw, e := os.ReadFile(bootPath)
	if e != nil {
		return e
	}
	next, e := render(raw, s)
	if e != nil {
		return e
	}
	if bytes.Equal(raw, next) {
		return nil
	}
	f, e := os.CreateTemp(filepath.Dir(bootPath), ".panasms-power-*")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if e = f.Chmod(0644); e != nil {
		return e
	}
	if _, e = f.Write(next); e != nil {
		return e
	}
	if e = f.Sync(); e != nil {
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	if e = os.Rename(f.Name(), bootPath); e != nil {
		return e
	}
	dir, e := os.Open(filepath.Dir(bootPath))
	if e != nil {
		return e
	}
	defer dir.Close()
	return dir.Sync()
}
