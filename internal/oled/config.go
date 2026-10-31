package oled

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"panasms.local/backend/internal/powercontrol"
)

const ConfigPath = "/etc/panasms/oled.json"
const StatusPath = "/run/panasms-oled/status.json"

type Settings struct {
	Layout      string `json:"layout"`
	PageSeconds int    `json:"pageSeconds"`
	Enabled     bool   `json:"enabled"`
	Brightness  int    `json:"brightness"`
	Rotation    int    `json:"rotation"`
	Bus         int    `json:"bus"`
	SDA         int    `json:"sda"`
	SCL         int    `json:"scl"`
	Address     int    `json:"address"`
	Controller  string `json:"controller"`
	ShowIP      bool   `json:"showIP"`
	ShowCPU     bool   `json:"showCPU"`
	ShowDisks   bool   `json:"showDisks"`
}
type Status struct {
	ObservedAt time.Time `json:"observedAt"`
	Applied    Settings  `json:"applied"`
	Error      string    `json:"error"`
	Lines      []string  `json:"lines"`
}
type State struct {
	Config    Settings `json:"config"`
	Supported bool     `json:"supported"`
	State     string   `json:"state"`
	Status    Status   `json:"status"`
}

func Defaults() Settings {
	return Settings{Layout: "compact", PageSeconds: 6, Brightness: 25, Bus: 1, SDA: 2, SCL: 3, Address: 0x3c, Controller: "ssd1306", ShowIP: true, ShowCPU: true, ShowDisks: true}
}
func (s Settings) Validate() error {
	if s.Layout != "compact" && s.Layout != "large" && s.Layout != "disks" && s.Layout != "pages" {
		return errors.New("Invalid OLED layout")
	}
	if s.PageSeconds < 4 || s.PageSeconds > 60 {
		return errors.New("OLED page interval must be 4..60 seconds")
	}
	bus, validPins := map[int]int{2: 1, 10: 1, 4: 2, 12: 2, 6: 3, 14: 3, 22: 3, 8: 0}[s.SDA]
	if s.Brightness < 1 || s.Brightness > 100 || (s.Rotation != 0 && s.Rotation != 180) || !validPins || s.SCL != s.SDA+1 || s.Bus != bus || (s.Address != 0x3c && s.Address != 0x3d) || (s.Controller != "ssd1306" && s.Controller != "sh1106") {
		return errors.New("Invalid OLED settings")
	}
	if s.Enabled && !s.ShowIP && !s.ShowCPU && !s.ShowDisks {
		return errors.New("Select at least one OLED reading")
	}
	return nil
}
func readConfig(path string) (Settings, error) {
	s := Defaults()
	raw, e := os.ReadFile(path)
	if errors.Is(e, os.ErrNotExist) {
		return s, nil
	}
	if e != nil {
		return s, e
	}
	if e = json.Unmarshal(raw, &s); e != nil {
		return s, e
	}
	return s, s.Validate()
}
func Supported() bool {
	raw, _ := os.ReadFile("/proc/device-tree/model")
	if !strings.Contains(string(raw), "Raspberry Pi 5") {
		return false
	}
	for _, tool := range []string{"pinctrl", "dtoverlay", "modprobe"} {
		if _, e := exec.LookPath(tool); e != nil {
			return false
		}
	}
	_, e := os.Stat("/boot/firmware/overlays/i2c1-pi5.dtbo")
	return e == nil
}
func Read() (State, error) { return readState(ConfigPath, StatusPath, Supported(), time.Now()) }
func readState(config, status string, supported bool, now time.Time) (State, error) {
	s := State{Supported: supported, State: "disabled", Status: Status{Applied: Defaults(), Lines: []string{}}}
	var e error
	s.Config, e = readConfig(config)
	if e != nil {
		return s, e
	}
	if !s.Config.Enabled {
		return s, nil
	}
	s.State = "unavailable"
	raw, e := os.ReadFile(status)
	if e == nil && json.Unmarshal(raw, &s.Status) == nil && !s.Status.ObservedAt.IsZero() && now.Sub(s.Status.ObservedAt) >= 0 && now.Sub(s.Status.ObservedAt) < 10*time.Second {
		if s.Status.Applied != s.Config {
			s.State = "starting"
		} else if s.Status.Error != "" {
			s.State = "error"
		} else {
			s.State = "active"
		}
	}
	return s, nil
}
func atomicJSON(path string, value any) error {
	raw, e := json.Marshal(value)
	if e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".oled-*")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if e = f.Chmod(0644); e != nil {
		return e
	}
	if _, e = f.Write(append(raw, '\n')); e != nil {
		return e
	}
	if e = f.Sync(); e != nil {
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	return os.Rename(f.Name(), path)
}
func run(ctx context.Context, name string, args ...string) error {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	raw, e := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if e != nil {
		return fmt.Errorf("%s: %w: %s", name, e, strings.TrimSpace(string(raw)))
	}
	return nil
}
func Configure(ctx context.Context, in io.Reader) error {
	unlock, e := powercontrol.Lock()
	if e != nil {
		return e
	}
	defer unlock()
	s := Defaults()
	d := json.NewDecoder(io.LimitReader(in, 4097))
	d.DisallowUnknownFields()
	if d.Decode(&s) != nil || d.Decode(new(any)) != io.EOF {
		return errors.New("Invalid OLED settings")
	}
	if e := s.Validate(); e != nil {
		return e
	}
	if s.Enabled && !Supported() {
		return errors.New("I2C display is not supported on this system")
	}
	f, e := os.OpenFile("/run/lock/panasms-oled-config.lock", os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return e
	}
	defer f.Close()
	if e = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); e != nil {
		return errors.New("OLED settings are already being applied")
	}
	defer unix.Flock(int(f.Fd()), unix.LOCK_UN)
	if s.Enabled {
		if e = checkCooling(s); e != nil {
			return e
		}
	}
	old, e := readConfig(ConfigPath)
	if e != nil {
		return e
	}
	if e = atomicJSON(ConfigPath, s); e != nil {
		return e
	}
	if e = applyService(ctx, s); e != nil {
		if restoreErr := atomicJSON(ConfigPath, old); restoreErr != nil {
			return fmt.Errorf("%w; configuration rollback failed: %v", e, restoreErr)
		}
		recovery, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if restoreErr := applyService(recovery, old); restoreErr != nil {
			return fmt.Errorf("%w; service recovery failed: %v", e, restoreErr)
		}
		return e
	}
	return nil
}
func applyService(ctx context.Context, s Settings) error {
	if !s.Enabled {
		return run(ctx, "systemctl", "disable", "--now", "panasms-oled.service")
	}
	if e := run(ctx, "systemctl", "enable", "panasms-oled.service"); e != nil {
		return e
	}
	return run(ctx, "systemctl", "restart", "panasms-oled.service")
}
func Restore(ctx context.Context) error {
	s, e := readConfig(ConfigPath)
	if e != nil {
		return e
	}
	if !s.Enabled {
		return run(ctx, "systemctl", "disable", "--now", "panasms-oled.service")
	}
	return applyService(ctx, s)
}
