package cooling

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Settings struct {
	CPUProfile    string `json:"cpuProfile"`
	Profile       string `json:"profile"`
	SampleSeconds int    `json:"sampleSeconds"`
	HardwareMode  string `json:"hardwareMode"`
	ControlGPIO   int    `json:"controlGPIO"`
	TachGPIO      *int   `json:"tachGPIO"`
}
type config struct {
	Settings
	Disks []string `json:"disks"`
}

var mu sync.Mutex

const configPath = "/etc/panasms-cooling/config.json"

func normalize(s Settings) Settings {
	if s.HardwareMode == "" {
		s.HardwareMode = "external-pwm"
		s.ControlGPIO = 27
	}
	return s
}

func Validate(s Settings) error {
	s = normalize(s)
	if s.HardwareMode != "none" && s.HardwareMode != "external-pwm" && s.HardwareMode != "internal-pwm" {
		return errors.New("unknown cooling hardware")
	}
	if s.HardwareMode != "none" {
		if s.ControlGPIO < 2 || s.ControlGPIO > 27 {
			return errors.New("control GPIO must be 2..27")
		}
		if s.HardwareMode == "internal-pwm" && s.ControlGPIO != 12 && s.ControlGPIO != 13 && s.ControlGPIO != 18 && s.ControlGPIO != 19 {
			return errors.New("hardware PWM requires GPIO12, 13, 18 or 19")
		}
		if s.TachGPIO != nil && (*s.TachGPIO < 2 || *s.TachGPIO > 27 || *s.TachGPIO == s.ControlGPIO) {
			return errors.New("invalid tachometer GPIO")
		}
	}
	if s.Profile != "quiet" && s.Profile != "balanced" && s.Profile != "performance" {
		return errors.New("unknown cooling profile")
	}
	if s.CPUProfile != "quiet" && s.CPUProfile != "balanced" && s.CPUProfile != "performance" {
		return errors.New("unknown CPU profile")
	}
	if s.SampleSeconds < 30 || s.SampleSeconds > 600 {
		return errors.New("sample interval must be 30..600 seconds")
	}
	return nil
}
func Read() (any, error) {
	raw, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}
	var cfg config
	if err = json.Unmarshal(raw, &cfg); err != nil {
		return nil, err
	}
	cfg.Settings = normalize(cfg.Settings)
	if cfg.CPUProfile == "" {
		cfg.CPUProfile = "balanced"
	}
	raw, err = os.ReadFile("/run/panasms-cooling/status.json")
	status := map[string]any{"dutyPercent": 0, "reason": "unavailable", "disks": []any{}, "observedAt": 0, "profile": cfg.Profile}
	if err == nil {
		_ = json.Unmarshal(raw, &status)
	}
	observed, _ := status["observedAt"].(float64)
	return map[string]any{"config": cfg.Settings, "status": status, "available": time.Now().Unix()-int64(observed) < 5}, nil
}
func Save(settings Settings) error {
	if err := Validate(settings); err != nil {
		return err
	}
	mu.Lock()
	defer mu.Unlock()
	raw, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}
	var cfg config
	if err = json.Unmarshal(raw, &cfg); err != nil {
		return err
	}
	previous := append([]byte(nil), raw...)
	old := normalize(cfg.Settings)
	if settings.HardwareMode == "" {
		settings.HardwareMode, settings.ControlGPIO, settings.TachGPIO = old.HardwareMode, old.ControlGPIO, old.TachGPIO
	}
	cfg.Settings = settings
	raw, err = json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	if err = writeConfig(raw); err != nil {
		return err
	}
	if old.HardwareMode == settings.HardwareMode && old.ControlGPIO == settings.ControlGPIO && samePin(old.TachGPIO, settings.TachGPIO) {
		return nil
	}
	deadline := time.Now().Add(12 * time.Second)
	for time.Now().Before(deadline) {
		stateRaw, readErr := os.ReadFile("/run/panasms-cooling/status.json")
		var state struct {
			Attempt  Settings `json:"hardwareAttempt"`
			Error    string   `json:"hardwareError"`
			Observed float64  `json:"observedAt"`
		}
		if readErr == nil && json.Unmarshal(stateRaw, &state) == nil && time.Now().Unix()-int64(state.Observed) < 5 && state.Attempt.HardwareMode == settings.HardwareMode && state.Attempt.ControlGPIO == settings.ControlGPIO && samePin(state.Attempt.TachGPIO, settings.TachGPIO) {
			if state.Error == "" {
				return nil
			}
			if err := writeConfig(previous); err != nil {
				return fmt.Errorf("%s; configuration rollback failed: %w", state.Error, err)
			}
			return errors.New(state.Error)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err := writeConfig(previous); err != nil {
		return fmt.Errorf("cooling controller did not apply settings; rollback failed: %w", err)
	}
	return errors.New("cooling controller did not apply settings; previous configuration restored")
}

func samePin(a, b *int) bool { return (a == nil && b == nil) || (a != nil && b != nil && *a == *b) }

func writeConfig(raw []byte) error {
	file, err := os.CreateTemp(filepath.Dir(configPath), ".config-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	if err = file.Chmod(0644); err != nil {
		return err
	}
	if _, err = file.Write(append(raw, '\n')); err != nil {
		return err
	}
	if err = file.Sync(); err != nil {
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), configPath)
}
