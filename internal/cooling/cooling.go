package cooling

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Settings struct {
	CPUProfile    string `json:"cpuProfile"`
	Profile       string `json:"profile"`
	SampleSeconds int    `json:"sampleSeconds"`
}
type config struct {
	Settings
	Disks []string `json:"disks"`
}

var mu sync.Mutex

const configPath = "/etc/ostojaos-cooling/config.json"

func Validate(s Settings) error {
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
	if cfg.CPUProfile == "" {
		cfg.CPUProfile = "balanced"
	}
	raw, err = os.ReadFile("/run/ostojaos-cooling/status.json")
	if err != nil {
		return nil, err
	}
	var status map[string]any
	if err = json.Unmarshal(raw, &status); err != nil {
		return nil, err
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
	cfg.Settings = settings
	raw, err = json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
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
