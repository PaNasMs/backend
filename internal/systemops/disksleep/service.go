package disksleep

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"panasms.local/backend/internal/systemops"
)

type config struct {
	Minutes int `json:"minutes"`
}
type service struct {
	config, state, lock, sys, fstab, uptime string
	run                                     func(string, ...string) ([]byte, int, error)
}

func defaultService() *service {
	return &service{"/etc/panasms/disk-sleep.json", "/run/panasms-disk-sleep/state.json", "/run/panasms-disk-sleep.lock", "/sys/class/block", "/etc/fstab", "/proc/uptime", run}
}
func run(name string, args ...string) ([]byte, int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	data, err := cmd.Output()
	code := 0
	if err != nil {
		code = -1
		var e *exec.ExitError
		if errors.As(err, &e) {
			code = e.ExitCode()
		}
	}
	return data, code, err
}
func valid(minutes int) error {
	for _, m := range []int{0, 5, 10, 15, 20, 30, 60, 120, 180, 300} {
		if m == minutes {
			return nil
		}
	}
	return fmt.Errorf("Select a sleep timeout from the list")
}
func (s *service) readConfig() (*config, error) {
	raw, err := os.ReadFile(s.config)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return decodeConfig(raw)
}
func decodeConfig(raw []byte) (*config, error) {
	var input struct {
		Minutes *int `json:"minutes"`
	}
	if err := json.Unmarshal(raw, &input); err != nil {
		return nil, err
	}
	if input.Minutes == nil {
		return nil, fmt.Errorf("Select a sleep timeout from the list")
	}
	if err := valid(*input.Minutes); err != nil {
		return nil, err
	}
	return &config{*input.Minutes}, nil
}
func (s *service) now() (float64, error) {
	raw, err := os.ReadFile(s.uptime)
	if err != nil {
		return 0, err
	}
	fields := strings.Fields(string(raw))
	if len(fields) == 0 {
		return 0, fmt.Errorf("system uptime unavailable")
	}
	return strconv.ParseFloat(fields[0], 64)
}
func (s *service) readState() (map[string]state, error) {
	result := map[string]state{}
	raw, err := os.ReadFile(s.state)
	if os.IsNotExist(err) {
		return result, nil
	}
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal(raw, &result); err != nil {
		return nil, err
	}
	if result == nil {
		result = map[string]state{}
	}
	return result, nil
}
func (s *service) writeState(data map[string]state) error {
	raw, err := json.Marshal(data)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(s.state), 0755); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(s.state), ".state-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if err = f.Chmod(0644); err != nil {
		return err
	}
	if _, err = f.Write(raw); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), s.state)
}
func (s *service) locked(nonblock bool, fn func() error) error {
	f, err := os.OpenFile(s.lock, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	flags := unix.LOCK_EX
	if nonblock {
		flags |= unix.LOCK_NB
	}
	if err = unix.Flock(int(f.Fd()), flags); err != nil {
		if nonblock && errors.Is(err, unix.EWOULDBLOCK) {
			return nil
		}
		return err
	}
	defer unix.Flock(int(f.Fd()), unix.LOCK_UN)
	return fn()
}
func (s *service) apply(disable bool) error {
	return s.locked(true, func() error {
		cfg, err := s.readConfig()
		if err != nil || cfg == nil {
			return err
		}
		if disable {
			cfg.Minutes = 0
		}
		disks, err := s.inventory()
		if err != nil {
			return err
		}
		previous, err := s.readState()
		if err != nil {
			previous = map[string]state{}
		}
		now, err := s.now()
		if err != nil {
			return err
		}
		current := map[string]state{}
		for _, d := range disks {
			old := previous[d.Key]
			if disable {
				old.Version = 0
			}
			next, e := s.step(d, old, cfg.Minutes, now)
			next.Device = d.Path
			next.Minutes = cfg.Minutes
			if e != nil {
				next.Status = "error"
				next.Error = e.Error()
				next.IdleSince = now
				next.Sleeping = false
			}
			current[d.Key] = next
		}
		return s.writeState(current)
	})
}
func (s *service) save(cfg *config) error {
	if err := s.locked(false, func() error {
		raw, _ := json.Marshal(cfg)
		if err := systemops.AtomicWrite(s.config, string(raw), 0600); err != nil {
			return err
		}
		return s.writeState(map[string]state{})
	}); err != nil {
		return err
	}
	for _, args := range [][]string{{"enable", "--now", "panasms-disk-sleep.timer"}, {"start", "panasms-disk-sleep.service"}} {
		if _, _, err := s.run("systemctl", args...); err != nil {
			return err
		}
	}
	return nil
}
func (s *service) query() (any, error) {
	cfg, err := s.readConfig()
	if err != nil {
		return nil, err
	}
	states, err := s.readState()
	if err != nil {
		return nil, err
	}
	disks, err := s.inventory()
	if err != nil {
		return nil, err
	}
	now, err := s.now()
	if err != nil {
		return nil, err
	}
	props, _, e := s.run("systemctl", "show", "panasms-disk-sleep.timer", "--property=ActiveState,UnitFileState")
	p := map[string]string{}
	for _, line := range strings.Split(string(props), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if ok {
			p[k] = v
		}
	}
	active, enabled := p["ActiveState"] == "active", p["UnitFileState"] == "enabled"
	applied, failed, busy := 0, false, false
	for _, d := range disks {
		st := states[d.Key]
		if st.Status == "error" {
			failed = true
		}
		if st.Status == "busy" {
			busy = true
		}
		if cfg != nil && st.Version == 1 && st.Minutes == cfg.Minutes && st.Status == "applied" && now >= st.Seen && now-st.Seen <= 90 {
			applied++
		}
	}
	status := "applied"
	switch {
	case cfg == nil:
		status = "unconfigured"
	case e != nil || p["ActiveState"] == "" || p["UnitFileState"] == "":
		status = "unknown"
	case !active || !enabled:
		status = "inactive"
	case len(disks) == 0:
		status = "unavailable"
	case failed:
		status = "error"
	case busy:
		status = "busy"
	case applied != len(disks):
		status = "pending"
	case cfg.Minutes == 0:
		status = "disabled"
	}
	return map[string]any{"sleepSettings": cfg, "sleepStatus": states, "sleepRuntime": map[string]any{"status": status, "timerActive": active, "timerEnabled": enabled, "applied": applied, "total": len(disks)}}, nil
}
func Command(mode string, input io.Reader, output io.Writer) error {
	s := defaultService()
	switch mode {
	case "once":
		return s.apply(false)
	case "disable":
		return s.apply(true)
	case "save", "validate":
		raw, err := io.ReadAll(io.LimitReader(input, 4096))
		if err != nil {
			return err
		}
		cfg, err := decodeConfig(raw)
		if err != nil {
			return err
		}
		if mode == "save" {
			return s.save(cfg)
		}
		return nil
	case "query":
		v, err := s.query()
		if err != nil {
			return err
		}
		return json.NewEncoder(output).Encode(v)
	default:
		return fmt.Errorf("unknown disk sleep command")
	}
}
