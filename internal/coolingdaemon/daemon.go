package coolingdaemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	"panasms.local/backend/internal/cooling"
)

const configPath = "/etc/panasms-cooling/config.json"
const statusPath = "/run/panasms-cooling/status.json"

type Config struct {
	cooling.Settings
	Disks []string `json:"disks"`
}

func readConfig() (Config, error) {
	raw, err := os.ReadFile(configPath)
	if err != nil {
		return Config{}, err
	}
	return decodeConfig(raw)
}
func decodeConfig(raw []byte) (Config, error) {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return c, err
	}
	if c.HardwareMode == "" {
		c.HardwareMode = "external-pwm"
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return c, err
	}
	if _, ok := fields["controlGPIO"]; !ok {
		c.ControlGPIO = 27
		if c.HardwareMode == "internal-pwm" {
			c.ControlGPIO = 18
		}
	}
	if _, ok := fields["tachGPIO"]; !ok && c.HardwareMode == "internal-pwm" {
		tach := 24
		c.TachGPIO = &tach
	}
	if c.CPUProfile == "" {
		c.CPUProfile = "balanced"
	}
	return c, cooling.Validate(c.Settings)
}
func atomicJSON(path string, value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".cooling-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0644); err == nil {
		_, err = f.Write(append(raw, '\n'))
	}
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
func Configure() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("run as root")
	}
	if err := os.MkdirAll(filepath.Dir(configPath), 0755); err != nil {
		return err
	}
	if _, err := os.Stat(configPath); errors.Is(err, os.ErrNotExist) {
		c := Config{Settings: cooling.Settings{CPUProfile: "balanced", Profile: "balanced", SampleSeconds: 60, HardwareMode: "none", ControlGPIO: 27}, Disks: []string{}}
		if err = atomicJSON(configPath, c); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	_, err := command("systemctl", "enable", "--now", "panasms-cooling.service")
	return err
}
func notify(message string) {
	address := os.Getenv("NOTIFY_SOCKET")
	if address == "" {
		return
	}
	c, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: address, Net: "unixgram"})
	if err != nil {
		log.Printf("systemd notify: %v", err)
		return
	}
	defer c.Close()
	if _, err = c.Write([]byte(message)); err != nil {
		log.Printf("systemd notify: %v", err)
	}
}

type sample struct {
	disks       []Disk
	at          time.Time
	initialized bool
}

func sampleDisks(ctx context.Context, c Config, out chan<- sample) {
	cached := map[string]Disk{}
	lastErrors := map[string]string{}
	sleepReads := loadSleepCapabilities(sleepCapabilityPath)
	initialized := false
	started := time.Now()
	for ctx.Err() == nil {
		current, err := readConfig()
		if err == nil && reflect.DeepEqual(current.Disks, c.Disks) {
			c = current
		}
		paths := map[string]bool{}
		for _, p := range c.Disks {
			paths[p] = true
		}
		found, _ := filepath.Glob("/dev/disk/by-id/ata-*")
		for _, p := range found {
			if !strings.Contains(filepath.Base(p), "-part") {
				paths[p] = true
			}
		}
		sorted := []string{}
		for p := range paths {
			sorted = append(sorted, p)
		}
		sort.Strings(sorted)
		disks := []Disk{}
		ready := len(sorted) > 0
		for _, p := range sorted {
			if ctx.Err() != nil {
				return
			}
			row := readDisk(ctx, p)
			if row.State == "active" {
				cached[p] = row
			}
			if row.State == "sleeping" {
				row = sleepingDisk(ctx, p, row, sleepReads)
			}
			row = cachedDisk(row, cached[p])
			disks = append(disks, row)
			if row.Error != lastErrors[p] {
				log.Printf("Cooling sensor %s: %s", p, row.Error)
				lastErrors[p] = row.Error
			}
			required := len(c.Disks) == 0
			for _, d := range c.Disks {
				if d == p {
					required = true
				}
			}
			if required && row.State != "active" && row.State != "sleeping" {
				ready = false
			}
		}
		initialized = initialized || ready
		select {
		case out <- sample{disks, time.Now(), initialized}:
		case <-ctx.Done():
			return
		}
		delay := time.Duration(c.SampleSeconds) * time.Second
		if !initialized && time.Since(started) < 120*time.Second {
			delay = 5 * time.Second
		}
		wait(ctx, delay)
	}
}

// sleepingDisk adds a standby temperature reading when the disk allows it. The first read of each
// disk is a probe: if the disk wakes up, it is remembered and never read in standby again.
func sleepingDisk(ctx context.Context, path string, row Disk, capabilities map[string]bool) Disk {
	capable, known := capabilities[path]
	if known && !capable {
		row.SleepReadable = &capable
		return row
	}
	temp, asleep := readSleeping(ctx, path)
	readable := asleep && temp != nil
	if !known || readable != capable {
		capabilities[path] = readable
		if err := atomicJSON(sleepCapabilityPath, capabilities); err != nil {
			log.Printf("Cooling sensor %s: cannot save standby read capability: %v", path, err)
		}
		if readable {
			log.Printf("Cooling sensor %s: temperature is readable in standby", path)
		} else {
			log.Printf("Cooling sensor %s: reading SMART in standby is not supported; using CPU temperature while disks sleep", path)
		}
	}
	row.SleepReadable = &readable
	if readable {
		now := float64(time.Now().UnixNano()) / 1e9
		row.Temperature = temp
		row.ObservedAt = &now
		row.SleepTemperature = true
	}
	return row
}

func Run(ctx context.Context) (err error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	c, err := readConfig()
	if err != nil {
		return err
	}
	if err = Failsafe(); err != nil {
		return err
	}
	h, err := openHardware(wiring(c.Settings))
	if err != nil {
		return err
	}
	defer func() {
		if h != nil {
			err = errors.Join(err, h.close())
		}
	}()
	attempted := h.wiring
	var hardwareError any
	samples := make(chan sample, 1)
	go sampleDisks(ctx, c, samples)
	state := sample{disks: []Disk{}}
	started := time.Now()
	last := time.Time{}
	lowerSince := time.Time{}
	kickUntil := time.Time{}
	value := .5
	previousTarget := -1.0
	cpuApplied := ""
	cpuStatus := map[string]any{"available": false}
	notify("READY=1")
	for ctx.Err() == nil {
		select {
		case state = <-samples:
		default:
		}
		now := time.Now()
		if now.Sub(last) >= time.Second {
			last = now
			newConfig, e := readConfig()
			invalid := e != nil || !reflect.DeepEqual(newConfig.Disks, c.Disks)
			if !invalid {
				next := wiring(newConfig.Settings)
				if !next.same(attempted) {
					attempted = next
					previous := h.wiring
					if e = h.close(); e != nil {
						return e
					}
					h, e = openHardware(next)
					if e != nil {
						hardwareError = e.Error()
						h, e = openHardware(previous)
						if e != nil {
							return e
						}
					} else {
						hardwareError = nil
					}
					value = .5
					lowerSince = time.Time{}
					previousTarget = -1
					kickUntil = time.Time{}
				}
				c = newConfig
				c.HardwareMode = h.wiring.Mode
				c.ControlGPIO = h.wiring.Control
				c.TachGPIO = h.wiring.Tach
			}
			if c.CPUProfile != cpuApplied {
				cpuStatus, e = applyCPU(c.CPUProfile, "/sys/class/thermal/thermal_zone0")
				if e != nil {
					cpuStatus = map[string]any{"available": false, "profile": c.CPUProfile, "error": e.Error()}
				} else {
					cpuApplied = c.CPUProfile
				}
			}
			required := []Disk{}
			for _, d := range state.disks {
				include := len(c.Disks) == 0
				for _, p := range c.Disks {
					if p == d.Path {
						include = true
					}
				}
				if include {
					required = append(required, d)
				}
			}
			targetValue, reason := target(c.Profile, required, systemTemperature(), !state.initialized, now.Sub(started), state.at.IsZero() || now.Sub(state.at) > time.Duration(c.SampleSeconds+60)*time.Second, invalid, value > 0)
			if targetValue < value {
				if previousTarget != targetValue {
					lowerSince = now
				}
				if !lowerSince.IsZero() && now.Sub(lowerSince) >= 20*time.Second {
					value = targetValue
				}
			} else {
				if value == 0 && targetValue > 0 {
					kickUntil = now.Add(2 * time.Second)
				}
				value = targetValue
				lowerSince = time.Time{}
			}
			previousTarget = targetValue
			actual := value
			if now.Before(kickUntil) {
				actual = 1
			}
			if h.wiring.Mode == "none" {
				actual = 0
				reason = "disabled"
			}
			var age any
			if !state.at.IsZero() {
				age = math.Round(now.Sub(state.at).Seconds())
			}
			status := map[string]any{"profile": c.Profile, "sampleSeconds": c.SampleSeconds, "dutyPercent": math.Round(actual * 100), "reason": reason, "disks": state.disks, "observedAt": float64(now.UnixNano()) / 1e9, "sampleAgeSeconds": age, "controller": h.wiring.Mode, "rpm": h.rpm, "cpu": cpuStatus, "hardware": h.wiring, "hardwareAttempt": attempted, "hardwareError": hardwareError}
			if e = atomicJSON(statusPath, status); e != nil {
				return e
			}
			notify("WATCHDOG=1")
		}
		actual := value
		if now.Before(kickUntil) {
			actual = 1
		}
		if err = h.tick(ctx, actual); err != nil {
			return err
		}
	}
	return nil
}
