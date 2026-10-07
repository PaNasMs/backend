package coolingdaemon

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

var profiles = map[string][3]float64{"quiet": {40, 45, 50}, "balanced": {35, 40, 45}, "performance": {30, 35, 40}}
var cpuProfiles = map[string][4]int{"quiet": {50000, 60000, 67500, 75000}, "balanced": {45000, 55000, 64000, 70000}, "performance": {40000, 50000, 60000, 65000}}

func target(profile string, disks []Disk, sensor *float64, starting bool, elapsed time.Duration, stale, invalid bool) (float64, string) {
	thresholds, ok := profiles[profile]
	if !ok || invalid {
		return 1, "stale-or-invalid-data"
	}
	if sensor != nil && *sensor >= 70 {
		return 1, "system-temperature"
	}
	unknown := len(disks) == 0
	active := false
	maximum := float64(-1)
	for _, d := range disks {
		if d.State == "active" {
			active = true
			if d.Temperature == nil {
				unknown = true
			} else if *d.Temperature > maximum {
				maximum = *d.Temperature
			}
		}
		if d.State == "unknown" || d.State == "unavailable" {
			unknown = true
		}
	}
	if maximum >= thresholds[2] {
		return 1, "automatic"
	}
	if starting && elapsed < 120*time.Second && unknown {
		return .5, "initializing-sensors"
	}
	if stale {
		return 1, "stale-or-invalid-data"
	}
	if unknown {
		return 1, "sensor-unavailable"
	}
	if sensor == nil {
		return 1, "system-temperature"
	}
	if !active {
		if *sensor < 65 {
			return 0, "all-disks-sleeping"
		}
		return .5, "system-temperature"
	}
	if maximum < 30 && *sensor < 65 {
		return 0, "disks-cool"
	}
	for i, t := range thresholds {
		if maximum < t {
			return float64(i+1) / 4, "automatic"
		}
	}
	return 1, "automatic"
}
func applyCPU(profile, root string) (map[string]any, error) {
	thresholds, ok := cpuProfiles[profile]
	if !ok || readText(filepath.Join(root, "type")) != "cpu-thermal" {
		return nil, fmt.Errorf("unsupported CPU thermal zone or profile")
	}
	paths := []string{}
	original := []string{}
	for i := 1; i <= 4; i++ {
		if readText(filepath.Join(root, fmt.Sprintf("trip_point_%d_type", i))) != "active" {
			return nil, fmt.Errorf("unexpected cooling trip mapping")
		}
		p := filepath.Join(root, fmt.Sprintf("trip_point_%d_temp", i))
		raw, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		paths = append(paths, p)
		original = append(original, string(raw))
	}
	for i, p := range paths {
		if err := os.WriteFile(p, []byte(strconv.Itoa(thresholds[i])), 0644); err != nil {
			for j, q := range paths {
				_ = os.WriteFile(q, []byte(original[j]), 0644)
			}
			return nil, err
		}
	}
	return map[string]any{"available": true, "profile": profile, "thresholds": thresholds}, nil
}
