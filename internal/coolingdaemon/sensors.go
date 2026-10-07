package coolingdaemon

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Disk struct {
	Path         string      `json:"path"`
	Device       string      `json:"device"`
	State        string      `json:"state"`
	Temperature  *float64    `json:"temperature"`
	Health       string      `json:"health"`
	Warnings     []string    `json:"warnings"`
	Attributes   []Attribute `json:"attributes"`
	PowerOnHours *float64    `json:"powerOnHours"`
	ObservedAt   *float64    `json:"observedAt"`
	Stale        bool        `json:"stale"`
	Error        string      `json:"error,omitempty"`
}
type Attribute struct {
	ID         int    `json:"id"`
	Name       string `json:"name"`
	Value      int    `json:"value"`
	Worst      int    `json:"worst"`
	Thresh     int    `json:"thresh"`
	WhenFailed string `json:"when_failed"`
	Raw        struct {
		Value  float64 `json:"value"`
		String string  `json:"string"`
	} `json:"raw"`
	Flags json.RawMessage `json:"flags,omitempty"`
}

func readDisk(ctx context.Context, path string) Disk {
	sub, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(sub, "/usr/sbin/smartctl", "-n", "standby,3,5", "-d", "ata", "-H", "-A", "-j", path)
	raw, err := cmd.Output()
	code := 0
	if err != nil {
		if e, ok := err.(*exec.ExitError); ok {
			code = e.ExitCode()
		} else {
			return unknownDisk(path, err)
		}
	}
	return parseDisk(path, raw, code)
}
func unknownDisk(path string, err error) Disk {
	return Disk{Path: path, State: "unknown", Health: "unknown", Warnings: []string{}, Attributes: []Attribute{}, Stale: true, Error: err.Error()}
}
func parseDisk(path string, raw []byte, code int) Disk {
	var data struct {
		Smartctl struct {
			Messages []struct {
				String string `json:"string"`
			} `json:"messages"`
		} `json:"smartctl"`
		Temperature struct {
			Current *float64 `json:"current"`
		} `json:"temperature"`
		Attributes struct {
			Table []Attribute `json:"table"`
		} `json:"ata_smart_attributes"`
		Status struct {
			Passed *bool `json:"passed"`
		} `json:"smart_status"`
		Power struct {
			Hours *float64 `json:"hours"`
		} `json:"power_on_time"`
	}
	if err := json.Unmarshal(raw, &data); err != nil {
		return unknownDisk(path, err)
	}
	if code == 3 {
		for _, msg := range data.Smartctl.Messages {
			s := strings.ToUpper(msg.String)
			if strings.Contains(s, "STANDBY") || strings.Contains(s, "SLEEP") {
				d := unknownDisk(path, fmt.Errorf(""))
				d.State = "sleeping"
				d.Error = ""
				return d
			}
		}
	}
	if code&7 != 0 || code < 0 {
		return unknownDisk(path, fmt.Errorf("SMART command failed (exit %d)", code))
	}
	temp := data.Temperature.Current
	if temp == nil {
		for _, a := range data.Attributes.Table {
			if a.ID == 194 {
				v := a.Raw.Value
				temp = &v
				break
			}
		}
	}
	if temp == nil || *temp < 0 || *temp > 100 {
		return unknownDisk(path, fmt.Errorf("temperature unavailable"))
	}
	warnings := []string{}
	for _, a := range data.Attributes.Table {
		switch a.ID {
		case 5, 187, 188, 197, 198, 199:
			if a.Raw.Value > 0 {
				warnings = append(warnings, a.Name)
			}
		}
	}
	if code&0xf0 != 0 {
		warnings = append(warnings, "SMART reports attribute or error-log warnings")
	}
	health := "unknown"
	if data.Status.Passed != nil && *data.Status.Passed {
		health = "passed"
	}
	if len(warnings) > 0 {
		health = "warning"
	}
	if code&8 != 0 || data.Status.Passed != nil && !*data.Status.Passed {
		health = "failed"
	}
	now := float64(time.Now().UnixNano()) / 1e9
	attrs := data.Attributes.Table
	if attrs == nil {
		attrs = []Attribute{}
	}
	return Disk{Path: path, State: "active", Temperature: temp, Health: health, Warnings: warnings, Attributes: attrs, PowerOnHours: data.Power.Hours, ObservedAt: &now}
}
func cachedDisk(row Disk, previous Disk) Disk {
	if row.State != "active" && previous.ObservedAt != nil {
		row.Temperature = previous.Temperature
		row.Health = previous.Health
		row.Warnings = previous.Warnings
		row.Attributes = previous.Attributes
		row.PowerOnHours = previous.PowerOnHours
		row.ObservedAt = previous.ObservedAt
		row.Stale = true
	}
	device, err := filepath.EvalSymlinks(row.Path)
	if err != nil {
		row.Device = row.Path
		row.State = "unavailable"
		row.Error = "Device path is not available"
	} else {
		row.Device = device
	}
	return row
}
func readText(path string) string { raw, _ := os.ReadFile(path); return strings.TrimSpace(string(raw)) }
func systemTemperature() *float64 {
	var maximum *float64
	paths, _ := filepath.Glob("/sys/class/hwmon/hwmon*")
	for _, p := range paths {
		name := readText(filepath.Join(p, "name"))
		if name != "cpu_thermal" && name != "rp1_adc" {
			continue
		}
		v, err := strconv.ParseFloat(readText(filepath.Join(p, "temp1_input")), 64)
		if err == nil {
			v /= 1000
			if maximum == nil || v > *maximum {
				maximum = &v
			}
		}
	}
	return maximum
}
