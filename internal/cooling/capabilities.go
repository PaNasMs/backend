package cooling

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type Capabilities struct {
	CPU  bool `json:"cpu"`
	Disk bool `json:"disk"`
}

func DetectCapabilities(root string) Capabilities {
	read := func(path string) string {
		raw, _ := os.ReadFile(filepath.Join(root, path))
		return strings.Trim(strings.TrimSpace(string(raw)), "\x00")
	}
	zone := "sys/class/thermal/thermal_zone0"
	caps := Capabilities{CPU: read(zone+"/type") == "cpu-thermal"}
	for i := 1; i <= 4; i++ {
		base := fmt.Sprintf("%s/trip_point_%d", zone, i)
		info, err := os.Stat(filepath.Join(root, base+"_temp"))
		if read(base+"_type") != "active" || err != nil || info.Mode().Perm()&0200 == 0 {
			caps.CPU = false
		}
	}
	if strings.HasPrefix(read("proc/device-tree/model"), "Raspberry Pi 5 Model") {
		chips, _ := filepath.Glob(filepath.Join(root, "sys/class/gpio/gpiochip*/label"))
		devices, _ := filepath.Glob(filepath.Join(root, "dev/gpiochip*"))
		for _, chip := range chips {
			raw, _ := os.ReadFile(chip)
			if strings.TrimSpace(string(raw)) == "pinctrl-rp1" && len(devices) > 0 {
				caps.Disk = true
			}
		}
	}
	return caps
}

func validateCapabilities(old, next Settings, caps Capabilities) error {
	if !caps.CPU && old.CPUProfile != next.CPUProfile {
		return fmt.Errorf("CPU cooling control is not supported on this system")
	}
	if !caps.Disk && next.HardwareMode != "none" && (old.HardwareMode != next.HardwareMode || old.ControlGPIO != next.ControlGPIO || !samePin(old.TachGPIO, next.TachGPIO) || old.Profile != next.Profile) {
		return fmt.Errorf("disk cooling control is not supported on this system")
	}
	return nil
}
