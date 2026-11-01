package network

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/godbus/dbus/v5"
)

var wifiConfigRoot = "/etc/NetworkManager/conf.d"
var netClassRoot = "/sys/class/net"
var macPattern = regexp.MustCompile(`^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$`)

type radioState struct {
	Enabled         bool `json:"enabled"`
	HardwareEnabled bool `json:"hardwareEnabled"`
}
type radioDevice struct {
	Name     string `json:"name"`
	MAC      string `json:"mac"`
	Disabled bool   `json:"disabled"`
	Managed  bool   `json:"managed"`
}
type radioSnapshot struct {
	Global  bool          `json:"global"`
	Devices []radioDevice `json:"devices"`
}

func (a *adapter) radio() (radioState, error) {
	p, e := a.props(nmPath, nm)
	return radioState{boolean(p["WirelessEnabled"]), boolean(p["WirelessHardwareEnabled"])}, e
}
func (a *adapter) setProperty(path dbus.ObjectPath, iface, name string, value any) error {
	return a.call(path, "org.freedesktop.DBus.Properties.Set", iface, name, dbus.MakeVariant(value)).Err
}
func (a *adapter) devices() ([]dbus.ObjectPath, error) {
	var paths []dbus.ObjectPath
	e := a.call(nmPath, nm+".GetDevices").Store(&paths)
	return paths, e
}
func wifiPolicyPath(mac string) (string, error) {
	if !macPattern.MatchString(mac) {
		return "", fmt.Errorf("Wi-Fi adapter has no stable hardware address")
	}
	return filepath.Join(wifiConfigRoot, "90-panasms-wifi-"+strings.ReplaceAll(mac, ":", "")+".conf"), nil
}
func (a *adapter) wifiPolicy(name string) (string, string, error) {
	p, _, e := a.device(name)
	if e != nil {
		return "", "", e
	}
	props, e := a.props(p, nm+".Device.Wireless")
	if e != nil {
		return "", "", e
	}
	mac := strings.ToLower(str(props["PermHwAddress"]))
	path, e := wifiPolicyPath(mac)
	return path, mac, e
}
func filePresent(path string) (bool, error) {
	_, e := os.Lstat(path)
	if os.IsNotExist(e) {
		return false, nil
	}
	return e == nil, e
}
func (a *adapter) wifiDisabled(name string) (bool, error) {
	p, _, e := a.wifiPolicy(name)
	if e != nil {
		return false, e
	}
	return filePresent(p)
}
func (a *adapter) adapterRadio(name string) (radioState, error) {
	r, e := a.radio()
	if e != nil {
		return r, e
	}
	if !validName.MatchString(name) {
		return r, fmt.Errorf("Invalid network interface")
	}
	paths, e := filepath.Glob(filepath.Join(netClassRoot, name, "phy80211", "rfkill*", "hard"))
	if e != nil {
		return r, e
	}
	if len(paths) > 0 {
		r.HardwareEnabled = true
		for _, p := range paths {
			raw, e := os.ReadFile(p)
			if e != nil {
				return r, e
			}
			r.HardwareEnabled = r.HardwareEnabled && strings.TrimSpace(string(raw)) == "0"
		}
	}
	disabled, e := a.wifiDisabled(name)
	r.Enabled = r.Enabled && !disabled
	return r, e
}
func writeWifiPolicy(mac string, disabled bool) error {
	path, e := wifiPolicyPath(mac)
	if e != nil {
		return e
	}
	if !disabled {
		e = os.Remove(path)
		if os.IsNotExist(e) {
			return nil
		}
		return e
	}
	if e = os.MkdirAll(wifiConfigRoot, 0755); e != nil {
		return e
	}
	text := "[device-panasms-wifi-" + strings.ReplaceAll(mac, ":", "") + "]\nmatch-device=mac:" + mac + "\nmanaged=0\n"
	return nmWrite(path, text, 0644)
}
func (a *adapter) configureRadio(name string, enabled bool) error {
	path, props, e := a.device(name)
	if e != nil {
		return e
	}
	file, mac, e := a.wifiPolicy(name)
	if e != nil {
		return e
	}
	disabled, e := filePresent(file)
	if e != nil {
		return e
	}
	if !boolean(props["Managed"]) && !disabled {
		return fmt.Errorf("Select a managed Wi-Fi adapter")
	}
	if e = writeWifiPolicy(mac, !enabled); e != nil {
		return e
	}
	if e = a.call(nmPath, nm+".Reload", uint32(1)).Err; e != nil {
		return e
	}
	if e = a.setProperty(path, nm+".Device", "Managed", enabled); e != nil {
		return e
	}
	if !enabled {
		_, e = nmCommand("ip", "link", "set", "dev", name, "down")
		return e
	}
	r, e := a.adapterRadio(name)
	if e != nil {
		return e
	}
	if r.Enabled && r.HardwareEnabled {
		for i := 0; i < 40; i++ {
			_, p, e := a.device(name)
			if e != nil {
				return e
			}
			if num(p["State"]) >= 30 {
				return nil
			}
			time.Sleep(250 * time.Millisecond)
		}
		return fmt.Errorf("Wi-Fi adapter did not become available; check its hardware switch")
	}
	return nil
}
func (a *adapter) radioSnapshot() (radioSnapshot, error) {
	r, e := a.radio()
	if e != nil {
		return radioSnapshot{}, e
	}
	result := radioSnapshot{Global: r.Enabled, Devices: []radioDevice{}}
	paths, e := a.devices()
	if e != nil {
		return result, e
	}
	for _, p := range paths {
		props, e := a.props(p, nm+".Device")
		if e != nil {
			return result, e
		}
		if num(props["DeviceType"]) != 2 {
			continue
		}
		name := str(props["Interface"])
		file, mac, e := a.wifiPolicy(name)
		if e != nil {
			return result, e
		}
		disabled, e := filePresent(file)
		if e != nil {
			return result, e
		}
		result.Devices = append(result.Devices, radioDevice{name, mac, disabled, boolean(props["Managed"])})
	}
	return result, nil
}
func (a *adapter) enableRadio(name string) error {
	r, e := a.adapterRadio(name)
	if e != nil {
		return e
	}
	if !r.HardwareEnabled {
		return fmt.Errorf("Wi-Fi is blocked by a hardware switch")
	}
	global, e := a.radio()
	if e != nil {
		return e
	}
	if !global.Enabled {
		before, e := a.radioSnapshot()
		if e != nil {
			return e
		}
		for _, d := range before.Devices {
			if d.Managed && !d.Disabled {
				if e = a.configureRadio(d.Name, false); e != nil {
					return e
				}
			}
		}
		if e = a.setProperty(nmPath, nm, "WirelessEnabled", true); e != nil {
			return e
		}
	}
	disabled, e := a.wifiDisabled(name)
	if e != nil {
		return e
	}
	if disabled {
		return a.configureRadio(name, true)
	}
	return nil
}
func (a *adapter) restoreRadios(before radioSnapshot) error {
	for _, d := range before.Devices {
		file, mac, e := a.wifiPolicy(d.Name)
		if e != nil {
			// Only an absent NM object permits restoring the saved MAC policy without a live adapter.
			if !missingDevice(e) {
				return e
			}
			if e = writeWifiPolicy(d.MAC, d.Disabled); e != nil {
				return e
			}
			continue
		}
		if mac != d.MAC {
			return fmt.Errorf("A network adapter was replaced; check its settings")
		}
		disabled, e := filePresent(file)
		if e != nil {
			return e
		}
		if disabled != d.Disabled {
			if e = a.configureRadio(d.Name, !d.Disabled); e != nil {
				return e
			}
		}
	}
	if e := a.call(nmPath, nm+".Reload", uint32(1)).Err; e != nil {
		return e
	}
	r, e := a.radio()
	if e != nil {
		return e
	}
	if r.Enabled != before.Global {
		return a.setProperty(nmPath, nm, "WirelessEnabled", before.Global)
	}
	return nil
}
func missingDevice(e error) bool {
	switch v := e.(type) {
	case dbus.Error:
		return v.Name == nm+".UnknownDevice" || v.Name == "org.freedesktop.DBus.Error.UnknownObject"
	case *dbus.Error:
		return v.Name == nm+".UnknownDevice" || v.Name == "org.freedesktop.DBus.Error.UnknownObject"
	}
	return false
}
func (a *adapter) wifiDevice(name string) (dbus.ObjectPath, map[string]dbus.Variant, error) {
	path, p, e := a.device(name)
	if e != nil {
		return path, p, e
	}
	if num(p["DeviceType"]) != 2 {
		return path, p, fmt.Errorf("Select a managed Wi-Fi adapter")
	}
	if !boolean(p["Managed"]) {
		disabled, e := a.wifiDisabled(name)
		if e != nil {
			return path, p, e
		}
		if !disabled {
			return path, p, fmt.Errorf("Select a managed Wi-Fi adapter")
		}
	}
	return path, p, nil
}
