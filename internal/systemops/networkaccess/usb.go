package networkaccess

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"panasms.local/backend/internal/systemops"
	"panasms.local/backend/internal/systemops/networknative"
)

const usbBootBlock = "\n# PaNasMs direct USB access\n[all]\ndtoverlay=dwc2,dr_mode=peripheral\n# End PaNasMs direct USB access\n"

type USBCapability struct {
	Available bool   `json:"available"`
	Port      string `json:"port"`
	Reason    string `json:"reason"`
	Reboot    bool   `json:"reboot"`
}

func piPort() string {
	model, _ := os.ReadFile("/proc/device-tree/model")
	m := string(model)
	if strings.HasPrefix(m, "Raspberry Pi 5 Model") || strings.HasPrefix(m, "Raspberry Pi 4 Model") {
		return "USB-C"
	}
	if strings.HasPrefix(m, "Raspberry Pi Zero") {
		return "micro-USB (USB)"
	}
	return ""
}
func udcs() []string { paths, _ := filepath.Glob("/sys/class/udc/*"); return paths }
func usbCapability() USBCapability {
	c := USBCapability{Port: piPort()}
	for _, p := range udcs() {
		function, _ := os.ReadFile(p + "/function")
		f := strings.TrimSpace(string(function))
		modules, _ := os.ReadFile("/etc/modules-load.d/panasms-usb.conf")
		if f != "" && !ownedEthernetFunction(f, string(modules)) {
			c.Reason = "controller-busy"
			return c
		}
	}
	if len(udcs()) > 1 {
		c.Reason = "multiple-controllers"
		return c
	}
	if len(udcs()) == 1 {
		c.Available = true
		if c.Port == "" {
			c.Port = "USB OTG"
		}
		return c
	}
	if c.Port != "" {
		if _, err := os.Stat("/boot/firmware/overlays/dwc2.dtbo"); err == nil {
			c.Available = true
			c.Reboot = true
			return c
		}
	}
	c.Reason = "unsupported"
	return c
}
func configureUSB(enabled bool) error {
	const modules = "/etc/modules-load.d/panasms-usb.conf"
	const boot = "/boot/firmware/config.txt"
	if enabled {
		c := usbCapability()
		if !c.Available {
			return reject("USB device mode is unavailable on this board")
		}
		if piPort() != "" && len(udcs()) == 0 {
			data, e := os.ReadFile(boot)
			if e != nil {
				return e
			}
			if !strings.Contains(string(data), usbBootBlock) {
				if e = systemops.AtomicWrite(boot, string(data)+usbBootBlock, 0644); e != nil {
					return e
				}
			}
		}
		id, err := os.ReadFile("/etc/machine-id")
		if err != nil {
			return err
		}
		hash := sha256.Sum256(id)
		options := fmt.Sprintf("# PaNasMs direct USB access\noptions g_ether dev_addr=02:%02x:%02x:%02x:%02x:%02x host_addr=06:%02x:%02x:%02x:%02x:%02x\n", hash[0], hash[1], hash[2], hash[3], hash[4], hash[0], hash[1], hash[2], hash[3], hash[4])
		if err = writeUSBFile("/etc/modprobe.d/panasms-usb.conf", options); err != nil {
			return err
		}
		return writeUSBFile(modules, "# PaNasMs direct USB access\ndwc2\ng_ether\n")
	}
	if data, e := os.ReadFile(boot); e == nil && strings.Contains(string(data), usbBootBlock) {
		if e = systemops.AtomicWrite(boot, strings.ReplaceAll(string(data), usbBootBlock, ""), 0644); e != nil {
			return e
		}
	}
	if _, e := os.Stat(modules); e == nil {
		if e = writeUSBFile(modules, "# PaNasMs direct USB access disabled\n"); e != nil {
			return e
		}
	}
	if e := os.Remove("/etc/modprobe.d/panasms-usb.conf"); e != nil && !os.IsNotExist(e) {
		return e
	}
	return nil
}
func writeUSBFile(path, content string) error {
	old, _ := os.ReadFile(path)
	if string(old) == content {
		return nil
	}
	return systemops.AtomicWrite(path, content, 0644)
}
func usbStatus(c Config, rows []Device) string {
	if !c.USB {
		for _, d := range rows {
			if d.Profile == usbUUID {
				if nativeNetwork() {
					if networknative.DirectStop(usbID, d.Name) != nil {
						return "error"
					}
					continue
				}
				_, e := run("nmcli", "connection", "down", "uuid", usbUUID)
				if e != nil {
					return "error"
				}
			}
		}
		return "disabled"
	}
	cap := usbCapability()
	if !cap.Available {
		return cap.Reason
	}
	if e := configureUSB(true); e != nil {
		return "error"
	}
	if cap.Reboot {
		return "reboot"
	}
	if _, e := run("/usr/sbin/modprobe", "g_ether"); e != nil {
		return "driver-unavailable"
	}
	paths, _ := filepath.Glob("/sys/class/net/*")
	name := ""
	for _, p := range paths {
		device, _ := filepath.EvalSymlinks(p)
		if IsGadgetPath(device) {
			name = filepath.Base(p)
			break
		}
	}
	if name == "" {
		return "waiting-cable"
	}
	for _, d := range rows {
		if d.Name == name {
			if state := usbConnectionState(d, nativeNetwork()); state != "" {
				return state
			}
		}
	}
	if _, e := run("ip", "link", "set", "dev", name, "up"); e != nil {
		return "error"
	}
	carrier, e := os.ReadFile("/sys/class/net/" + name + "/carrier")
	if e != nil || strings.TrimSpace(string(carrier)) != "1" {
		return "waiting-cable"
	}
	addr, e := subnet(rows, 120)
	if e != nil {
		return "error"
	}
	if nativeNetwork() {
		if e = networknative.DirectStart(usbID, name, addr, nil); e != nil {
			return "error"
		}
		return "connected"
	}
	if e = installProfile(usbID, profile(usbID, usbUUID, "ethernet", name, addr, "")); e != nil {
		return "error"
	}
	if _, e = run("nmcli", "--wait", "10", "connection", "up", "uuid", usbUUID, "ifname", name); e != nil {
		return "error"
	}
	return "connected"
}

func usbConnectionState(d Device, native bool) string {
	if d.Reserved {
		return "controller-busy"
	}
	if !d.Connected {
		return ""
	}
	if d.Profile == usbUUID {
		if native && !hasAddress(d) {
			return ""
		}
		return "connected"
	}
	if !native || d.Profile != "" || hasAddress(d) {
		return "controller-busy"
	}
	return ""
}

func IsGadgetPath(path string) bool {
	parts := strings.Split(filepath.Clean(path), "/")
	for i, part := range parts {
		if (part == "gadget" || strings.HasPrefix(part, "gadget.")) && i+1 < len(parts) && parts[i+1] == "net" {
			return true
		}
	}
	return false
}
func ownedEthernetFunction(function, modules string) bool {
	if function != "g_ether" && function != "Ethernet Gadget" && function != "RNDIS/Ethernet Gadget" {
		return false
	}
	if !strings.Contains(modules, "# PaNasMs direct USB access") {
		return false
	}
	for _, line := range strings.Split(modules, "\n") {
		if strings.TrimSpace(line) == "g_ether" {
			return true
		}
	}
	return false
}
