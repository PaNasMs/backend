package networkaccess

import (
	"net"
	"os"
	"path/filepath"
	"strings"

	"panasms.local/backend/internal/systemops/networknative"
)

func nativeNetwork() bool {
	_, e := run("systemctl", "is-active", "--quiet", "NetworkManager")
	return e != nil && networknative.Active()
}
func nativeDevices() ([]Device, error) {
	interfaces, e := net.Interfaces()
	if e != nil {
		return nil, e
	}
	groups, e := networknative.Groups()
	if e != nil {
		return nil, e
	}
	rows := []Device{}
	for _, i := range interfaces {
		path, _ := filepath.EvalSymlinks("/sys/class/net/" + i.Name)
		usb := IsGadgetPath(path)
		wireless := networknative.Wireless(i.Name)
		if !usb && !wireless && (i.Name == "lo" || strings.Contains(path, "/virtual/")) {
			continue
		}
		d := Device{Name: i.Name, MAC: i.HardwareAddr.String(), Kind: "ethernet", Usable: true, Addresses: networknative.Addresses(i.Name)}
		carrier, _ := os.ReadFile("/sys/class/net/" + i.Name + "/carrier")
		d.Connected = strings.TrimSpace(string(carrier)) == "1"
		if master, err := filepath.EvalSymlinks("/sys/class/net/" + i.Name + "/master"); err == nil {
			d.Addresses = append(d.Addresses, networknative.Addresses(filepath.Base(master))...)
		}
		if wireless {
			d.Kind = "wifi"
			cap := networknative.Capability(i.Name)
			d.AP = cap.AP
			d.Bands = cap.Bands
			w, err := networknative.Wifi(i.Name)
			if err != nil {
				return nil, err
			}
			d.Usable = w.HardwareEnabled
			d.Connected = w.ActiveAP != "/" || w.Mode == 3
			d.Clients = w.Clients
			if networknative.DirectInterface(apID) == i.Name && networknative.APActive(i.Name) {
				d.Profile = apUUID
			}
		}
		if usb {
			d.Kind = "usb"
			if networknative.DirectInterface(usbID) == i.Name {
				d.Profile = usbUUID
			}
		}
		for _, g := range groups {
			for _, name := range append(append([]string{}, g.Outputs...), g.Source) {
				if name == i.Name {
					d.Reserved = true
				}
			}
		}
		rows = append(rows, d)
	}
	return rows, nil
}
