package systemops

import (
	"os"
	"path/filepath"
)

// networkd reads these non-secret files after dropping root privileges.
// Netplan YAML and hostapd/wpa_supplicant credentials must remain private.
func NetworkConfigMode(path string) os.FileMode {
	if filepath.Dir(path) == "/etc/systemd/network" {
		switch filepath.Ext(path) {
		case ".network", ".netdev", ".link":
			return 0644
		}
	}
	return 0600
}
