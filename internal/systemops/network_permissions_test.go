package systemops

import (
	"os"
	"testing"
)

func TestNetworkConfigurationReadabilityAndSecrets(t *testing.T) {
	for _, tc := range []struct {
		path string
		mode os.FileMode
	}{
		{"/etc/systemd/network/00-panasms-end0.network", 0644},
		{"/etc/systemd/network/00-panasms-bridge.netdev", 0644},
		{"/etc/systemd/network/00-panasms.link", 0644},
		{"/etc/netplan/90-panasms-wlan0.yaml", 0600},
		{"/etc/panasms/network/hostapd-wlan0.conf", 0600},
		{"/etc/panasms/network/wpa-wlan0.conf", 0600},
		{"/var/lib/panasms-agent/network-native/pending.json", 0600},
	} {
		if mode := NetworkConfigMode(tc.path); mode != tc.mode {
			t.Errorf("%s mode %o, want %o", tc.path, mode, tc.mode)
		}
	}
}
