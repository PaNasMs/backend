package networkaccess

import (
	"os"
	"testing"
)

// Opt-in hardware test; the wired management connection must remain available.
func TestLiveAccessPoint(t *testing.T) {
	name := os.Getenv("PANASMS_NETWORK_LIVE")
	if name == "" {
		t.Skip("set PANASMS_NETWORK_LIVE to a Wi-Fi interface on a test NAS")
	}
	if os.Geteuid() != 0 {
		t.Fatal("root required")
	}
	rows, err := devices()
	if err != nil {
		t.Fatal(err)
	}
	var target *Device
	wired := false
	for i := range rows {
		if rows[i].Profile == apUUID {
			t.Fatal("fallback AP already active; do not interrupt its clients")
		}
		if rows[i].Kind == "ethernet" && rows[i].Connected && hasAddress(rows[i]) {
			wired = true
		}
		if rows[i].Name == name {
			target = &rows[i]
		}
	}
	if !wired || target == nil || !target.AP || target.Reserved {
		t.Fatal("need a wired connection and unreserved AP-capable Wi-Fi")
	}
	c, err := load()
	if err != nil {
		t.Fatal(err)
	}
	original := target.Profile
	if _, err = run("systemctl", "stop", "panasms-network-access.service"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = stopAP()
		if original != "" {
			if _, err := run("nmcli", "--wait", "15", "connection", "up", "uuid", original); err != nil {
				t.Error(err)
			}
		}
		if _, err := run("systemctl", "start", "panasms-network-access.service"); err != nil {
			t.Error(err)
		}
	})
	if err = startAP(c, *target, rows); err != nil {
		t.Fatal(err)
	}
	rows, err = devices()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, d := range rows {
		if d.Name == name && d.Profile == apUUID && d.Connected && hasAddress(d) {
			found = true
		}
	}
	if !found {
		t.Fatal("AP did not become active with an assigned address")
	}
	if !connected(rows) {
		t.Fatal("wired management connectivity lost")
	}
	t.Log("AP active with assigned IPv4; wired management preserved; restoring saved Wi-Fi")
}
