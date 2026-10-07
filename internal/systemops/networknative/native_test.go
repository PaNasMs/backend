package networknative

import (
	"os"
	"strings"
	"testing"
)

func TestScanSecurityAndSignal(t *testing.T) {
	raw := []byte("BSS 00:11:22:33:44:55(on wlan0)\n\tfreq: 2412\n\tsignal: -55.00 dBm\n\tcapability: ESS Privacy\n\tSSID: Home\\x20WiFi\n\tRSN:\n\t\tAuthentication suites: PSK\nBSS 00:11:22:33:44:66(on wlan0)\n\tfreq: 5180\n\tsignal: -90.00 dBm\n\tSSID: Guest\n")
	rows := parseScan(raw)
	if len(rows) != 2 || rows[0].SSID != "Home WiFi" || rows[0].Security != "wpa2" || rows[0].Signal != 90 || rows[1].Security != "open" {
		t.Fatalf("unexpected networks: %+v", rows)
	}
}
func TestScanDoesNotTreatEnterpriseAsPersonal(t *testing.T) {
	rows := parseScan([]byte("BSS 00:11:22:33:44:55(on wlan0)\nSSID: Corporate\nRSN:\nAuthentication suites: IEEE 802.1X\n"))
	if len(rows) != 1 || rows[0].Security != "enterprise" {
		t.Fatalf("unexpected security %+v", rows)
	}
}
func TestChannelsExcludeForbiddenDFSAndDisabled(t *testing.T) {
	c := Channels("* 2412 MHz [1] (20.0 dBm)\n* 2462 MHz [11] (disabled)\n* 5180 MHz [36] (no IR)\n* 5200 MHz [40] (23.0 dBm)\n* 5500 MHz [100] (radar detection)\n* 5975 MHz [5] (23.0 dBm)")
	if len(c["bg"]) != 1 || c["bg"][0] != 1 || len(c["a"]) != 1 || c["a"][0] != 40 {
		t.Fatalf("unsafe channels %+v", c)
	}
}
func TestAPUsesHexSSIDAndOptionalBridge(t *testing.T) {
	c := APConfig{SSID: "Cafe #1", Password: "testing-password", Band: "bg", Channel: 6}
	raw := hostapdConfig("wlan0", "", c)
	if strings.Contains(raw, "bridge=") || !strings.Contains(raw, "ssid2=43616665202331\n") || !strings.Contains(raw, "wpa=2\n") {
		t.Fatal(raw)
	}
	raw = hostapdConfig("wlan0", "osbr123", c)
	if !strings.Contains(raw, "bridge=osbr123\n") {
		t.Fatal(raw)
	}
}
func TestSavedWifiSelectionRetainsCredentialsAndRejectsUnknownID(t *testing.T) {
	c := wifiConfig{Name: "wlan0", Profiles: []WifiProfile{{ID: "test", SSID: "test", Password: "secret"}}}
	selected, e := selectWifi(c, map[string]any{"connection": "test"})
	if e != nil || selected.Password != "secret" {
		t.Fatal("saved connection lost credentials")
	}
	_, e = selectWifi(c, map[string]any{"connection": "missing"})
	if e == nil {
		t.Fatal("unknown connection accepted")
	}
}
func TestSSIDAndPasswordValidation(t *testing.T) {
	for _, p := range []map[string]any{{"ssid": "bad\nname", "security": "open"}, {"ssid": "home", "security": "wpa2", "password": "short"}, {"ssid": "home", "security": "open", "password": "unexpected"}, {"ssid": "home", "security": "enterprise"}} {
		if _, e := selectWifi(wifiConfig{}, p); e == nil {
			t.Fatalf("accepted invalid input %+v", p)
		}
	}
	if _, e := selectWifi(wifiConfig{}, map[string]any{"ssid": "home", "security": "wpa2", "password": "valid-password"}); e != nil {
		t.Fatal(e)
	}
}
func TestDNSPrivateRange(t *testing.T) {
	c, e := dnsConfig("osbr123", "10.42.0.1/24")
	if e != nil || !strings.Contains(c, "dhcp-range=10.42.0.20,10.42.0.200,255.255.255.0,12h") {
		t.Fatalf("%s %v", c, e)
	}
	if _, e = dnsConfig("br0", "::1/128"); e == nil {
		t.Fatal("accepted unsupported DHCP address")
	}
}

func TestConnectionReadinessRejectsLinkLocal(t *testing.T) {
	for _, addresses := range [][]string{nil, {"fe80::1/64"}, {"169.254.10.2/16"}, {"127.0.0.1/8"}} {
		if hasGlobalAddress(addresses) {
			t.Fatalf("accepted unusable addresses %v", addresses)
		}
	}
	if !hasGlobalAddress([]string{"192.168.1.10/24"}) {
		t.Fatal("rejected LAN address")
	}
}
func TestRollbackLeavesUnchangedGroupsAlone(t *testing.T) {
	before := []Group{{ID: "one", Enabled: true}, {ID: "two", Enabled: true}}
	after := []Group{{ID: "one", Enabled: false}, {ID: "two", Enabled: true}}
	changed := changedGroups(after, before)
	if len(changed) != 1 || changed[0].ID != "one" {
		t.Fatalf("unrelated group included: %+v", changed)
	}
	if len(changedGroups(before, before)) != 0 {
		t.Fatal("unchanged groups must not restart")
	}
}

func TestUplinkRoutesConnectedBeforeGatewayAndNoOtherInterface(t *testing.T) {
	rows := []map[string]any{
		{"dst": "default", "gateway": "192.168.1.1", "dev": "end0", "metric": float64(100)},
		{"dst": "192.168.1.0/24", "dev": "end0"},
		{"dst": "default", "gateway": "10.0.0.1", "dev": "wlan0"},
	}
	routes := desiredRoutes("end0", rows)
	if len(routes) != 2 || routes[0].Gateway != "" || routes[1].Gateway != "192.168.1.1" {
		t.Fatalf("incorrect route order: %+v", routes)
	}
}

func TestInterfaceSystemdEscaping(t *testing.T) {
	if dnsUnit("eth-test") != `panasms-dnsmasq@eth\x2dtest.service` {
		t.Fatal("hyphen must not decode as a path separator")
	}
	if apUnit("wlan0") != "panasms-hostapd@wlan0.service" {
		t.Fatal("plain interface changed")
	}
}

func TestRollbackRestoresOnlyRecordedFiles(t *testing.T) {
	oldRoot, oldPending, oldWrite := root, pending, writeFile
	writeFile = func(path, value string, mode os.FileMode) error { return os.WriteFile(path, []byte(value), mode) }
	root = t.TempDir()
	pending = root + "/run/change.json"
	t.Cleanup(func() { root, pending, writeFile = oldRoot, oldPending, oldWrite })
	existing, added, unrelated := root+"/existing", root+"/added", root+"/unrelated"
	for path, value := range map[string]string{existing: "changed", added: "new", unrelated: "leave alone"} {
		if err := setFile(path, text(value)); err != nil {
			t.Fatal(err)
		}
	}
	change := &transaction{ID: "test", Kind: "network.native", Status: "pending", Before: map[string]*string{existing: text("original"), added: nil}}
	if err := rollback(change); err != nil {
		t.Fatal(err)
	}
	got, err := fileState(existing)
	if err != nil || got == nil || *got != "original" {
		t.Fatal("original settings not restored")
	}
	got, err = fileState(added)
	if err != nil || got != nil {
		t.Fatal("new configuration not removed")
	}
	got, err = fileState(unrelated)
	if err != nil || got == nil || *got != "leave alone" {
		t.Fatal("unrelated configuration changed")
	}
	saved, err := loadTransaction()
	if err != nil || saved == nil || saved.Status != "rolled-back" {
		t.Fatal("durable recovery status not saved")
	}
}

func TestForeignSharingGroupsAreNeverRewritten(t *testing.T) {
	old := groupsPath
	groupsPath = t.TempDir() + "/groups.json"
	t.Cleanup(func() { groupsPath = old })
	original := `[{'id':'legacy','profiles':{'end0':'saved-uuid'}}]`
	original = strings.ReplaceAll(original, "'", `"`)
	if err := os.WriteFile(groupsPath, []byte(original), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Groups(); err == nil {
		t.Fatal("foreign group accepted for native mutation")
	}
	data, err := os.ReadFile(groupsPath)
	if err != nil || string(data) != original {
		t.Fatal("foreign configuration changed")
	}
}
