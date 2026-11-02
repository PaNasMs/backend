package network

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/godbus/dbus/v5"
)

func TestWifiCredentialsAndTypedConnection(t *testing.T) {
	for _, tc := range []struct {
		security, password string
		valid              bool
	}{
		{"open", "", true}, {"owe", "", true}, {"open", "secret", false}, {"wpa2", "12345678", true},
		{"wpa2", "short", false}, {"wpa2", strings.Repeat("a", 64), true}, {"wpa2", strings.Repeat("z", 64), false},
		{"wpa3", "x", true}, {"wpa3", strings.Repeat("a", 64), false}, {"enterprise", "password", false},
	} {
		c, e := wifiCredentials([]byte("Тест"), tc.security, tc.password, true, "/")
		if (e == nil) != tc.valid {
			t.Fatalf("%s/%d validity: %v", tc.security, len(tc.password), e)
		}
		if e != nil {
			continue
		}
		s := wifiConnection(c, "wlan0", "fixture")
		if dbus.SignatureOf(s).String() != "a{sa{sv}}" {
			t.Fatal(dbus.SignatureOf(s))
		}
		if str(s["connection"]["id"]) != "Тест" || boolean(s["connection"]["autoconnect"]) {
			t.Fatal("identity/autoconnect changed")
		}
		if _, ok := s["802-11-wireless"]["ssid"].Value().([]byte); !ok {
			t.Fatal("SSID must use D-Bus ay")
		}
		if tc.security == "open" {
			if _, ok := s["802-11-wireless-security"]; ok {
				t.Fatal("open network security section")
			}
		}
	}
	for _, ssid := range [][]byte{nil, []byte("a\x00b"), []byte(strings.Repeat("я", 17))} {
		if _, e := wifiCredentials(ssid, "open", "", false, "/"); e == nil {
			t.Fatal("invalid SSID accepted")
		}
	}
}
func TestWifiPolicyMACValidationAndRoundTrip(t *testing.T) {
	old := wifiConfigRoot
	wifiConfigRoot = t.TempDir()
	defer func() { wifiConfigRoot = old }()
	for _, mac := range []string{"../file", "00:11:22:33:44", "00:11:22:33:44:gg", "00:11:22:33:44:55\n"} {
		if e := writeWifiPolicy(mac, true); e == nil {
			t.Fatal("accepted invalid MAC")
		}
	}
	const mac = "00:11:22:33:44:55"
	if e := writeWifiPolicy(mac, true); e != nil {
		t.Fatal(e)
	}
	p := filepath.Join(wifiConfigRoot, "90-panasms-wifi-001122334455.conf")
	raw, e := os.ReadFile(p)
	if e != nil {
		t.Fatal(e)
	}
	if string(raw) != "[device-panasms-wifi-001122334455]\nmatch-device=mac:00:11:22:33:44:55\nmanaged=0\n" {
		t.Fatal(string(raw))
	}
	info, _ := os.Stat(p)
	if info.Mode().Perm() != 0644 {
		t.Fatal(info.Mode())
	}
	if e = writeWifiPolicy(mac, false); e != nil {
		t.Fatal(e)
	}
	if e = writeWifiPolicy(mac, false); e != nil {
		t.Fatal("restore must be idempotent", e)
	}
	if _, e = os.Stat(p); !os.IsNotExist(e) {
		t.Fatal("policy still present")
	}
}
func TestWifiSecurityClassification(t *testing.T) {
	for flags, want := range map[uint32]string{0: "open", 0x100: "wpa2", 0x400: "wpa3", 0x800: "owe", 0x200: "enterprise"} {
		if got := wifiSecurity(map[string]dbus.Variant{"RsnFlags": dbus.MakeVariant(flags)}); got != want {
			t.Fatalf("%x: %s", flags, got)
		}
	}
	if got := wifiSecurity(map[string]dbus.Variant{"Flags": dbus.MakeVariant(uint32(1))}); got != "unsupported" {
		t.Fatal(got)
	}
}

func TestLegacyPythonProfileHash(t *testing.T) {
	s := settings{
		"connection":      {"id": dbus.MakeVariant("Тест <&> 😀"), "uuid": dbus.MakeVariant("fixture"), "type": dbus.MakeVariant("802-11-wireless"), "timestamp": dbus.MakeVariant(uint64(111))},
		"802-11-wireless": {"ssid": dbus.MakeVariant([]byte("Тест")), "hidden": dbus.MakeVariant(false)},
		"ipv4":            {"route-metric": dbus.MakeVariant(int64(600)), "address-data": dbus.MakeVariant([]map[string]dbus.Variant{{"address": dbus.MakeVariant("192.0.2.1"), "prefix": dbus.MakeVariant(uint32(24))}})},
	}
	got, e := legacyProfileSignature(s)
	if e != nil || got != "312a036c313cadcd2665429d7a9c6a44db8fdf101486225baa523d156de420aa" {
		t.Fatalf("legacy Python hash: %s %v", got, e)
	}
	old := nmChange{}
	if !old.matchesProfile(s, got) {
		t.Fatal("old journal rejected")
	}
	modern := nmChange{HashVersion: 1}
	if !modern.matchesProfile(s, signature(s)) {
		t.Fatal("new journal rejected")
	}
	s["connection"]["id"] = dbus.MakeVariant("changed")
	if old.matchesProfile(s, got) {
		t.Fatal("external profile edit accepted")
	}
}
func TestNMJournalPreservesLegacyFieldsAndNoCredentials(t *testing.T) {
	oldState, oldRecovery, oldRoot := statePath, wifiRecoveryPath, sharingRoot
	root := t.TempDir()
	statePath = filepath.Join(root, "run/change.json")
	wifiRecoveryPath = filepath.Join(root, "wifi/pending.json")
	sharingRoot = filepath.Join(root, "sharing")
	defer func() { statePath, wifiRecoveryPath, sharingRoot = oldState, oldRecovery, oldRoot }()
	s := nmChange{state: state{ID: strings.Repeat("a", 32), Kind: "network.wifi.connect", Interface: "wlan0", User: "admin", Status: "pending", Deadline: 1791368436.034579, Profile: "/profile/1", ProfileHash: "hash"}, Boot: "boot", RadioBefore: true, NewUUID: "uuid", AdaptersBefore: &radioSnapshot{Global: true, Devices: []radioDevice{{"wlan0", "00:11:22:33:44:55", false, true}}}}
	if e := s.remember(); e != nil {
		t.Fatal(e)
	}
	for _, path := range []string{statePath, wifiRecoveryPath} {
		got, e := readNMChange(path)
		if e != nil {
			t.Fatal(e)
		}
		if got.Profile != s.Profile || got.Deadline != s.Deadline || got.NewUUID != s.NewUUID || got.AdaptersBefore.Devices[0].MAC != s.AdaptersBefore.Devices[0].MAC {
			t.Fatalf("lost legacy state: %#v", got)
		}
		raw, _ := os.ReadFile(path)
		if strings.Contains(string(raw), "password") || strings.Contains(string(raw), "psk") {
			t.Fatal("credential field persisted")
		}
		info, _ := os.Stat(path)
		if info.Mode().Perm() != 0600 {
			t.Fatal("journal readable by other users")
		}
	}
}

func TestForeignSharingProviderRemainsVisibleButCannotBeMutated(t *testing.T) {
	old := sharingRoot
	sharingRoot = t.TempDir()
	t.Cleanup(func() { sharingRoot = old })
	if e := os.WriteFile(filepath.Join(sharingRoot, "groups.json"), []byte(`[{"id":"native","provider":"networkd","outputs":[]}]`), 0600); e != nil {
		t.Fatal(e)
	}
	groups, e := readNMGroups()
	if e != nil || len(groups) != 1 || groups[0].ID != "native" {
		t.Fatalf("read-only inventory: %v %v", groups, e)
	}
	if _, e = loadNMGroups(); e == nil {
		t.Fatal("foreign provider must block mutations")
	}
}

func TestNMSubnetSelectionIncludesHostRoutes(t *testing.T) {
	old := nmCommand
	t.Cleanup(func() { nmCommand = old })
	nmCommand = func(args ...string) ([]byte, error) {
		return []byte(`[{"dst":"default"},{"dst":"127.0.0.1"},{"dst":"10.42.0.8"},{"dst":"10.43.0.0/24"}]`), nil
	}
	subnet, e := chooseNMSubnet(nil)
	if e != nil || subnet != "10.44.0.0/24" {
		t.Fatalf("host routes must block overlap without rejecting inventory: %s %v", subnet, e)
	}
}
