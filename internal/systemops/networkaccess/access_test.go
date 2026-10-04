package networkaccess

import (
	"reflect"
	"strings"
	"testing"
)

func TestDecisions(t *testing.T) {
	c := Config{Enabled: true, Delay: 90, OnLoss: true}
	wifi := Device{Name: "wlan0", Kind: "wifi", AP: true, Usable: true, Bands: []string{"bg"}}
	lan := Device{Name: "eth0", Kind: "ethernet", Connected: true, Addresses: []string{"192.168.1.100/24"}}
	ap := wifi
	ap.Profile = apUUID
	ap.Connected = true
	ap.Addresses = []string{"10.180.10.1/24"}
	tests := []struct {
		name          string
		config        Config
		state         State
		rows          []Device
		now           int64
		phase, action string
	}{
		{"boot delay", c, State{}, []Device{wifi}, 100, "waiting", ""},
		{"offline AP", c, State{Since: 1}, []Device{wifi}, 100, "access-point", "start"},
		{"local LAN without internet", c, State{Since: 1}, []Device{wifi, lan}, 100, "connected", ""},
		{"no disruptive rescan", c, State{Since: 1}, []Device{ap}, 100, "access-point", ""},
		{"network returns idle", c, State{Since: 1}, []Device{ap, lan}, 100, "waiting", "stop"},
		{"manual stop holds", c, State{Since: 1, Suppressed: true}, []Device{wifi}, 100, "suppressed", ""},
		{"missing radio", c, State{Since: 1}, nil, 100, "unavailable", ""},
	}
	for _, n := range []int{1, -1} {
		a := ap
		a.Clients = n
		tests = append(tests, struct {
			name          string
			config        Config
			state         State
			rows          []Device
			now           int64
			phase, action string
		}{"keep client or unknown count", c, State{Since: 1}, []Device{a, lan}, 100, "restored", ""})
	}
	off := c
	off.Enabled = false
	tests = append(tests, struct {
		name          string
		config        Config
		state         State
		rows          []Device
		now           int64
		phase, action string
	}{"disabled", off, State{Since: 1}, []Device{wifi}, 100, "disabled", ""})
	c.OnLoss = false
	tests = append(tests, struct {
		name          string
		config        Config
		state         State
		rows          []Device
		now           int64
		phase, action string
	}{"boot only policy", c, State{Since: 1, HadNetwork: true}, []Device{wifi}, 100, "waiting-reboot", ""})
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, action, _ := decide(tc.config, tc.state, tc.rows, tc.now)
			if got.Phase != tc.phase || action != tc.action {
				t.Fatalf("got %s/%s want %s/%s", got.Phase, action, tc.phase, tc.action)
			}
		})
	}
}
func TestNeverStealSharingOrConnectedAdapter(t *testing.T) {
	c := Config{Adapter: "02:00:00:00:00:01"}
	d := Device{Kind: "wifi", MAC: c.Adapter, AP: true, Usable: true, Reserved: true}
	if choose(c, []Device{d}) != nil {
		t.Fatal("selected sharing member")
	}
	d.Reserved = false
	d.Connected = true
	d.Addresses = []string{"192.168.1.2/24"}
	if choose(c, []Device{d}) != nil {
		t.Fatal("selected active network")
	}
	d.Connected = false
	d.MAC = "02:00:00:00:00:02"
	if choose(c, []Device{d}) != nil {
		t.Fatal("selected different radio")
	}
}
func TestRegulatoryAndParsing(t *testing.T) {
	info := "* AP\n* 2412.0 MHz [1] (20 dBm)\n* 5260.0 MHz [52] (no IR, radar detection)\n* 5745.0 MHz [149] (disabled)"
	if got := wifiBands(info); !reflect.DeepEqual(got, []string{"bg"}) {
		t.Fatalf("%v", got)
	}
	if got := wifiBands(strings.ReplaceAll(info, "* AP", "* managed")); len(got) != 0 {
		t.Fatal(got)
	}
	if got := splitRow(`wlan0:wifi:connected:escaped\:name`); len(got) != 4 || got[3] != "escaped:name" {
		t.Fatal(got)
	}
}
func TestNoLinkLocalConnectivity(t *testing.T) {
	for _, addr := range []string{"169.254.2.1/16", "fe80::1/64", "127.0.0.1/8"} {
		if connected([]Device{{Connected: true, Addresses: []string{addr}}}) {
			t.Fatal(addr)
		}
	}
	if connected([]Device{{Connected: true, Profile: apUUID, Addresses: []string{"10.180.10.1/24"}}}) {
		t.Fatal("AP counts as upstream")
	}
}
func TestConfigValidation(t *testing.T) {
	c := Config{SSID: "PaNasMs", Password: "abcdefghijkl", Band: "auto", Delay: 90}
	if err := validate(c); err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"", strings.Repeat("ю", 17), "name\n[wifi]"} {
		b := c
		b.SSID = s
		if validate(b) == nil {
			t.Fatal("accepted invalid SSID")
		}
	}
	for _, s := range []string{"short", "abcdefghijkl\n", strings.Repeat("x", 64)} {
		b := c
		b.Password = s
		if validate(b) == nil {
			t.Fatal("accepted invalid password")
		}
	}
}
