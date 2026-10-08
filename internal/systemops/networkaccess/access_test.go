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

func TestNetworkdEthernetPreventsFallbackAP(t *testing.T) {
	for _, tc := range []struct {
		name, state, carrier, address string
		connected                     bool
	}{
		{"networkd DHCP", "unmanaged", "1\n", "192.168.1.100/24", true},
		{"networkd IPv6", "unmanaged", "1", "fd00::2/64", true},
		{"cable without address", "unmanaged", "1", "", false},
		{"link local only", "unmanaged", "1", "169.254.1.2/16", false},
		{"unplugged stale address", "unmanaged", "0", "192.168.1.100/24", false},
		{"unreadable carrier", "unmanaged", "", "192.168.1.100/24", false},
		{"NM disconnected", "disconnected", "1", "192.168.1.100/24", false},
		{"NM external", "connected (externally)", "1", "192.168.1.100/24", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lan := Device{Name: "end0", Kind: "ethernet", Connected: ethernetConnected(tc.state, tc.carrier), Addresses: []string{tc.address}}
			wifi := Device{Name: "wlan0", Kind: "wifi", AP: true, Usable: true}
			state, action, _ := decide(Config{Enabled: true, Delay: 90, OnLoss: true}, State{Since: 1}, []Device{lan, wifi}, 100)
			if tc.connected {
				if state.Phase != "connected" || action != "" {
					t.Fatalf("working Ethernet triggered fallback: %s/%s", state.Phase, action)
				}
			} else if state.Phase != "access-point" || action != "start" {
				t.Fatalf("missing Ethernet suppressed fallback: %s/%s", state.Phase, action)
			}
		})
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

func TestWifiPasswordBoundaries(t *testing.T) {
	for _, size := range []int{7, 8, 11, 12, 63, 64} {
		c := Config{SSID: "PaNasMs", Password: strings.Repeat("a", size), Band: "auto", Delay: 90}
		if got := validate(c) == nil; got != (size >= 8 && size <= 63) {
			t.Errorf("password length %d: accepted=%v", size, got)
		}
	}
}

func TestGadgetKernelNames(t *testing.T) {
	for path, want := range map[string]bool{"/sys/devices/platform/usb/gadget/net/usb0": true, "/sys/devices/platform/usb/gadget.0/net/usb0": true, "/sys/devices/platform/usb/net/eth1": false, "/tmp/gadget.0/not-net/usb0": false} {
		if got := IsGadgetPath(path); got != want {
			t.Errorf("%s: %v", path, got)
		}
	}
	modules := "# PaNasMs direct USB access\ndwc2\ng_ether\n"
	for _, name := range []string{"g_ether", "Ethernet Gadget", "RNDIS/Ethernet Gadget"} {
		if !ownedEthernetFunction(name, modules) {
			t.Error(name)
		}
	}
	if ownedEthernetFunction("g_mass_storage", modules) || ownedEthernetFunction("g_ether", "") || ownedEthernetFunction("g_ether", "# PaNasMs direct USB access disabled\n") {
		t.Fatal("unowned or disabled gadget accepted")
	}
}

func TestUSBCarrierDoesNotClaimAnUnconfiguredNativeInterface(t *testing.T) {
	for _, tc := range []struct {
		name   string
		d      Device
		native bool
		want   string
	}{
		{"native cable only", Device{Connected: true}, true, ""},
		{"native link local", Device{Connected: true, Addresses: []string{"169.254.2.3/16", "fe80::1/64"}}, true, ""},
		{"native foreign address", Device{Connected: true, Addresses: []string{"192.168.4.1/24"}}, true, "controller-busy"},
		{"native foreign profile", Device{Connected: true, Profile: "other"}, true, "controller-busy"},
		{"native owned pending", Device{Connected: true, Profile: usbUUID}, true, ""},
		{"native owned ready", Device{Connected: true, Profile: usbUUID, Addresses: []string{"10.180.120.1/24"}}, true, "connected"},
		{"reserved", Device{Reserved: true}, true, "controller-busy"},
		{"NM foreign", Device{Connected: true}, false, "controller-busy"},
		{"NM owned", Device{Connected: true, Profile: usbUUID}, false, "connected"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := usbConnectionState(tc.d, tc.native); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}
