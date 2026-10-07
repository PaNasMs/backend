package network

import (
	"encoding/json"
	"github.com/godbus/dbus/v5"
	"panasms.local/backend/internal/systemops/networkd"
	"testing"
)

func basicConfig() networkd.Config {
	ip := networkd.IPConfig{Method: "auto", Addresses: []string{}, DNS: []string{}, Routes: []networkd.Route{}, Metric: -1}
	return networkd.Config{IPv4: ip, IPv6: ip}
}
func basicSettings() settings {
	return settings{"connection": {"type": dbus.MakeVariant("802-3-ethernet"), "uuid": dbus.MakeVariant("test"), "timestamp": dbus.MakeVariant(uint64(1))}, "ipv4": {"method": dbus.MakeVariant("auto")}, "ipv6": {"method": dbus.MakeVariant("auto")}}
}
func TestNetworkManagerTypedSettingsRoundTrip(t *testing.T) {
	c := basicConfig()
	c.IPv4.Method = "manual"
	c.IPv4.Addresses = []string{"192.0.2.4/24"}
	c.IPv4.DNS = []string{"192.0.2.53"}
	c.IPv4.Routes = []networkd.Route{{Destination: "198.51.100.0/24", Gateway: "192.0.2.1", Metric: 123}}
	c.IPv6.Method = "manual"
	c.IPv6.Addresses = []string{"fd00::2/64"}
	c.IPv6.DNS = []string{"fd00::53"}
	c.MTU = 1400
	s := basicSettings()
	s["802-3-ethernet"] = map[string]dbus.Variant{"auto-negotiate": dbus.MakeVariant(true)}
	result := patched(s, c)
	if got := config(result); digest(got) != digest(c) {
		t.Fatalf("round trip: %+v != %+v", got, c)
	}
	if _, ok := s["ipv4"]["address-data"]; ok {
		t.Fatal("mutated original settings")
	}
	if !boolean(result["802-3-ethernet"]["auto-negotiate"]) {
		t.Fatal("unrelated setting lost")
	}
	if !editable(result) {
		t.Fatal("simple settings should be editable")
	}
}
func TestFingerprintIncludesNestedValues(t *testing.T) {
	s := patched(basicSettings(), basicConfig())
	s["ipv4"]["address-data"] = dbus.MakeVariant([]map[string]dbus.Variant{{"address": dbus.MakeVariant("192.0.2.1"), "prefix": dbus.MakeVariant(uint32(24))}})
	before := signature(s)
	s["connection"]["timestamp"] = dbus.MakeVariant(uint64(2))
	if signature(s) != before {
		t.Fatal("timestamp changed fingerprint")
	}
	s["ipv4"]["address-data"] = dbus.MakeVariant([]map[string]dbus.Variant{{"address": dbus.MakeVariant("192.0.2.2"), "prefix": dbus.MakeVariant(uint32(24))}})
	if signature(s) == before {
		t.Fatal("nested address change not detected")
	}
}
func TestIPValidationRejectsUnsafeConfigurations(t *testing.T) {
	for _, bad := range []string{"192.0.2.1", "::1/64", "224.0.0.1/24", "192.0.2.1/24\nDNS=1.1.1.1"} {
		c := basicConfig()
		c.IPv4.Method = "manual"
		c.IPv4.Addresses = []string{bad}
		if networkd.Validate(c) == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
	for _, bad := range []string{"192.0.2.1;reboot", "::1", "0.0.0.0"} {
		c := basicConfig()
		c.IPv4.DNS = []string{bad}
		if networkd.Validate(c) == nil {
			t.Fatalf("accepted DNS %q", bad)
		}
	}
	c := basicConfig()
	c.MTU = 1200
	if networkd.Validate(c) == nil {
		t.Fatal("IPv6 MTU")
	}
	c.IPv6.Method = "disabled"
	if e := networkd.Validate(c); e != nil {
		t.Fatal(e)
	}
	c.IPv4.Method = "disabled"
	if networkd.Validate(c) == nil {
		t.Fatal("both disabled")
	}
	c = basicConfig()
	c.IPv4.NeverDefault = true
	c.IPv4.Routes = []networkd.Route{{Destination: "0.0.0.0/0", Gateway: "192.0.2.1", Metric: -1}}
	if networkd.Validate(c) == nil {
		t.Fatal("local-only default route")
	}
}

func TestAbsentOptionalProperties(t *testing.T) {
	c := config(basicSettings())
	if c.IPv4.Method != "auto" || len(c.IPv4.DNS) != 0 || len(c.IPv6.Routes) != 0 {
		t.Fatalf("%+v", c)
	}
}

func TestRecoveryFailureIsExposedWithoutPrivateState(t *testing.T) {
	var s state
	if err := json.Unmarshal([]byte(`{"id":"test","status":"rollback-failed","error":"external configuration changed","profileHash":"private"}`), &s); err != nil {
		t.Fatal(err)
	}
	result := public(&s).(map[string]any)
	if result["status"] != "rollback-failed" || result["error"] != "external configuration changed" {
		t.Fatalf("missing recovery error: %#v", result)
	}
	if _, ok := result["profileHash"]; ok {
		t.Fatal("private transaction data exposed")
	}
}

func TestLegacyWiFiFractionalDeadline(t *testing.T) {
	var s state
	if err := json.Unmarshal([]byte(`{"kind":"network.wifi.radio","status":"expired","deadline":1791368436.034579}`), &s); err != nil {
		t.Fatal(err)
	}
	if s.Deadline != 1791368436.034579 {
		t.Fatalf("deadline changed: %v", s.Deadline)
	}
}
