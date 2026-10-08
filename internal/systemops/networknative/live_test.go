package networknative

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLiveNativeAccessPoint(t *testing.T) {
	name := os.Getenv("PANASMS_NATIVE_TEST_WIFI")
	if name == "" {
		t.Skip("requires an explicitly selected test adapter with NetworkManager stopped")
	}
	if os.Geteuid() != 0 || !Wireless(name) || !Active() {
		t.Fatal("native Wi-Fi test prerequisites unavailable")
	}
	if run("systemctl", "is-active", "--quiet", "NetworkManager") == nil {
		t.Fatal("stop NetworkManager before this hardware test")
	}
	c := Capability(name)
	if !c.AP || len(c.Channels["bg"]) == 0 {
		t.Fatal("no usable 2.4GHz AP channel")
	}
	subnet, err := groupSubnet(nil)
	if err != nil {
		t.Fatal(err)
	}
	const id = "native-acceptance"
	if DirectActive(id) {
		t.Fatal("previous test configuration still exists")
	}
	t.Cleanup(func() {
		if err := DirectStop(id, name); err != nil {
			t.Errorf("restore adapter: %v", err)
		}
	})
	config := APConfig{SSID: "PaNasMs-native-test", Password: ident(), Band: "bg", Channel: c.Channels["bg"][0]}
	if err := DirectStart(id, name, address(subnet), &config); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		raw, err := invoke("iw", "dev", name, "info")
		if err == nil && strings.Contains(string(raw), "type AP") && APActive(name) && hasGlobalAddress(Addresses(name)) {
			if err := run("systemctl", "is-active", "--quiet", dnsUnit(name)); err != nil {
				t.Fatal("DHCP service unavailable")
			}
			t.Log("native AP mode, assigned address, hostapd and DHCP confirmed; no client traffic tested")
			return
		}
		time.Sleep(time.Second)
	}
	t.Fatal("native AP did not become ready")
}

func TestLiveNativeRadioAndScan(t *testing.T) {
	name := os.Getenv("PANASMS_NATIVE_TEST_WIFI")
	if name == "" {
		t.Skip("requires an explicitly selected test adapter")
	}
	if os.Geteuid() != 0 || !Wireless(name) || !Active() {
		t.Fatal("native Wi-Fi prerequisites unavailable")
	}
	if run("systemctl", "is-active", "--quiet", "NetworkManager") == nil {
		t.Fatal("stop NetworkManager before this hardware test")
	}
	enabled, hardware := radio(name)
	if !hardware {
		t.Fatal("hardware blocked")
	}
	t.Cleanup(func() {
		if err := setRadio(name, enabled); err != nil {
			t.Error(err)
		}
	})
	if err := setRadio(name, false); err != nil {
		t.Fatal(err)
	}
	if enabled, _ := radio(name); enabled {
		t.Fatal("radio remained enabled")
	}
	if err := setRadio(name, true); err != nil {
		t.Fatal(err)
	}
	if enabled, _ := radio(name); !enabled {
		t.Fatal("radio remained disabled")
	}
	if err := Scan(name); err != nil {
		t.Fatal(err)
	}
	var networks []AccessPoint
	if err := read(root+"/scan/"+name+".json", &networks); err != nil {
		t.Fatal(err)
	}
	t.Logf("radio off/on confirmed; scan returned %d networks (names omitted)", len(networks))
}

func TestLiveNativeSharing(t *testing.T) {
	source := os.Getenv("PANASMS_NATIVE_TEST_UPLINK")
	if source == "" {
		t.Skip("requires an explicitly selected uplink and isolated veth test")
	}
	if os.Geteuid() != 0 || !Active() {
		t.Fatal("native sharing prerequisites unavailable")
	}
	if run("systemctl", "is-active", "--quiet", "NetworkManager") == nil {
		t.Fatal("stop NetworkManager before this hardware test")
	}
	const namespace, output, peer = "pn-native-test", "pn-test-out", "pn-test-peer"
	if exists("/run/netns/"+namespace) || exists("/sys/class/net/"+output) {
		t.Fatal("test namespace/interface already exists")
	}
	raw, err := invoke("ip", "-j", "-4", "rule", "show")
	if err != nil {
		t.Fatal(err)
	}
	var rules []map[string]any
	if err = json.Unmarshal(raw, &rules); err != nil {
		t.Fatal(err)
	}
	for _, r := range rules {
		if r["priority"] == float64(18098) {
			t.Fatal("test routing priority occupied")
		}
	}
	subnet, err := groupSubnet(nil)
	if err != nil {
		t.Fatal(err)
	}
	g := Group{ID: "acceptance12", Source: source, Outputs: []string{output}, Bridge: "pn-test-br", Mode: "nat", Subnet: subnet, Slot: 98, Enabled: true, Provider: "networkd", Previous: map[string]*string{}, Wifi: map[string]APConfig{}}
	if exists("/sys/class/net/" + g.Bridge) {
		t.Fatal("test bridge already exists")
	}
	if err = run("ip", "netns", "add", namespace); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = run("ip", "netns", "delete", namespace) })
	if err = run("ip", "link", "add", output, "type", "veth", "peer", "name", peer); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = run("ip", "link", "delete", output) })
	if err = run("ip", "link", "set", peer, "netns", namespace); err != nil {
		t.Fatal(err)
	}
	g.Files, err = renderGroup(g)
	if err != nil {
		t.Fatal(err)
	}
	for path := range g.Files {
		previous, err := fileState(path)
		if err != nil || previous != nil {
			t.Fatalf("test configuration already exists: %s", path)
		}
		g.Previous[path] = nil
	}
	t.Cleanup(func() {
		if err := DeactivateGroup(g); err != nil {
			t.Errorf("cleanup sharing: %v", err)
		}
	})
	if err = validateFiles(g.Files); err != nil {
		t.Fatal(err)
	}
	if err = ActivateGroup(g); err != nil {
		t.Fatal(err)
	}
	ip, _, _ := net.ParseCIDR(subnet)
	ip = ip.To4()
	ip[3] = 2
	for _, args := range [][]string{{"ip", "-n", namespace, "link", "set", peer, "up"}, {"ip", "-n", namespace, "address", "add", ip.String() + "/24", "dev", peer}, {"ip", "-n", namespace, "route", "add", "default", "via", strings.Split(address(subnet), "/")[0]}} {
		if err = run(args...); err != nil {
			t.Fatal(err)
		}
	}
	if os.Getenv("PANASMS_NATIVE_TEST_DHCP") == "1" {
		if err = run("ip", "-n", namespace, "address", "flush", "dev", peer); err != nil {
			t.Fatal(err)
		}
		script := filepath.Join(t.TempDir(), "lease.sh")
		if err = os.WriteFile(script, []byte("#!/bin/sh\nset -eu\ncase \"$1\" in bound|renew) ip addr replace \"$ip/24\" dev \"$interface\"; ip route replace default via \"${router%% *}\"; echo DHCP_BOUND;; esac\n"), 0700); err != nil {
			t.Fatal(err)
		}
		raw, err := invoke("ip", "netns", "exec", namespace, "busybox", "udhcpc", "-i", peer, "-s", script, "-n", "-q", "-t", "10", "-T", "3")
		if err != nil || !strings.Contains(string(raw), "DHCP_BOUND") {
			t.Fatalf("client did not obtain DHCP lease: %s %v", raw, err)
		}
		t.Log("isolated client obtained a real DHCP lease")
	}
	deadline := time.Now().Add(45 * time.Second)
	for {
		err = run("ip", "netns", "exec", namespace, "ping", "-c", "1", "-W", "1", strings.Split(address(subnet), "/")[0])
		if err == nil || time.Now().After(deadline) {
			break
		}
		time.Sleep(time.Second)
	}
	if err != nil {
		for _, args := range [][]string{{"ip", "-br", "address"}, {"bridge", "link", "show"}, {"networkctl", "status", output, "--no-pager"}} {
			raw, _ := invoke(args...)
			t.Log(string(raw))
		}
		t.Fatal("client cannot reach sharing bridge: ", err)
	}
	raw, err = invoke("ip", "-j", "-4", "route", "show", "default", "dev", source)
	if err != nil {
		t.Fatal(err)
	}
	var routes []struct {
		Gateway string `json:"gateway"`
	}
	if err = json.Unmarshal(raw, &routes); err != nil || len(routes) == 0 || routes[0].Gateway == "" {
		t.Fatal("no uplink gateway to test")
	}
	if err = run("ip", "netns", "exec", namespace, "ping", "-c", "2", "-W", "3", routes[0].Gateway); err != nil {
		t.Fatal("client cannot reach uplink gateway through NAT: ", err)
	}
	t.Log("isolated client reached bridge and upstream gateway through native NAT")
}
