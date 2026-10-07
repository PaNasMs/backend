package network

import (
	"encoding/json"
	"os"
	"panasms.local/backend/internal/systemops/networkd"
	"path/filepath"
	"testing"
	"time"
)

func TestLiveNetworkManagerCheckpoint(t *testing.T) {
	if os.Getenv("PANASMS_NETWORK_LIVE") != "1" {
		t.Skip("requires an explicitly enabled root-only host integration run")
	}
	a, e := connect()
	if e != nil {
		t.Fatal(e)
	}
	defer a.bus.Close()
	const name = "pnm-test0"
	const peer = "pnm-test1"
	const profile = "panasms-go-network-test"
	if _, e = os.Stat("/sys/class/net/" + name); !os.IsNotExist(e) {
		t.Fatal("test interface already exists")
	}
	old := statePath
	statePath = filepath.Join(t.TempDir(), "change.json")
	defer func() { statePath = old }()
	run := func(args ...string) {
		t.Helper()
		if _, e := command(args...); e != nil {
			t.Fatalf("%v: %v", args, e)
		}
	}
	run("ip", "link", "add", name, "type", "veth", "peer", "name", peer)
	t.Cleanup(func() {
		if s, _ := readState(); s != nil && active(s) {
			_ = a.rollback(s.Checkpoint)
		}
		_, _ = command("nmcli", "connection", "delete", profile)
		_, _ = command("ip", "link", "delete", name)
	})
	run("ip", "link", "set", peer, "up")
	run("nmcli", "connection", "add", "type", "ethernet", "ifname", name, "con-name", profile, "ipv4.method", "manual", "ipv4.addresses", "198.18.91.1/30", "ipv4.never-default", "yes", "ipv6.method", "disabled", "connection.autoconnect", "no")
	run("nmcli", "--wait", "10", "connection", "up", profile)
	_, _, saved, _, _, e := a.active(name)
	if e != nil {
		t.Fatal(e)
	}
	original := config(saved)
	c := original
	c.IPv4.Addresses = []string{"198.18.91.2/30"}
	c.IPv4.Routes = []networkd.Route{{Destination: "198.18.92.0/24", Gateway: "198.18.91.1", Metric: 321}}
	c.IPv6.Method = "manual"
	c.IPv6.Addresses = []string{"fd61:1a8e:99::2/64"}
	c.IPv6.NeverDefault = true
	c.MTU = 1400
	p := map[string]any{"interface": name, "config": c}
	apply := func() {
		t.Helper()
		s, _ := current(a)
		if _, e := nmOperation(a, "execute", "network.configure", "test-admin", p, s); e != nil {
			t.Fatal(e)
		}
	}
	confirm := func(action, user string) error {
		s, e := current(a)
		if e != nil {
			return e
		}
		_, e = nmOperation(a, "execute", action, user, map[string]any{"id": s.ID}, s)
		return e
	}
	check := func(want networkd.Config, persisted bool) {
		t.Helper()
		_, _, saved, applied, _, e := a.active(name)
		if e != nil {
			t.Fatal(e)
		}
		got := config(applied)
		if persisted {
			got = config(saved)
		}
		if digest(got) != digest(want) {
			b, _ := json.Marshal(got)
			w, _ := json.Marshal(want)
			t.Fatalf("configuration %s != %s", b, w)
		}
	}
	apply()
	check(original, true)
	check(c, false)
	if confirm("network.confirm", "other-admin") == nil {
		t.Fatal("another administrator confirmed")
	}
	if e = confirm("network.rollback", "test-admin"); e != nil {
		t.Fatal(e)
	}
	time.Sleep(time.Second)
	check(original, false)
	t.Log("temporary apply, identity check and explicit rollback passed")
	apply()
	s, _ := readState()
	if e = a.call(nmPath, nm+".CheckpointAdjustRollbackTimeout", s.Checkpoint, uint32(2)).Err; e != nil {
		t.Fatal(e)
	}
	time.Sleep(4 * time.Second)
	s, e = current(a)
	if e != nil || s.Status != "expired" {
		t.Fatalf("timeout: %+v %v", s, e)
	}
	check(original, false)
	check(original, true)
	t.Log("NetworkManager timeout restored settings")
	apply()
	if e = confirm("network.confirm", "test-admin"); e != nil {
		t.Fatal(e)
	}
	check(c, true)
	c.MTU = 1450
	p["config"] = c
	apply()
	run("nmcli", "connection", "modify", profile, "ipv4.route-metric", "123")
	if confirm("network.confirm", "test-admin") == nil {
		t.Fatal("external edit overwritten")
	}
	if e = confirm("network.rollback", "test-admin"); e != nil {
		t.Fatal(e)
	}
	t.Log("confirmation and external edit protection passed")
}
