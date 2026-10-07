package networkd

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

const armbianConfig = "[Match]\nName=e*\n[Network]\nDHCP=yes\nLinkLocalAddressing=ipv6\nIPv6PrivacyExtensions=yes\n[DHCP]\nRouteMetric=100\nUseMTU=true\n"

func TestArmbianReadAndNativeRoundTrip(t *testing.T) {
	c, e := readConfig(armbianConfig)
	if e != nil {
		t.Fatal(e)
	}
	if c.IPv4.Method != "auto" || c.IPv6.Method != "auto" || c.IPv4.Metric != 100 {
		t.Fatal(c)
	}
	c.IPv4.Method = "manual"
	c.IPv4.Addresses = []string{"192.0.2.15/24"}
	c.IPv4.DNS = []string{"192.0.2.1"}
	c.IPv4.Gateway = "192.0.2.1"
	c.MTU = 1400
	c.IPv4.Routes = []Route{{"198.51.100.0/24", "192.0.2.2", 50}}
	text, e := render("end0", "02:00:00:00:00:01", armbianConfig, c)
	if e != nil {
		t.Fatal(e)
	}
	got, e := readConfig(text)
	if e != nil {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(got, c) {
		t.Fatalf("round trip: %#v != %#v\n%s", got, c, text)
	}
	if strings.Contains(text, "Name=e*") {
		t.Fatal("modified all Ethernet devices")
	}
}
func TestRejectUnsupportedConfiguration(t *testing.T) {
	for _, extra := range []string{"[Network]\nBridge=br0\n", "[RoutingPolicyRule]\nTable=100\n", "[Route]\nTable=100\n", "[Network]\nDNS=bad;command\n"} {
		if _, e := readConfig(armbianConfig + extra); e == nil {
			t.Fatal(extra)
		}
	}
}
func TestNetplanPreservesWildcardAndOtherFields(t *testing.T) {
	c, _ := readConfig(armbianConfig)
	c.MTU = 1400
	original := map[string]any{"match": map[string]any{"name": "e*"}, "dhcp4": true, "dhcp6": true, "optional": true, "ipv6-privacy": true, "nameservers": map[string]any{"search": []string{"home.arpa"}}}
	before := digest(original)
	s := snapshot{Netplan: original, Link: link{Name: "end0", HardwareAddress: []byte{2, 0, 0, 0, 0, 1}}}
	text, e := renderNetplan(s, c)
	if e != nil {
		t.Fatal(e)
	}
	if digest(original) != before {
		t.Fatal("mutated original wildcard definition")
	}
	var doc map[string]any
	if e = yaml.Unmarshal([]byte(text), &doc); e != nil {
		t.Fatal(e)
	}
	node := doc["network"].(map[string]any)["ethernets"].(map[string]any)["00-panasms-end0"].(map[string]any)
	if node["match"].(map[string]any)["name"] != "end0" || node["optional"] != true || node["ipv6-privacy"] != true {
		t.Fatal(node)
	}
	if node["nameservers"].(map[string]any)["search"].([]any)[0] != "home.arpa" {
		t.Fatal(node)
	}
}
func TestRejectInjectedAndInvalidIP(t *testing.T) {
	base, _ := readConfig(armbianConfig)
	for _, v := range []string{"1.2.3.4\n[Network]", "::1", "224.0.0.1"} {
		c := base
		c.IPv4.DNS = []string{v}
		if validate(c) == nil {
			t.Fatal(v)
		}
	}
}
func TestRecoveryRestoresOnlyOwnedFile(t *testing.T) {
	oldDir, oldPending, oldInvoke, oldWrite := stateDir, pendingPath, invoke, writeFile
	writeFile = func(p, s string, m os.FileMode) error {
		if e := os.MkdirAll(filepath.Dir(p), 0700); e != nil {
			return e
		}
		return os.WriteFile(p, []byte(s), m)
	}
	t.Cleanup(func() { stateDir, pendingPath, invoke, writeFile = oldDir, oldPending, oldInvoke, oldWrite })
	root := t.TempDir()
	stateDir = root + "/state"
	pendingPath = root + "/run/change.json"
	calls := []string{}
	invoke = func(args ...string) ([]byte, error) { calls = append(calls, strings.Join(args, " ")); return nil, nil }
	path := root + "/90-panasms-end0.yaml"
	original := "old YAML"
	applied := "new YAML"
	if e := os.WriteFile(path, []byte(applied), 0600); e != nil {
		t.Fatal(e)
	}
	other := root + "/original-netplan.yaml"
	os.WriteFile(other, []byte("original"), 0600)
	s := &change{Backend: "netplan", Status: "pending", Interface: "end0", Deadline: time.Now().Unix() - 1, Path: path, Previous: &original, Applied: applied}
	if e := save(s); e != nil {
		t.Fatal(e)
	}
	if e := Recover(); e != nil {
		t.Fatal(e)
	}
	got, _ := os.ReadFile(path)
	if string(got) != original {
		t.Fatal(string(got))
	}
	if !reflect.DeepEqual(calls, []string{"netplan generate", "networkctl reload", "networkctl reconfigure end0"}) {
		t.Fatal(calls)
	}
	b, _ := os.ReadFile(other)
	if string(b) != "original" {
		t.Fatal("changed unrelated file")
	}
	s.Status = "pending"
	s.Previous = nil
	s.Deadline = time.Now().Unix() + 120
	os.WriteFile(path, []byte(applied), 0600)
	save(s)
	os.Remove(pendingPath)
	if e := Recover(); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(path); !os.IsNotExist(e) {
		t.Fatal("new per-interface definition survived reboot rollback")
	}
}
func TestRecoveryDoesNotOverwriteExternalEdits(t *testing.T) {
	oldDir, oldPending := stateDir, pendingPath
	t.Cleanup(func() { stateDir, pendingPath = oldDir, oldPending })
	root := t.TempDir()
	stateDir = root + "/state"
	pendingPath = root + "/run/change.json"
	path := filepath.Join(root, "settings")
	os.WriteFile(path, []byte("external"), 0600)
	s := &change{Status: "pending", Path: path, Applied: "ours"}
	if e := rollback(s); e == nil {
		t.Fatal("overwrote external changes")
	}
	b, _ := os.ReadFile(path)
	if string(b) != "external" {
		t.Fatal(string(b))
	}
}
