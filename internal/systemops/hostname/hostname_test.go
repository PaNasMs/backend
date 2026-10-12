package hostname

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidation(t *testing.T) {
	for _, n := range []string{"nas", "n", strings.Repeat("a", 63), "nas-2"} {
		if e := Validate(n); e != nil {
			t.Fatal(n, e)
		}
	}
	for _, n := range []string{"", "NAS", "localhost", "nas.local", "-nas", "nas-", "foo\nbar", strings.Repeat("a", 64), "../etc"} {
		if Validate(n) == nil {
			t.Fatal(n)
		}
	}
}
func TestHosts(t *testing.T) {
	in := "127.0.0.1 localhost\n127.0.1.1 old old.local alias # keep\n10.0.0.2 other\n"
	want := "127.0.0.1 localhost\n127.0.1.1\tnew\talias # keep\n10.0.0.2 other\n"
	if got := Hosts(in, "old", "new"); got != want {
		t.Fatal(got)
	}
	if !strings.Contains(Hosts("127.0.0.1 localhost\n", "old", "new"), "127.0.1.1\tnew\n") {
		t.Fatal("missing loopback mapping")
	}
}
func TestConfigPreservesUnownedSettings(t *testing.T) {
	in := "[server]\nhost-name=custom\nallow-interfaces=docker0\nuse-ipv6=no\n[publish]\npublish-workstation=no\n[reflector]\nenable-reflector=yes\n"
	got := Config(in, []string{"wlan0", "eth0"})
	for _, s := range []string{"allow-interfaces=eth0,wlan0", "use-ipv6=no", "publish-workstation=no", "enable-reflector=no", "domain-name=local"} {
		if !strings.Contains(got, s) {
			t.Fatal(got)
		}
	}
	if strings.Contains(got, "custom") || strings.Count(got, "[server]") != 1 {
		t.Fatal(got)
	}
	if !strings.Contains(Config(in, nil), "allow-interfaces=lo") {
		t.Fatal("empty interfaces must not advertise everywhere")
	}
}
func TestInterfaceSelection(t *testing.T) {
	root := t.TempDir()
	for _, n := range []string{"eth0/device", "wlan0/phy80211", "docker0", "veth123", "br0/lower_eth0", "vlan10/lower_eth0", "lo"} {
		if e := os.MkdirAll(filepath.Join(root, n), 0755); e != nil {
			t.Fatal(e)
		}
	}
	for n, want := range map[string]bool{"eth0": true, "wlan0": true, "br0": true, "vlan10": true, "docker0": false, "veth123": false, "lo": false} {
		if got := InterfaceAllowed(root, n, map[string]bool{}); got != want {
			t.Fatal(n, got)
		}
	}
}
func fixture(t *testing.T) (*Service, *string) {
	t.Helper()
	d := t.TempDir()
	name := "old"
	s := &Service{Write: func(p, v string, m os.FileMode) error { return os.WriteFile(p, []byte(v), m) }, Hosts: filepath.Join(d, "hosts"), State: filepath.Join(d, "state"), Lock: filepath.Join(d, "lock"), Static: filepath.Join(d, "hostname"), Current: func() (string, error) { return name, nil }, Set: func(n string) error { name = n; return nil }, Refresh: func() error { return nil }}
	os.WriteFile(s.Hosts, []byte("127.0.1.1 old\n"), 0644)
	os.WriteFile(s.Static, []byte("old-static\n"), 0644)
	return s, &name
}
func TestChangeAndRollback(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "rollback"}[fail], func(t *testing.T) {
			s, n := fixture(t)
			calls := 0
			s.Refresh = func() error {
				calls++
				if fail && calls == 1 {
					return errors.New("failed")
				}
				return nil
			}
			_, e := s.Execute(map[string]any{"hostname": "new"})
			if (e != nil) != fail {
				t.Fatal(e)
			}
			want := "new"
			if fail {
				want = "old"
			}
			if *n != want {
				t.Fatal(*n)
			}
			b, _ := os.ReadFile(s.Hosts)
			if !strings.Contains(string(b), want) {
				t.Fatal(string(b))
			}
			if _, e := os.Stat(s.State); !os.IsNotExist(e) {
				t.Fatal("journal remains", e)
			}
		})
	}
}
func TestRecoveryAndStalePlan(t *testing.T) {
	s, n := fixture(t)
	p := map[string]any{"hostname": "new"}
	a, _ := s.Plan(p)
	os.WriteFile(s.Hosts, []byte("127.0.1.1 old alias\n"), 0644)
	b, _ := s.Plan(p)
	if string(a) == string(b) {
		t.Fatal("hosts change must invalidate plan")
	}
	st, _ := json.Marshal(saved{Old: "old", Next: "new", Hosts: "127.0.1.1 old\n", Static: "old-static\n"})
	os.WriteFile(s.State, st, 0600)
	*n = "new"
	if _, e := s.Plan(p); e == nil {
		t.Fatal("pending recovery ignored")
	}
	if e := s.Recover(); e != nil {
		t.Fatal(e)
	}
	if *n != "old" {
		t.Fatal(*n)
	}
	static, _ := os.ReadFile(s.Static)
	if string(static) != "old-static\n" {
		t.Fatal(string(static))
	}
}
