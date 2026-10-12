package hostname

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"panasms.local/backend/internal/systemops"
	"panasms.local/backend/internal/systemops/webaccess"
)

var valid = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

func Validate(name string) error {
	if !valid.MatchString(name) || name == "localhost" {
		return reject("Use 1–63 lowercase letters, digits or hyphens; start and end with a letter or digit")
	}
	return nil
}
func reject(s string) error { return &systemops.Rejected{Message: s} }
func run(args ...string) ([]byte, error) {
	return systemops.Command(context.Background(), args, systemops.CommandOptions{Timeout: 20 * time.Second, Operation: true})
}

type Service struct {
	Write                      func(string, string, os.FileMode) error
	Hosts, State, Lock, Static string
	Current                    func() (string, error)
	Set                        func(string) error
	Refresh                    func() error
}

func Default() *Service {
	return &Service{Write: systemops.AtomicWrite, Hosts: "/etc/hosts", Static: "/etc/hostname", State: "/var/lib/panasms-agent/hostname-change.json", Lock: "/run/lock/panasms-hostname.lock", Current: os.Hostname, Set: func(n string) error {
		_, e := run("hostnamectl", "--static", "--transient", "set-hostname", n)
		return e
	}, Refresh: func() error { _, e := run("systemctl", "restart", "avahi-daemon.service"); return e }}
}

type saved struct{ Old, Next, Hosts, Static string }

func (s *Service) locked(fn func() error) error {
	f, e := os.OpenFile(s.Lock, os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return e
	}
	defer f.Close()
	if e = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); e != nil {
		return reject("A hostname change is already in progress")
	}
	defer unix.Flock(int(f.Fd()), unix.LOCK_UN)
	return fn()
}
func Hosts(content, old, next string) string {
	lines := strings.Split(content, "\n")
	found := false
	for i, line := range lines {
		body, comment, _ := strings.Cut(line, "#")
		fields := strings.Fields(body)
		if len(fields) < 2 || fields[0] != "127.0.1.1" {
			continue
		}
		found = true
		aliases := []string{fields[0], next}
		for _, v := range fields[1:] {
			if v != old && v != old+".local" && v != next {
				aliases = append(aliases, v)
			}
		}
		lines[i] = strings.Join(aliases, "\t")
		if comment != "" {
			lines[i] += " #" + comment
		}
	}
	out := strings.Join(lines, "\n")
	if !found {
		out = strings.TrimRight(out, "\n") + "\n127.0.1.1\t" + next + "\n"
	}
	return out
}
func (s *Service) rollback(st saved) error {
	if e := s.Set(st.Old); e != nil {
		return e
	}
	if e := s.Write(s.Hosts, st.Hosts, 0644); e != nil {
		return e
	}
	if s.Static != "" {
		if e := s.Write(s.Static, st.Static, 0644); e != nil {
			return e
		}
	}
	if e := s.Refresh(); e != nil {
		return e
	}
	return os.Remove(s.State)
}
func (s *Service) Recover() error {
	return s.locked(func() error {
		b, e := os.ReadFile(s.State)
		if os.IsNotExist(e) {
			return nil
		}
		if e != nil {
			return e
		}
		var st saved
		if e = json.Unmarshal(b, &st); e != nil {
			return e
		}
		return s.rollback(st)
	})
}
func (s *Service) Plan(p map[string]any) (json.RawMessage, error) {
	n, _ := p["hostname"].(string)
	if e := Validate(n); e != nil {
		return nil, e
	}
	if _, e := os.Stat(s.State); e == nil {
		return nil, reject("An interrupted hostname change requires recovery")
	}
	old, e := s.Current()
	if e != nil {
		return nil, e
	}
	b, e := os.ReadFile(s.Hosts)
	if e != nil {
		return nil, e
	}
	fp, e := systemops.Fingerprint("system.hostname", p, map[string]any{"hostname": old, "hosts": string(b)})
	if e != nil {
		return nil, e
	}
	return json.Marshal(map[string]any{"target": n, "confirmation": n, "fingerprint": fp, "details": []string{old + " → " + n, n + ".local"}})
}
func (s *Service) Execute(p map[string]any) (json.RawMessage, error) {
	n, _ := p["hostname"].(string)
	if e := Validate(n); e != nil {
		return nil, e
	}
	e := s.locked(func() error {
		if _, e := s.Plan(p); e != nil {
			return e
		}
		old, e := s.Current()
		if e != nil {
			return e
		}
		hosts, e := os.ReadFile(s.Hosts)
		if e != nil {
			return e
		}
		st := saved{Old: old, Next: n, Hosts: string(hosts)}
		if s.Static != "" {
			b, e := os.ReadFile(s.Static)
			if e != nil {
				return e
			}
			st.Static = string(b)
		}
		b, _ := json.Marshal(st)
		if e = s.Write(s.State, string(b), 0600); e != nil {
			return e
		}
		e = s.Write(s.Hosts, Hosts(string(hosts), old, n), 0644)
		if e == nil {
			e = s.Set(n)
		}
		if e == nil {
			e = s.Refresh()
		}
		if e != nil {
			if r := s.rollback(st); r != nil {
				return reject("Hostname change failed; recovery is required")
			}
			return reject("Hostname change failed; previous settings were restored")
		}
		return os.Remove(s.State)
	})
	if e != nil {
		return nil, e
	}
	return json.Marshal(map[string]string{"message": "Hostname updated"})
}
func Query() (json.RawMessage, error) {
	name, e := os.Hostname()
	if e != nil {
		return nil, e
	}
	port, e := webaccess.Default().Current()
	if e != nil {
		return nil, e
	}
	fqdn := ""
	state := "unavailable"
	if b, e := run("busctl", "call", "org.freedesktop.Avahi", "/", "org.freedesktop.Avahi.Server", "GetState"); e == nil && strings.TrimSpace(string(b)) == "i 2" {
		b, e = run("busctl", "call", "org.freedesktop.Avahi", "/", "org.freedesktop.Avahi.Server", "GetHostNameFqdn")
		if e == nil {
			fqdn, _ = strconv.Unquote(strings.TrimPrefix(strings.TrimSpace(string(b)), "s "))
			if fqdn != "" {
				state = "ready"
			}
		}
	}
	scheme := "http"
	if _, e := os.Stat("/etc/panasms/https.enabled"); e == nil {
		scheme = "https"
	}
	return json.Marshal(map[string]any{"hostname": name, "networkName": fqdn, "state": state, "port": port, "scheme": scheme})
}

// Include virtual bridges/VLANs only when backed by a user-facing interface.
func InterfaceAllowed(root, name string, seen map[string]bool) bool {
	if seen[name] || name == "lo" {
		return false
	}
	seen[name] = true
	path := filepath.Join(root, name)
	if _, e := os.Stat(filepath.Join(path, "device")); e == nil {
		return true
	}
	if _, e := os.Stat(filepath.Join(path, "phy80211")); e == nil {
		return true
	}
	resolved, _ := filepath.EvalSymlinks(path)
	if strings.Contains(resolved, "/gadget/") || strings.Contains(resolved, "/gadget.") {
		return true
	}
	lowers, _ := filepath.Glob(filepath.Join(path, "lower_*"))
	for _, p := range lowers {
		if InterfaceAllowed(root, strings.TrimPrefix(filepath.Base(p), "lower_"), seen) {
			return true
		}
	}
	return false
}
func Config(base string, interfaces []string) string {
	sort.Strings(interfaces)
	if len(interfaces) == 0 {
		interfaces = []string{"lo"}
	}
	values := map[string]map[string]string{"server": {"host-name": "", "host-name-from-machine-id": "no", "domain-name": "local", "allow-interfaces": strings.Join(interfaces, ","), "deny-interfaces": "", "enable-dbus": "yes"}, "publish": {"disable-publishing": "no", "publish-addresses": "yes"}, "reflector": {"enable-reflector": "no"}}
	section := ""
	lines := []string{}
	for _, line := range strings.Split(base, "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "[") && strings.HasSuffix(t, "]") {
			section = strings.Trim(t, "[]")
		}
		k, _, ok := strings.Cut(t, "=")
		if ok {
			if _, owned := values[section][strings.TrimSpace(k)]; owned {
				continue
			}
		}
		lines = append(lines, line)
	}
	// Append keys to existing sections instead of duplicating section headers.
	for _, sec := range []string{"server", "publish", "reflector"} {
		block := []string{}
		keys := []string{}
		for k := range values[sec] {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if values[sec][k] != "" {
				block = append(block, k+"="+values[sec][k])
			}
		}
		pos := -1
		for i, l := range lines {
			if strings.TrimSpace(l) == "["+sec+"]" {
				pos = i + 1
				break
			}
		}
		if pos < 0 {
			lines = append(lines, "["+sec+"]")
			lines = append(lines, block...)
		} else {
			tail := append([]string{}, lines[pos:]...)
			lines = append(lines[:pos], block...)
			lines = append(lines, tail...)
		}
	}
	return strings.Join(lines, "\n") + "\n"
}
func Configure(restart bool) error {
	b, e := os.ReadFile("/etc/avahi/avahi-daemon.conf")
	if e != nil {
		return e
	}
	entries, e := os.ReadDir("/sys/class/net")
	if e != nil {
		return e
	}
	names := []string{}
	for _, entry := range entries {
		if InterfaceAllowed("/sys/class/net", entry.Name(), map[string]bool{}) {
			names = append(names, entry.Name())
		}
	}
	content := Config(string(b), names)
	path := "/run/panasms-mdns/avahi.conf"
	old, _ := os.ReadFile(path)
	if string(old) == content {
		return nil
	}
	if e = os.MkdirAll(filepath.Dir(path), 0755); e != nil {
		return e
	}
	if e = systemops.AtomicWrite(path, content, 0644); e != nil {
		return e
	}
	if restart {
		_, e = run("systemctl", "restart", "avahi-daemon.service")
		if e != nil {
			_ = os.Remove(path)
		}
	}
	return e
}
func CLI(mode string) error {
	switch mode {
	case "configure":
		return Configure(false)
	case "reconcile":
		return Configure(true)
	case "recover":
		return Default().Recover()
	}
	return fmt.Errorf("unknown hostname operation")
}
