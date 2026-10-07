package networknative

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"panasms.local/backend/internal/systemops"
)

var root = "/var/lib/panasms-agent/network-native"
var validName = regexp.MustCompile(`^[a-zA-Z0-9_-][a-zA-Z0-9_.-]{0,14}$`)
var invoke = command
var writeFile = systemops.AtomicWrite

func command(args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	return systemops.Command(ctx, args, systemops.CommandOptions{})
}
func run(args ...string) error { _, e := invoke(args...); return e }
func exists(path string) bool  { _, e := os.Stat(path); return e == nil }
func read(path string, v any) error {
	b, e := os.ReadFile(path)
	if e != nil {
		return e
	}
	return json.Unmarshal(b, v)
}
func write(path string, v any) error {
	b, e := json.Marshal(v)
	if e != nil {
		return e
	}
	if e = os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return e
	}
	return writeFile(path, string(b), 0600)
}
func hash(v any) string {
	b, _ := json.Marshal(v)
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}
func ident() string {
	b := make([]byte, 16)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return hex.EncodeToString(b)
}
func Active() bool { return run("systemctl", "is-active", "--quiet", "systemd-networkd") == nil }
func Netplan() bool {
	_, e := exec.LookPath("netplan")
	return e == nil && (hasGlob("/etc/netplan/*.yaml") || hasGlob("/run/netplan/*.yaml") || hasGlob("/lib/netplan/*.yaml"))
}
func hasGlob(p string) bool { x, _ := filepath.Glob(p); return len(x) > 0 }
func Wireless(name string) bool {
	return validName.MatchString(name) && exists("/sys/class/net/"+name+"/phy80211")
}
func CheckInterface(name string) error {
	if !validName.MatchString(name) {
		return fmt.Errorf("Invalid network interface")
	}
	p, e := filepath.EvalSymlinks("/sys/class/net/" + name)
	if e != nil {
		return e
	}
	if name == "lo" || strings.Contains(p, "/virtual/") && !Wireless(name) || strings.Contains(p, "/gadget") {
		return fmt.Errorf("System interfaces cannot be used for connection sharing")
	}
	return nil
}
func Identity(name string) string {
	p, _ := filepath.EvalSymlinks("/sys/class/net/" + name + "/device")
	b, _ := os.ReadFile("/sys/class/net/" + name + "/address")
	return p + ":" + strings.TrimSpace(string(b))
}
func Addresses(name string) []string {
	a := []string{}
	i, e := net.InterfaceByName(name)
	if e != nil {
		return a
	}
	rows, _ := i.Addrs()
	for _, r := range rows {
		a = append(a, r.String())
	}
	return a
}
func fileState(path string) (*string, error) {
	b, e := os.ReadFile(path)
	if os.IsNotExist(e) {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	s := string(b)
	return &s, nil
}
func setFile(path string, text *string) error {
	if text == nil {
		e := os.Remove(path)
		if os.IsNotExist(e) {
			return nil
		}
		return e
	}
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return e
	}
	return writeFile(path, *text, 0600)
}
func text(s string) *string { return &s }
func fields(raw []byte) map[string]string {
	m := map[string]string{}
	for _, l := range strings.Split(string(raw), "\n") {
		k, v, ok := strings.Cut(l, "=")
		if ok {
			m[k] = v
		}
	}
	return m
}

func hasGlobalAddress(addresses []string) bool {
	for _, address := range addresses {
		ip, _, err := net.ParseCIDR(address)
		if err == nil && ip.IsGlobalUnicast() {
			return true
		}
	}
	return false
}

func unitInstance(name string) string { return strings.ReplaceAll(name, "-", `\x2d`) }
func dnsUnit(name string) string      { return "panasms-dnsmasq@" + unitInstance(name) + ".service" }

func identityMAC(identity string) string {
	if len(identity) < 17 {
		return ""
	}
	candidate := identity[len(identity)-17:]
	if _, err := net.ParseMAC(candidate); err != nil {
		return ""
	}
	return candidate
}
