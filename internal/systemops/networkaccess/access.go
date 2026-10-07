package networkaccess

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"panasms.local/backend/internal/systemops"
)

const root = "/var/lib/panasms-agent/network-access"
const apID = "panasms-rescue-ap"
const usbID = "panasms-direct-usb"
const apUUID = "e2d765ac-e075-4f5e-8201-e1c5c58906c1"
const usbUUID = "e2d765ac-e075-4f5e-8201-e1c5c58906c2"

type Config struct {
	Enabled  bool   `json:"enabled"`
	Adapter  string `json:"adapter"`
	SSID     string `json:"ssid"`
	Password string `json:"password"`
	Band     string `json:"band"`
	Delay    int    `json:"delay"`
	OnLoss   bool   `json:"onLoss"`
	USB      bool   `json:"usb"`
}
type Device struct {
	Name      string   `json:"name"`
	MAC       string   `json:"mac"`
	Kind      string   `json:"kind"`
	Connected bool     `json:"connected"`
	Profile   string   `json:"profile"`
	AP        bool     `json:"ap"`
	Bands     []string `json:"bands"`
	Addresses []string `json:"addresses"`
	Clients   int      `json:"clients"`
	Usable    bool     `json:"usable"`
	Reserved  bool     `json:"reserved"`
}
type State struct {
	Phase      string `json:"phase"`
	Interface  string `json:"interface,omitempty"`
	Since      int64  `json:"since,omitempty"`
	HadNetwork bool   `json:"hadNetwork"`
	Suppressed bool   `json:"suppressed"`
	Clients    int    `json:"clients"`
	Error      string `json:"error,omitempty"`
	USBState   string `json:"usbState"`
}

func run(args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	b, err := systemops.Command(ctx, args, systemops.CommandOptions{})
	return string(b), err
}
func reject(s string) error { return &systemops.Rejected{Message: s} }
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
	if path != "/run/panasms-network-access.json" {
		old, _ := os.ReadFile(path)
		if string(old) == string(b) {
			return nil
		}
		return systemops.AtomicWrite(path, string(b), 0600)
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".network-access-*")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if _, e = f.Write(b); e != nil {
		f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	return os.Rename(f.Name(), path)
}
func lock() (func(), error) {
	if e := os.MkdirAll(root, 0700); e != nil {
		return nil, e
	}
	f, e := os.OpenFile(root+"/lock", os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	if e = unix.Flock(int(f.Fd()), unix.LOCK_EX); e != nil {
		f.Close()
		return nil, e
	}
	return func() { f.Close() }, nil
}
func load() (Config, error) { var c Config; e := read(root+"/config.json", &c); return c, e }
func splitRow(s string) []string {
	var fields []string
	var b strings.Builder
	escaped := false
	for _, r := range s {
		if escaped {
			b.WriteRune(r)
			escaped = false
		} else if r == '\\' {
			escaped = true
		} else if r == ':' {
			fields = append(fields, b.String())
			b.Reset()
		} else {
			b.WriteRune(r)
		}
	}
	return append(fields, b.String())
}
func wifiBands(info string) []string {
	var bands []string
	ap := false
	for _, line := range strings.Split(info, "\n") {
		if strings.TrimSpace(line) == "* AP" {
			ap = true
		}
	}
	if !ap {
		return bands
	}
	for _, band := range []struct{ label, pattern string }{{"bg", `\* 24[0-9]+(?:\.[0-9]+)? MHz`}, {"a", `\* 5[0-9]+(?:\.[0-9]+)? MHz`}} {
		for _, line := range strings.Split(info, "\n") {
			if regexp.MustCompile(band.pattern).MatchString(line) && !strings.Contains(line, "disabled") && !strings.Contains(line, "no IR") && !strings.Contains(line, "radar detection") {
				bands = append(bands, band.label)
				break
			}
		}
	}
	return bands
}
func devices() ([]Device, error) {
	out, e := run("nmcli", "-t", "-f", "DEVICE,TYPE,STATE,CON-UUID", "device")
	if e != nil {
		return nil, e
	}
	rows := []Device{}
	var groups []struct {
		Source  string   `json:"source"`
		Outputs []string `json:"outputs"`
	}
	if err := read("/var/lib/panasms-agent/network-sharing/groups.json", &groups); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		f := splitRow(line)
		if len(f) != 4 {
			continue
		}
		name := f[0]
		if f[1] != "wifi" && f[1] != "ethernet" {
			continue
		}
		p := filepath.Join("/sys/class/net", name)
		resolved, _ := filepath.EvalSymlinks(p)
		isUSB := strings.Contains(resolved, "/gadget/") || strings.Contains(resolved, "/gadget/net/")
		if f[1] == "ethernet" && strings.Contains(resolved, "/virtual/") {
			continue
		}
		d := Device{Name: name, Kind: f[1], Profile: f[3], Connected: strings.HasPrefix(f[2], "connected"), Clients: 0, Usable: f[2] != "unmanaged" && f[2] != "unavailable"}
		for _, g := range groups {
			for _, member := range append(g.Outputs, g.Source) {
				if member == name {
					d.Reserved = true
				}
			}
		}
		if isUSB {
			d.Kind = "usb"
		}
		if intf, err := net.InterfaceByName(name); err == nil {
			d.MAC = intf.HardwareAddr.String()
			addresses, _ := intf.Addrs()
			for _, a := range addresses {
				d.Addresses = append(d.Addresses, a.String())
			}
		}
		if f[1] == "ethernet" {
			carrier, err := os.ReadFile(p + "/carrier")
			d.Connected = err == nil && ethernetConnected(f[2], string(carrier))
			if master, err := filepath.EvalSymlinks(p + "/master"); err == nil {
				if intf, err := net.InterfaceByName(filepath.Base(master)); err == nil {
					addresses, _ := intf.Addrs()
					for _, a := range addresses {
						d.Addresses = append(d.Addresses, a.String())
					}
				}
			}
		}
		if f[1] == "wifi" {
			if mac, err := os.ReadFile(p + "/phy80211/macaddress"); err == nil {
				d.MAC = strings.ToLower(strings.TrimSpace(string(mac)))
			}
			phy, err := filepath.EvalSymlinks(p + "/phy80211")
			if err == nil {
				info, err := run("/usr/sbin/iw", "phy", filepath.Base(phy), "info")
				if err == nil {
					d.Bands = wifiBands(info)
					d.AP = len(d.Bands) > 0
				}
			}
			if d.Profile == apUUID {
				stations, err := run("/usr/sbin/iw", "dev", name, "station", "dump")
				if err != nil {
					d.Clients = -1
				} else {
					d.Clients = strings.Count(stations, "Station ")
				}
			}
		}
		rows = append(rows, d)
	}
	return rows, nil
}
func ethernetConnected(state, carrier string) bool {
	return strings.TrimSpace(carrier) == "1" && (strings.HasPrefix(state, "connected") || state == "unmanaged")
}

func hasAddress(d Device) bool {
	for _, a := range d.Addresses {
		ip, _, e := net.ParseCIDR(a)
		if e == nil && ip.IsGlobalUnicast() && !ip.IsLinkLocalUnicast() {
			return true
		}
	}
	return false
}
func connected(rows []Device) bool {
	for _, d := range rows {
		if d.Connected && d.Profile != apUUID && hasAddress(d) {
			return true
		}
	}
	return false
}
func choose(c Config, rows []Device) *Device {
	for i := range rows {
		d := &rows[i]
		if d.Kind == "wifi" && d.AP && d.Usable && !d.Reserved && (c.Adapter == "" || strings.EqualFold(c.Adapter, d.MAC)) && (!d.Connected || !hasAddress(*d)) {
			return d
		}
	}
	return nil
}
func validate(c Config) error {
	if c.Delay < 30 || c.Delay > 900 {
		return reject("Choose a network wait between 30 and 900 seconds")
	}
	if len(c.SSID) < 1 || len(c.SSID) > 32 || strings.ContainsAny(c.SSID, "\n\r\x00") {
		return reject("Enter a Wi-Fi name between 1 and 32 bytes")
	}
	if len(c.Password) < 12 || len(c.Password) > 63 {
		return reject("Use a Wi-Fi password with 12 to 63 printable characters")
	}
	for _, r := range c.Password {
		if r < 32 || r > 126 {
			return reject("Use a Wi-Fi password with 12 to 63 printable characters")
		}
	}
	if c.Band != "auto" && c.Band != "bg" && c.Band != "a" {
		return reject("Choose an available Wi-Fi band")
	}
	if c.Adapter != "" {
		if _, e := net.ParseMAC(c.Adapter); e != nil {
			return reject("Choose an available Wi-Fi adapter")
		}
	}
	return nil
}
func keyValue(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "\n", "\\n")
	s = strings.ReplaceAll(s, "\r", "\\r")
	if strings.HasPrefix(s, " ") {
		s = "\\s" + s[1:]
	}
	return s
}
func subnet(rows []Device, offset int) (string, error) {
	for n := offset; n < offset+100; n++ {
		cidr := fmt.Sprintf("10.%d.%d.1/24", 180+n/250, n%250)
		_, candidate, _ := net.ParseCIDR(cidr)
		overlap := false
		routes, err := run("ip", "-j", "-4", "route", "show", "table", "all")
		if err != nil {
			return "", err
		}
		var entries []struct {
			Dst string `json:"dst"`
		}
		if err = json.Unmarshal([]byte(routes), &entries); err != nil {
			return "", err
		}
		for _, r := range entries {
			ip, network, e := net.ParseCIDR(r.Dst)
			if e == nil && r.Dst != "0.0.0.0/0" && (network.Contains(candidate.IP) || candidate.Contains(ip)) {
				overlap = true
			}
		}
		for _, d := range rows {
			for _, a := range d.Addresses {
				ip, network, e := net.ParseCIDR(a)
				if e == nil && (network.Contains(candidate.IP) || candidate.Contains(ip)) {
					overlap = true
				}
			}
		}
		if !overlap {
			return cidr, nil
		}
	}
	return "", reject("No unused subnet is available for direct access")
}
func profile(id, uuid, kind, name, addr, extra string) string {
	return fmt.Sprintf("[connection]\nid=%s\nuuid=%s\ntype=%s\ninterface-name=%s\nautoconnect=false\n\n[ipv4]\nmethod=shared\naddress1=%s\nnever-default=true\n\n[ipv6]\nmethod=disabled\n%s", id, uuid, kind, name, addr, extra)
}
func installProfile(id, content string) error {
	path := "/etc/NetworkManager/system-connections/" + id + ".nmconnection"
	if e := systemops.AtomicWrite(path, content, 0600); e != nil {
		return e
	}
	_, e := run("nmcli", "connection", "load", path)
	return e
}
func startAP(c Config, d Device, rows []Device) error {
	band := c.Band
	if band == "auto" {
		band = d.Bands[0]
	}
	found := false
	for _, b := range d.Bands {
		found = found || b == band
	}
	if !found {
		return reject("The selected Wi-Fi band is unavailable")
	}
	addr, e := subnet(rows, 10)
	if e != nil {
		return e
	}
	extra := fmt.Sprintf("\n[wifi]\nmode=ap\nsecurity=802-11-wireless-security\nssid=%s\nband=%s\n\n[wifi-security]\nkey-mgmt=wpa-psk\nproto=rsn;\npsk=%s\n", keyValue(c.SSID), band, keyValue(c.Password))
	if e = installProfile(apID, profile(apID, apUUID, "wifi", d.Name, addr, extra)); e != nil {
		return e
	}
	_, e = run("nmcli", "--wait", "15", "connection", "up", "uuid", apUUID, "ifname", d.Name)
	return e
}
func stopAP() error {
	_, e := run("nmcli", "--wait", "10", "connection", "down", "uuid", apUUID)
	return e
}
func Query() (json.RawMessage, error) {
	c, e := load()
	if e != nil {
		return nil, e
	}
	rows, e := devices()
	if e != nil {
		return nil, e
	}
	var state State
	_ = read("/run/panasms-network-access.json", &state)
	usb := usbCapability()
	return json.Marshal(map[string]any{"config": c, "devices": rows, "state": state, "usb": usb})
}
func Credentials() error {
	c, e := load()
	if e != nil {
		return e
	}
	if c.Enabled {
		fmt.Printf("Fallback Wi-Fi: %s\nWi-Fi password: %s\nReview these settings before travelling: Settings > Network.\n", c.SSID, c.Password)
	}
	return nil
}
func Plan(action string, p map[string]any) (json.RawMessage, error) {
	c, e := load()
	if e != nil {
		return nil, e
	}
	if action == "network.access.save" {
		b, _ := json.Marshal(p)
		var next Config
		if e = json.Unmarshal(b, &next); e != nil {
			return nil, e
		}
		if e = validate(next); e != nil {
			return nil, e
		}
		if next.USB && !usbCapability().Available {
			return nil, reject("USB device mode is unavailable on this board")
		}
		oldAP, newAP := c, next
		oldAP.USB, newAP.USB = false, false
		if next.Enabled && oldAP != newAP {
			rows, err := devices()
			if err != nil {
				return nil, err
			}
			ok := false
			for _, d := range rows {
				if d.AP && !d.Reserved && (next.Adapter == "" || strings.EqualFold(d.MAC, next.Adapter)) {
					ok = true
					if next.Band != "auto" {
						ok = false
						for _, b := range d.Bands {
							ok = ok || b == next.Band
						}
					}
					if ok {
						break
					}
				}
			}
			if !ok {
				return nil, reject("No suitable Wi-Fi adapter is available")
			}
		}
	} else if action != "network.access.stop" {
		return nil, reject("Unknown network access operation")
	}
	digest := sha256.Sum256([]byte(c.Password))
	c.Password = hex.EncodeToString(digest[:])
	fingerprint, e := systemops.Fingerprint(action, p, map[string]any{"config": fmt.Sprintf("%+v", c)})
	if e != nil {
		return nil, e
	}
	return json.Marshal(map[string]any{"target": "network-access", "confirmation": "network-access", "fingerprint": fingerprint, "details": []string{"Direct access settings"}})
}
func Execute(action string, p map[string]any) (json.RawMessage, error) {
	release, err := networkLock()
	if err != nil {
		return nil, err
	}
	defer release()
	unlock, e := lock()
	if e != nil {
		return nil, e
	}
	defer unlock()
	var st State
	_ = read("/run/panasms-network-access.json", &st)
	rows, e := devices()
	if e != nil {
		return nil, e
	}
	active := false
	for _, d := range rows {
		active = active || d.Profile == apUUID
	}
	if action == "network.access.stop" {
		if active {
			if e = stopAP(); e != nil {
				return nil, e
			}
		}
		st.Suppressed = true
		st.Phase = "suppressed"
		st.Interface = ""
		st.Clients = 0
	} else {
		b, _ := json.Marshal(p)
		previous, e := load()
		if e != nil {
			return nil, e
		}
		var c Config
		if e = json.Unmarshal(b, &c); e != nil {
			return nil, e
		}
		if e = validate(c); e != nil {
			return nil, e
		}
		// Persist intent first so restart/retry converges on the requested configuration.
		if e = write(root+"/config.json", c); e != nil {
			return nil, e
		}
		oldAP, newAP := previous, c
		oldAP.USB, newAP.USB = false, false
		if active && oldAP != newAP {
			if e = stopAP(); e != nil {
				return nil, e
			}
		}
		if e = configureUSB(c.USB); e != nil {
			return nil, e
		}
		st = State{Since: time.Now().Unix(), Phase: "waiting"}
	}
	if e = write("/run/panasms-network-access.json", st); e != nil {
		return nil, e
	}
	return json.Marshal(map[string]any{"updated": true})
}
func Initialize() error {
	unlock, e := lock()
	if e != nil {
		return e
	}
	defer unlock()
	c, e := load()
	if errors.Is(e, os.ErrNotExist) {
		random := make([]byte, 12)
		if _, e = rand.Read(random); e != nil {
			return e
		}
		rows, err := devices()
		if err != nil {
			return err
		}
		enabled := false
		for _, d := range rows {
			enabled = enabled || (d.AP && !d.Reserved)
		}
		c = Config{Enabled: enabled, SSID: "PaNasMs-" + hex.EncodeToString(random[:3]), Password: hex.EncodeToString(random[3:]), Band: "auto", Delay: 90, OnLoss: true, USB: usbCapability().Available}
		if e = write(root+"/config.json", c); e != nil {
			return e
		}
	} else if e != nil {
		return e
	}
	return configureUSB(c.USB)
}
func Tick() error {
	unlock, e := lock()
	if e != nil {
		return e
	}
	defer unlock()
	c, e := load()
	if e != nil {
		return e
	}
	rows, e := devices()
	if e != nil {
		return e
	}
	var st State
	_ = read("/run/panasms-network-access.json", &st)
	st.USBState = usbStatus(c, rows)
	next, action, adapter := decide(c, st, rows, time.Now().Unix())
	switch action {
	case "stop":
		e = stopAP()
	case "start":
		e = startAP(c, *adapter, rows)
	}
	if e != nil {
		next.Error = e.Error()
		next.Phase = "error"
		next.Since = time.Now().Unix()
	}
	if err := write("/run/panasms-network-access.json", next); err != nil {
		return err
	}
	return e
}
func decide(c Config, st State, rows []Device, now int64) (State, string, *Device) {
	if st.Since == 0 {
		st.Since = now
	}
	st.Error = ""
	var active *Device
	for i := range rows {
		if rows[i].Profile == apUUID {
			active = &rows[i]
			break
		}
	}
	online := connected(rows)
	if online {
		st.HadNetwork = true
	}
	if active != nil {
		st.Interface, st.Clients, st.Phase = active.Name, active.Clients, "access-point"
		if !c.Enabled || st.Suppressed || (online && active.Clients == 0) {
			st.Interface, st.Phase, st.Since = "", "waiting", now
			return st, "stop", nil
		}
		if online {
			st.Phase = "restored"
		}
	} else {
		st.Interface, st.Clients = "", 0
		switch {
		case online:
			st.Since, st.Phase = now, "connected"
		case !c.Enabled:
			st.Phase = "disabled"
		case st.Suppressed:
			st.Phase = "suppressed"
		case st.HadNetwork && !c.OnLoss:
			st.Phase = "waiting-reboot"
		case now-st.Since < int64(c.Delay):
			st.Phase = "waiting"
		default:
			if d := choose(c, rows); d != nil {
				st.Phase, st.Interface = "access-point", d.Name
				return st, "start", d
			}
			st.Phase = "unavailable"
		}
	}
	return st, "", nil
}
func networkLock() (func(), error) {
	const path = "/run/panasms-network"
	if e := os.MkdirAll(path, 0700); e != nil {
		return nil, e
	}
	f, e := os.OpenFile(path+"/lock", os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	if e = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); e != nil {
		f.Close()
		return nil, reject("A network operation is in progress; try again shortly")
	}
	var change struct {
		Status string `json:"status"`
	}
	if e = read(path+"/change.json", &change); e != nil && !errors.Is(e, os.ErrNotExist) {
		f.Close()
		return nil, e
	}
	if change.Status == "pending" || change.Status == "applying" {
		f.Close()
		return nil, reject("Confirm or revert the pending network change first")
	}
	return func() { f.Close() }, nil
}

func Run() error {
	if e := Initialize(); e != nil {
		if _, configError := load(); configError != nil {
			return e
		}
		fmt.Fprintln(os.Stderr, "network access initialization:", e)
	}
	for {
		if e := tickGuarded(); e != nil {
			fmt.Fprintln(os.Stderr, "network access:", e)
		}
		time.Sleep(10 * time.Second)
	}
}
func tickGuarded() error {
	// Cooperate with network rollback transactions and exclusive package maintenance.
	var files []*os.File
	defer func() {
		for _, f := range files {
			f.Close()
		}
	}()
	for _, spec := range []struct {
		path string
		mode int
	}{{"/run/lock/panasms-maintenance.lock", unix.LOCK_SH}, {"/run/panasms-network/lock", unix.LOCK_EX}} {
		if e := os.MkdirAll(filepath.Dir(spec.path), 0700); e != nil {
			return e
		}
		f, e := os.OpenFile(spec.path, os.O_CREATE|os.O_RDWR, 0600)
		if e != nil {
			return e
		}
		files = append(files, f)
		if e = unix.Flock(int(f.Fd()), spec.mode|unix.LOCK_NB); e != nil {
			return nil
		}
	}
	var change struct {
		Status string `json:"status"`
	}
	_ = read("/run/panasms-network/change.json", &change)
	if change.Status == "pending" || change.Status == "applying" {
		return nil
	}
	return Tick()
}
func Remove() error {
	rows, e := devices()
	if e != nil {
		return e
	}
	for _, d := range rows {
		if d.Profile == apUUID || d.Profile == usbUUID {
			if _, e = run("nmcli", "connection", "down", "uuid", d.Profile); e != nil {
				return e
			}
		}
	}
	for id, uuid := range map[string]string{apID: apUUID, usbID: usbUUID} {
		p := "/etc/NetworkManager/system-connections/" + id + ".nmconnection"
		if _, e = os.Stat(p); e == nil {
			if _, e = run("nmcli", "connection", "delete", "uuid", uuid); e != nil {
				return e
			}
		}
	}
	if e = configureUSB(false); e != nil {
		return e
	}
	if e = os.Remove("/etc/modules-load.d/panasms-usb.conf"); e != nil && !errors.Is(e, os.ErrNotExist) {
		return e
	}
	return nil
}
