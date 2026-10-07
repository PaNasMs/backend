package networkd

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"panasms.local/backend/internal/systemops"
)

var stateDir = "/var/lib/panasms-agent/networkd"
var pendingPath = "/run/panasms-network/change.json"

var interfaceName = regexp.MustCompile(`^[a-zA-Z0-9_.:-]{1,15}$`)

type link struct {
	Name                string
	NetworkFile         string
	NetworkFileDropins  []string
	AdministrativeState string
	OperationalState    string
	CarrierState        string
	HardwareAddress     []byte
	DNS                 []struct{ Address []byte }
}
type View struct {
	Manager  string   `json:"manager"`
	Source   string   `json:"configurationSource"`
	File     string   `json:"configurationFile"`
	Profile  string   `json:"profile"`
	Editable bool     `json:"editable"`
	Reason   string   `json:"editReason,omitempty"`
	Config   *Config  `json:"config"`
	DNS      []string `json:"dns"`
	Carrier  bool     `json:"carrier"`
	State    string   `json:"providerState"`
}
type snapshot struct {
	Backend     string
	Netplan     map[string]any
	Link        link
	Files       map[string]string
	Text        string
	Config      Config
	Path        string
	Fingerprint string
}
type change struct {
	Backend     string            `json:"backend"`
	PreviousMTU int               `json:"previousMTU"`
	AppliedMTU  int               `json:"appliedMTU"`
	Expected    string            `json:"expectedNetworkFile"`
	ID          string            `json:"id"`
	Kind        string            `json:"kind"`
	Interface   string            `json:"interface"`
	User        string            `json:"user"`
	Status      string            `json:"status"`
	Deadline    int64             `json:"deadline"`
	Addresses   []string          `json:"addresses"`
	Checkpoint  string            `json:"checkpoint"`
	Path        string            `json:"path"`
	Previous    *string           `json:"previous"`
	Applied     string            `json:"applied"`
	Sources     map[string]string `json:"sources"`
	Error       string            `json:"error,omitempty"`
}
type request struct {
	Action string `json:"action"`
	User   string `json:"user"`
	Params struct {
		Interface string `json:"interface"`
		Config    Config `json:"config"`
		ID        string `json:"id"`
	} `json:"params"`
	Names []string `json:"names"`
}

func command(args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return systemops.Command(ctx, args, systemops.CommandOptions{})
}

var invoke = command
var writeFile = systemops.AtomicWrite

func digest(v any) string {
	b, _ := json.Marshal(v)
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}
func ownedPath(name string) string { return "/etc/systemd/network/00-panasms-" + name + ".network" }
func inspect(name string) (snapshot, error) {
	s := snapshot{Files: map[string]string{}}
	if !interfaceName.MatchString(name) {
		return s, fmt.Errorf("Invalid network interface")
	}
	p, e := filepath.EvalSymlinks("/sys/class/net/" + name)
	if e != nil {
		return s, e
	}
	if strings.HasPrefix(p, "/sys/devices/virtual/") {
		return s, fmt.Errorf("System interfaces cannot be edited")
	}
	raw, e := invoke("networkctl", "--json=short", "status", name)
	if e != nil {
		return s, e
	}
	if e = json.Unmarshal(raw, &s.Link); e != nil {
		return s, e
	}
	if s.Link.Name != name || s.Link.NetworkFile == "" || s.Link.AdministrativeState == "unmanaged" {
		return s, fmt.Errorf("Interface is not managed by systemd-networkd")
	}
	s.Path = ownedPath(name)
	if filepath.Base(s.Path) > filepath.Base(s.Link.NetworkFile) {
		return s, fmt.Errorf("An earlier network file prevents safe per-interface configuration")
	}
	for _, path := range append([]string{s.Link.NetworkFile}, s.Link.NetworkFileDropins...) {
		clean := filepath.Clean(path)
		if !strings.HasPrefix(clean, "/etc/systemd/network/") && !strings.HasPrefix(clean, "/run/systemd/network/") && !strings.HasPrefix(clean, "/usr/lib/systemd/network/") {
			return s, fmt.Errorf("Unsupported network configuration location")
		}
		info, err := os.Lstat(clean)
		if err != nil {
			return s, err
		}
		if !info.Mode().IsRegular() || info.Size() > 1024*1024 {
			return s, fmt.Errorf("Unsupported network configuration file")
		}
		b, err := os.ReadFile(clean)
		if err != nil {
			return s, err
		}
		s.Files[clean] = string(b)
		s.Text += string(b) + "\n"
	}
	if len(s.Link.NetworkFileDropins) > 0 {
		return s, fmt.Errorf("Network configuration with drop-ins requires manual review")
	}
	s.Config, e = readConfig(s.Text)
	if e == nil && isNetplanFile(s.Link.NetworkFile) {
		e = readNetplan(&s)
	}
	s.Fingerprint = digest([]any{s.Link.Name, s.Link.HardwareAddress, s.Files})
	return s, e
}
func query(names []string) map[string]View {
	result := map[string]View{}
	for _, name := range names {
		s, e := inspect(name)
		if s.Link.NetworkFile == "" {
			continue
		}
		v := View{Manager: "systemd-networkd", Source: "systemd-networkd", File: s.Link.NetworkFile, Profile: filepath.Base(s.Link.NetworkFile), Editable: e == nil, Config: &s.Config, DNS: []string{}, Carrier: s.Link.CarrierState == "carrier", State: s.Link.AdministrativeState}
		if s.Backend == "netplan" {
			v.Source = "Netplan"
		}
		if s.Link.NetworkFile == s.Path {
			v.Source = "PaNasMs"
		}
		for _, d := range s.Link.DNS {
			v.DNS = append(v.DNS, net.IP(d.Address).String())
		}
		if e != nil {
			v.Reason = e.Error()
			v.Config = nil
		}
		result[name] = v
	}
	return result
}
func load() (*change, error) {
	b, e := os.ReadFile(stateDir + "/change.json")
	if os.IsNotExist(e) {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	var s change
	e = json.Unmarshal(b, &s)
	return &s, e
}
func save(s *change) error {
	b, e := json.Marshal(s)
	if e != nil {
		return e
	}
	if e = os.MkdirAll(stateDir, 0700); e != nil {
		return e
	}
	if e = writeFile(stateDir+"/change.json", string(b), 0600); e != nil {
		return e
	}
	if e = os.MkdirAll(filepath.Dir(pendingPath), 0700); e != nil {
		return e
	}
	return writeFile(pendingPath, string(b), 0600)
}
func active(s *change) bool {
	return s != nil && (s.Status == "pending" || s.Status == "applying" || s.Status == "rollback-failed")
}
func pending() bool {
	b, e := os.ReadFile(pendingPath)
	if e != nil {
		return false
	}
	var s struct {
		Status string `json:"status"`
	}
	if json.Unmarshal(b, &s) != nil {
		return true
	}
	return s.Status == "pending" || s.Status == "applying" || s.Status == "rollback-failed"
}
func unchanged(files map[string]string) bool {
	for p, want := range files {
		b, e := os.ReadFile(p)
		if e != nil || string(b) != want {
			return false
		}
	}
	return true
}
func reconfigure(name, backend string, mtu int) error {
	if backend == "netplan" {
		if _, e := invoke("netplan", "generate"); e != nil {
			return e
		}
	}
	if mtu > 0 {
		if b, err := os.ReadFile("/sys/class/net/" + name + "/mtu"); err == nil && strings.TrimSpace(string(b)) != strconv.Itoa(mtu) {
			if _, err = invoke("ip", "link", "set", "dev", name, "down"); err != nil {
				return err
			}
			_, mtuErr := invoke("ip", "link", "set", "dev", name, "mtu", strconv.Itoa(mtu))
			_, upErr := invoke("ip", "link", "set", "dev", name, "up")
			if mtuErr != nil {
				return mtuErr
			}
			if upErr != nil {
				return upErr
			}
		}
	}
	if _, e := invoke("networkctl", "reload"); e != nil {
		return e
	}
	_, e := invoke("networkctl", "reconfigure", name)
	return e
}
func rollback(s *change) error {
	b, e := os.ReadFile(s.Path)
	if e != nil && !os.IsNotExist(e) {
		return e
	}
	alreadyRestored := (s.Previous == nil && os.IsNotExist(e)) || (s.Previous != nil && e == nil && string(b) == *s.Previous)
	if !alreadyRestored && string(b) != s.Applied {
		s.Status = "rollback-failed"
		s.Error = "Network configuration changed externally; automatic rollback refused"
		_ = save(s)
		return fmt.Errorf("%s", s.Error)
	}
	if !alreadyRestored {
		if s.Previous == nil {
			e = os.Remove(s.Path)
		} else {
			e = writeFile(s.Path, *s.Previous, 0600)
		}
	} else {
		e = nil
	}
	if e == nil {
		e = reconfigure(s.Interface, s.Backend, s.PreviousMTU)
	}
	if e != nil {
		s.Status = "rollback-failed"
		s.Error = "Could not restore previous network settings; check the local console"
		_ = save(s)
		return e
	}
	s.Status = "rolled-back"
	s.Error = ""
	return save(s)
}
func public(s *change) any {
	if s == nil {
		return nil
	}
	return map[string]any{"id": s.ID, "kind": s.Kind, "interface": s.Interface, "user": s.User, "status": s.Status, "deadline": s.Deadline, "addresses": s.Addresses, "checkpoint": s.Checkpoint, "error": s.Error}
}
func plan(r request) (any, error) {
	s, e := load()
	if e != nil {
		return nil, e
	}
	if r.Action == "network.configure" {
		if active(s) || pending() {
			return nil, fmt.Errorf("Confirm or roll back the pending network change first")
		}
		snap, e := inspect(r.Params.Interface)
		if e != nil {
			return nil, e
		}
		if e = validate(r.Params.Config); e != nil {
			return nil, e
		}
		if digest(snap.Config) == digest(r.Params.Config) {
			return nil, fmt.Errorf("Network settings have not changed")
		}
		if snap.Backend == "netplan" {
			content, err := renderNetplan(snap, r.Params.Config)
			if err != nil {
				return nil, err
			}
			if err = validateNetplan(snap.Path, content); err != nil {
				return nil, fmt.Errorf("Netplan rejected these settings: %w", err)
			}
		}
		return map[string]any{"target": r.Params.Interface, "confirmation": r.Params.Interface, "details": []string{r.Params.Interface, "Network changes require confirmation within two minutes"}, "fingerprint": digest([]any{r.Action, r.Params, snap.Fingerprint})}, nil
	}
	if r.Action != "network.confirm" && r.Action != "network.rollback" {
		return nil, fmt.Errorf("Unknown network operation")
	}
	if !active(s) || s.ID != r.Params.ID || s.User != r.User {
		return nil, fmt.Errorf("This network change has expired or is owned by another user")
	}
	if r.Action == "network.confirm" && (s.Status != "pending" || time.Now().Unix() >= s.Deadline) {
		return nil, fmt.Errorf("This network change has expired")
	}
	return map[string]any{"target": s.Interface, "confirmation": s.ID, "details": []string{s.Interface}, "fingerprint": digest([]any{r.Action, r.Params, s})}, nil
}
func execute(r request) (any, error) {
	if _, e := plan(r); e != nil {
		return nil, e
	}
	if r.Action == "network.configure" {
		snap, e := inspect(r.Params.Interface)
		if e != nil {
			return nil, e
		}
		content, e := render(r.Params.Interface, net.HardwareAddr(snap.Link.HardwareAddress).String(), snap.Text, r.Params.Config)
		if snap.Backend == "netplan" {
			content, e = renderNetplan(snap, r.Params.Config)
			if e == nil {
				e = validateNetplan(snap.Path, content)
			}
		}
		if e != nil {
			return nil, e
		}
		var previous *string
		if b, e := os.ReadFile(snap.Path); e == nil {
			v := string(b)
			previous = &v
		} else if !os.IsNotExist(e) {
			return nil, e
		}
		id := make([]byte, 16)
		if _, e = rand.Read(id); e != nil {
			return nil, e
		}
		s := &change{Backend: snap.Backend, ID: hex.EncodeToString(id), Kind: "network.networkd", Interface: r.Params.Interface, User: r.User, Status: "applying", Deadline: time.Now().Unix() + 120, Addresses: append(append([]string{}, r.Params.Config.IPv4.Addresses...), r.Params.Config.IPv6.Addresses...), Path: snap.Path, Previous: previous, Applied: content, Sources: snap.Files}
		if b, err := os.ReadFile("/sys/class/net/" + s.Interface + "/mtu"); err == nil {
			s.PreviousMTU, _ = strconv.Atoi(strings.TrimSpace(string(b)))
		}
		s.AppliedMTU = r.Params.Config.MTU
		if s.AppliedMTU == 0 {
			s.AppliedMTU = automaticMTU(s.Interface)
		}
		s.Checkpoint = s.ID
		s.Expected = s.Path
		if s.Backend == "netplan" {
			s.Expected = "/run/systemd/network/10-netplan-" + netplanID(s.Interface) + ".network"
		}
		if e = save(s); e != nil {
			return nil, e
		}
		if _, e = invoke("systemctl", "start", "panasms-networkd-recovery.service"); e != nil {
			s.Status = "rolled-back"
			_ = save(s)
			return nil, e
		}
		if e = os.MkdirAll(filepath.Dir(s.Path), 0755); e == nil {
			e = writeFile(s.Path, content, 0600)
		}
		if e == nil {
			e = reconfigure(s.Interface, s.Backend, s.AppliedMTU)
		}
		if e != nil {
			if re := rollback(s); re != nil {
				return nil, fmt.Errorf("Apply and rollback failed; check the local console")
			}
			return nil, fmt.Errorf("Could not apply network settings; previous settings restored")
		}
		s.Status = "pending"
		if e = save(s); e != nil {
			return nil, e
		}
		return map[string]any{"message": "Network changes await confirmation", "change": public(s)}, nil
	}
	s, e := load()
	if e != nil {
		return nil, e
	}
	if r.Action == "network.rollback" {
		e = rollback(s)
	} else {
		sources := map[string]string{}
		for p, v := range s.Sources {
			if p != s.Path {
				sources[p] = v
			}
		}
		b, err := os.ReadFile(s.Path)
		if err != nil || string(b) != s.Applied || !unchanged(sources) {
			return nil, fmt.Errorf("Network configuration changed externally; roll back and review it again")
		}
		snap, err := inspect(s.Interface)
		if err != nil || snap.Link.NetworkFile != s.Expected || snap.Link.AdministrativeState != "configured" {
			return nil, fmt.Errorf("Network settings have not been applied; wait or roll back")
		}
		if s.AppliedMTU > 0 {
			b, err := os.ReadFile("/sys/class/net/" + s.Interface + "/mtu")
			if err != nil || strings.TrimSpace(string(b)) != strconv.Itoa(s.AppliedMTU) {
				return nil, fmt.Errorf("The requested MTU has not been applied; roll back and review the interface")
			}
		}
		s.Status = "confirmed"
		e = save(s)
	}
	if e != nil {
		return nil, e
	}
	return map[string]any{"message": map[bool]string{true: "Network settings confirmed", false: "Previous network settings restored"}[s.Status == "confirmed"]}, nil
}
func lock() (func(), error) {
	if e := os.MkdirAll(filepath.Dir(pendingPath), 0700); e != nil {
		return nil, e
	}
	f, e := os.OpenFile(filepath.Join(filepath.Dir(pendingPath), "lock"), os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	if e = unix.Flock(int(f.Fd()), unix.LOCK_EX); e != nil {
		f.Close()
		return nil, e
	}
	return func() { f.Close() }, nil
}
func Recover() error {
	for {
		unlock, e := lock()
		if e != nil {
			return e
		}
		s, e := load()
		if e != nil {
			unlock()
			return e
		}
		if !active(s) {
			unlock()
			return nil
		}
		_, pendingErr := os.Stat(pendingPath)
		if errors.Is(pendingErr, os.ErrNotExist) || time.Now().Unix() >= s.Deadline || s.Status == "rollback-failed" {
			e = rollback(s)
			unlock()
			return e
		}
		unlock()
		time.Sleep(time.Second)
	}
}
func Run(mode string, in io.Reader, out io.Writer) error {
	if mode == "recover" {
		return Recover()
	}
	if mode == "plan" || mode == "execute" {
		unlock, err := lock()
		if err != nil {
			return err
		}
		defer unlock()
	}
	var r request
	if e := json.NewDecoder(io.LimitReader(in, 1024*1024)).Decode(&r); e != nil {
		return e
	}
	var value any
	var e error
	switch mode {
	case "query":
		value = query(r.Names)
	case "current":
		var s *change
		s, e = load()
		value = public(s)
	case "plan":
		value, e = plan(r)
	case "execute":
		value, e = execute(r)
	default:
		e = fmt.Errorf("Unknown networkd operation")
	}
	if e != nil {
		value = map[string]string{"error": e.Error()}
	}
	return json.NewEncoder(out).Encode(value)
}

func automaticMTU(name string) int {
	index, err := os.ReadFile("/sys/class/net/" + name + "/ifindex")
	if err == nil {
		lease, _ := os.ReadFile("/run/systemd/netif/leases/" + strings.TrimSpace(string(index)))
		for _, line := range strings.Split(string(lease), "\n") {
			if v, ok := strings.CutPrefix(line, "MTU="); ok {
				if mtu, err := strconv.Atoi(v); err == nil && mtu >= 1280 && mtu <= 9000 {
					return mtu
				}
			}
		}
	}
	return 1500
}
