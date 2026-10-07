package network

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/godbus/dbus/v5"
	"panasms.local/backend/internal/systemops"
	"panasms.local/backend/internal/systemops/networkaccess"
	"panasms.local/backend/internal/systemops/networkd"
	"panasms.local/backend/internal/systemops/networknative"
)

var validName = regexp.MustCompile(`^[a-zA-Z0-9_.:-]{1,15}$`)
var statePath = "/run/panasms-network/change.json"

type state struct {
	ID          string          `json:"id"`
	Kind        string          `json:"kind"`
	Interface   string          `json:"interface"`
	User        string          `json:"user"`
	Status      string          `json:"status"`
	Error       string          `json:"error,omitempty"`
	Deadline    float64         `json:"deadline"`
	Addresses   []string        `json:"addresses"`
	Checkpoint  dbus.ObjectPath `json:"checkpoint"`
	Profile     dbus.ObjectPath `json:"profile"`
	ProfileHash string          `json:"profileHash"`
	AppliedHash string          `json:"appliedHash"`
	Config      networkd.Config `json:"config"`
}

func command(args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	return systemops.Command(ctx, args, systemops.CommandOptions{})
}
func digest(v any) string {
	b, _ := json.Marshal(v)
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}
func readState() (*state, error) {
	b, e := os.ReadFile(statePath)
	if os.IsNotExist(e) {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	var s state
	e = json.Unmarshal(b, &s)
	return &s, e
}
func save(s *state) error {
	b, e := json.Marshal(s)
	if e != nil {
		return e
	}
	if e = os.MkdirAll(filepath.Dir(statePath), 0700); e != nil {
		return e
	}
	return systemops.AtomicWrite(statePath, string(b), 0600)
}
func active(s *state) bool {
	return s != nil && (s.Status == "pending" || s.Status == "applying" || s.Status == "rollback-failed")
}
func current(a *adapter) (*state, error) {
	s, e := readState()
	if e != nil || s == nil {
		return s, e
	}
	if a != nil && s.Kind == "network.nm" && active(s) {
		paths, e := a.checkpoints()
		if e != nil {
			return nil, e
		}
		if !slices.Contains(paths, s.Checkpoint) {
			s.Status = "expired"
			e = save(s)
			return s, e
		}
	}
	return s, nil
}
func public(s *state) any {
	if s == nil {
		return nil
	}
	return map[string]any{"id": s.ID, "interface": s.Interface, "user": s.User, "status": s.Status, "error": s.Error, "deadline": s.Deadline, "addresses": s.Addresses}
}
func systemInterface(name string) bool {
	p, e := filepath.EvalSymlinks("/sys/class/net/" + name)
	if e != nil {
		return true
	}
	_, wireless := os.Stat("/sys/class/net/" + name + "/phy80211")
	return networkaccess.IsGadgetPath(p) || name == "lo" || name == "docker0" || strings.HasPrefix(name, "veth") || (strings.HasPrefix(p, "/sys/devices/virtual/net/") && wireless != nil)
}
func accessInterface(name string) bool {
	b, _ := os.ReadFile("/run/panasms-network-access.json")
	var s struct {
		Interface string `json:"interface"`
	}
	_ = json.Unmarshal(b, &s)
	p, _ := filepath.EvalSymlinks("/sys/class/net/" + name)
	_, usb := os.Stat("/etc/modules-load.d/panasms-usb.conf")
	return name != "" && (name == s.Interface || (networkaccess.IsGadgetPath(p) && usb == nil))
}
func guard(name string) error {
	if !validName.MatchString(name) || systemInterface(name) {
		return fmt.Errorf("System interfaces cannot be edited")
	}
	if accessInterface(name) {
		return fmt.Errorf("Manage this connection in Network access settings")
	}
	b, e := os.ReadFile("/var/lib/panasms-agent/network-sharing/groups.json")
	if e != nil && !os.IsNotExist(e) {
		return e
	}
	if len(b) > 0 {
		var groups []struct {
			Source  string   `json:"source"`
			Outputs []string `json:"outputs"`
		}
		if e = json.Unmarshal(b, &groups); e != nil {
			return e
		}
		for _, g := range groups {
			if g.Source == name || slices.Contains(g.Outputs, name) {
				return fmt.Errorf("Edit this interface through its sharing group")
			}
		}
	}
	return nil
}
func legacy(ctx context.Context, mode, action, user string, p map[string]any) (json.RawMessage, error) {
	body, _ := json.Marshal(map[string]any{"mode": mode, "action": action, "user": user, "params": p})
	raw, e := systemops.Command(ctx, []string{"/usr/bin/python3", "-B", "/usr/lib/panasms/management/network_dependencies.py"}, systemops.CommandOptions{Input: body, Operation: mode == "execute"})
	if e != nil {
		return nil, e
	}
	var result struct {
		Error string `json:"error"`
	}
	if e = systemops.Decode(raw, &result); e != nil {
		return nil, e
	}
	if result.Error != "" {
		return nil, &systemops.Rejected{Message: result.Error}
	}
	return raw, nil
}
func Operation(ctx context.Context, mode, action, user string, p map[string]any) (json.RawMessage, error) {
	s, e := readState()
	if e != nil {
		return nil, e
	}
	if s != nil && s.Kind == "network.native" && (action == "network.confirm" || action == "network.rollback") {
		return networknative.Operation(mode, action, user, p)
	}
	if strings.HasPrefix(action, "network.wifi.") || strings.HasPrefix(action, "network.share.") {
		a, err := connect()
		if err == nil {
			a.bus.Close()
			return legacy(ctx, mode, action, user, p)
		}
		if !networknative.Active() {
			return nil, fmt.Errorf("No supported network manager is active")
		}
		if strings.HasPrefix(action, "network.wifi.") && action != "network.wifi.scan" && action != "network.wifi.radio" {
			name, _ := p["interface"].(string)
			if err := guard(name); err != nil {
				return nil, err
			}
		}
		if action == "network.wifi.radio" {
			name, _ := p["interface"].(string)
			if systemInterface(name) || accessInterface(name) {
				return nil, fmt.Errorf("Manage this connection in Network access settings")
			}
		}
		return networknative.Operation(mode, action, user, p)
	}
	if action != "network.configure" && s != nil && s.Kind != "network.nm" && s.Kind != "network.networkd" {
		return legacy(ctx, mode, action, user, p)
	}
	unlock, e := networkd.Lock()
	if e != nil {
		return nil, e
	}
	defer unlock()
	a, _ := connect()
	if a != nil {
		defer a.bus.Close()
	}
	s, e = current(a)
	if e != nil {
		return nil, e
	}
	native := s != nil && s.Kind == "network.networkd"
	if action == "network.configure" {
		name, _ := p["interface"].(string)
		if e = guard(name); e != nil {
			return nil, &systemops.Rejected{Message: e.Error()}
		}
		managed := false
		if a != nil {
			_, props, err := a.device(name)
			managed = err == nil && boolean(props["Managed"])
		}
		native = !managed && len(networkd.Query([]string{name})) > 0
	}
	var result any
	if native {
		result, e = networkd.Operation(mode, action, user, p)
	} else if a == nil {
		e = fmt.Errorf("No supported network manager owns this interface")
	} else {
		result, e = nmOperation(a, mode, action, user, p, s)
	}
	if e != nil {
		return nil, &systemops.Rejected{Message: e.Error()}
	}
	return json.Marshal(result)
}
func nmOperation(a *adapter, mode, action, user string, p map[string]any, s *state) (any, error) {
	if action == "network.configure" {
		if active(s) {
			return nil, fmt.Errorf("Confirm or roll back the pending network change first")
		}
		name, _ := p["interface"].(string)
		path, profile, saved, applied, version, e := a.active(name)
		if e != nil {
			return nil, e
		}
		if !editable(saved) || !editable(applied) {
			return nil, fmt.Errorf("Advanced connection settings cannot be edited by this form")
		}
		b, _ := json.Marshal(p["config"])
		var c networkd.Config
		if e = json.Unmarshal(b, &c); e != nil {
			return nil, e
		}
		if e = networkd.Validate(c); e != nil {
			return nil, e
		}
		if digest(c) == digest(config(saved)) {
			return nil, fmt.Errorf("Network settings have not changed")
		}
		if mode == "plan" {
			return map[string]any{"target": name, "confirmation": name, "details": []string{name, "Network changes require confirmation within two minutes"}, "fingerprint": digest([]any{action, p, path, profile, signature(saved), signature(applied), version})}, nil
		}
		var checkpoint dbus.ObjectPath
		if e = a.call(nmPath, nm+".CheckpointCreate", []dbus.ObjectPath{path}, uint32(120), uint32(0)).Store(&checkpoint); e != nil {
			return nil, e
		}
		id := make([]byte, 16)
		if _, e = rand.Read(id); e != nil {
			_ = a.rollback(checkpoint)
			return nil, e
		}
		s = &state{ID: hex.EncodeToString(id), Kind: "network.nm", Interface: name, User: user, Checkpoint: checkpoint, Profile: profile, ProfileHash: signature(saved), Status: "applying", Deadline: float64(time.Now().Unix() + 120), Addresses: append(append([]string{}, c.IPv4.Addresses...), c.IPv6.Addresses...), Config: c}
		if e = save(s); e != nil {
			_ = a.rollback(checkpoint)
			return nil, e
		}
		e = a.call(path, nm+".Device.Reapply", patched(applied, c), version, uint32(0)).Err
		if e == nil {
			e = a.call(path, nm+".Device.GetAppliedConnection", uint32(0)).Store(&applied, &version)
		}
		if e != nil {
			rollbackErr := a.rollback(checkpoint)
			s.Status = "rolled-back"
			if rollbackErr != nil {
				s.Status = "pending"
			}
			_ = save(s)
			return nil, fmt.Errorf("Could not apply network settings; rollback requested")
		}
		s.AppliedHash = signature(applied)
		s.Status = "pending"
		if e = save(s); e != nil {
			return nil, e
		}
		return map[string]any{"message": "Network changes await confirmation", "change": public(s)}, nil
	}
	if action != "network.confirm" && action != "network.rollback" {
		return nil, fmt.Errorf("Unknown network operation")
	}
	if s == nil || s.Status != "pending" || p["id"] != s.ID || s.User != user || float64(time.Now().Unix()) >= s.Deadline {
		return nil, fmt.Errorf("This network change has expired or is owned by another user")
	}
	if mode == "plan" {
		return map[string]any{"target": s.Interface, "confirmation": s.ID, "details": []string{s.Interface}, "fingerprint": digest([]any{action, p, s.ID, s.Checkpoint})}, nil
	}
	if action == "network.rollback" {
		if e := a.rollback(s.Checkpoint); e != nil {
			return nil, e
		}
		s.Status = "rolled-back"
	} else {
		_, profile, saved, applied, _, e := a.active(s.Interface)
		if e != nil {
			return nil, e
		}
		if profile != s.Profile || signature(saved) != s.ProfileHash || signature(applied) != s.AppliedHash {
			return nil, fmt.Errorf("Network configuration changed externally; roll back and review it again")
		}
		if e = a.call(nmPath, nm+".CheckpointAdjustRollbackTimeout", s.Checkpoint, uint32(60)).Err; e != nil {
			return nil, e
		}
		s.Deadline = float64(time.Now().Unix() + 60)
		if e = save(s); e != nil {
			return nil, e
		}
		if e = a.persist(saved, s.Config); e != nil {
			return nil, e
		}
		if e = a.call(nmPath, nm+".CheckpointDestroy", s.Checkpoint).Err; e != nil {
			return nil, e
		}
		s.Status = "confirmed"
	}
	if e := save(s); e != nil {
		return nil, e
	}
	message := "Previous network settings restored"
	if s.Status == "confirmed" {
		message = "Network settings confirmed"
	}
	return map[string]any{"message": message}, nil
}
