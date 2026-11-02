package network

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/godbus/dbus/v5"
)

func readNMGroups() ([]nmGroup, error) {
	groups := []nmGroup{}
	raw, e := os.ReadFile(filepath.Join(sharingRoot, "groups.json"))
	if os.IsNotExist(e) {
		return groups, nil
	}
	if e == nil {
		e = json.Unmarshal(raw, &groups)
	}
	if e != nil {
		return nil, e
	}
	return groups, nil
}
func loadNMGroups() ([]nmGroup, error) {
	groups, e := readNMGroups()
	if e != nil {
		return nil, e
	}
	for _, g := range groups {
		if g.Provider != "" && g.Provider != "NetworkManager" {
			return nil, fmt.Errorf("Existing sharing groups require migration before switching network providers")
		}
	}
	return groups, nil
}
func (a *adapter) wifiPlan(action, user string, p map[string]any) (any, error) {
	s, e := readState()
	if e != nil {
		return nil, e
	}
	if active(s) {
		return nil, fmt.Errorf("Confirm or roll back the pending network change first")
	}
	name, _ := p["interface"].(string)
	if accessInterface(name) {
		return nil, fmt.Errorf("Manage this connection in Network access settings")
	}
	if action != "network.wifi.scan" && action != "network.wifi.radio" {
		groups, e := loadNMGroups()
		if e != nil {
			return nil, e
		}
		for _, g := range groups {
			if name == g.Source || slices.Contains(g.Outputs, name) {
				return nil, fmt.Errorf("Edit this interface through its sharing group")
			}
		}
	}
	path, props, e := a.wifiDevice(name)
	if e != nil {
		return nil, e
	}
	radios, e := a.adapterRadio(name)
	if e != nil {
		return nil, e
	}
	var extra any
	if action == "network.wifi.radio" {
		enabled, ok := p["enabled"].(bool)
		if !ok {
			return nil, fmt.Errorf("Invalid network option")
		}
		if enabled == radios.Enabled {
			return nil, fmt.Errorf("Network settings have not changed")
		}
		if enabled && !radios.HardwareEnabled {
			return nil, fmt.Errorf("Wi-Fi is blocked by a hardware switch")
		}
	} else {
		if !radios.Enabled || !radios.HardwareEnabled {
			return nil, fmt.Errorf("Enable Wi-Fi before scanning or connecting")
		}
		switch action {
		case "network.wifi.connect":
			choice, e := a.wifiSelection(path, props, p)
			if e != nil {
				return nil, e
			}
			extra = map[string]any{"profile": choice.Profile, "hash": choice.Hash, "security": choice.Security, "accessPoint": choice.AccessPoint, "hidden": choice.Hidden}
		case "network.wifi.disconnect":
			if obj(props["ActiveConnection"]) == "/" {
				return nil, fmt.Errorf("Wi-Fi adapter is not connected")
			}
		case "network.wifi.scan":
		default:
			return nil, fmt.Errorf("Unknown network operation")
		}
	}
	return map[string]any{"target": name, "confirmation": name, "details": []string{name}, "fingerprint": digest([]any{action, publicNetworkParams(p), path, radios, obj(props["ActiveConnection"]), extra})}, nil
}
func publicNetworkParams(value any) any {
	switch v := value.(type) {
	case map[string]any:
		out := map[string]any{}
		for k, x := range v {
			secret := false
			for _, word := range []string{"password", "passphrase", "secret", "token"} {
				secret = secret || strings.Contains(strings.ToLower(k), word)
			}
			if !secret {
				out[k] = publicNetworkParams(x)
			}
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, x := range v {
			out[i] = publicNetworkParams(x)
		}
		return out
	default:
		return value
	}
}
func (a *adapter) resumeNMSharing(name string) error {
	groups, e := loadNMGroups()
	if e != nil {
		return e
	}
	for _, g := range groups {
		if !g.Enabled || (g.Source != name && !slices.Contains(g.Outputs, name)) {
			continue
		}
		id := g.Profiles[name]
		if id == "" && g.Previous[name] != nil {
			id = *g.Previous[name]
		}
		if id == "" {
			continue
		}
		profiles, e := a.profiles()
		if e != nil {
			return e
		}
		profile, ok := profiles[id]
		if !ok {
			return fmt.Errorf("Sharing configuration changed externally; review it again")
		}
		path, _, e := a.device(name)
		if e != nil {
			return e
		}
		if e = a.call(nmPath, nm+".ActivateConnection", profile.Path, path, dbus.ObjectPath("/")).Err; e != nil {
			return e
		}
	}
	return nil
}
func (a *adapter) wifiExecute(action, user string, p map[string]any) (any, error) {
	if _, e := a.wifiPlan(action, user, p); e != nil {
		return nil, e
	}
	name, _ := p["interface"].(string)
	path, props, e := a.wifiDevice(name)
	if e != nil {
		return nil, e
	}
	if action == "network.wifi.scan" {
		previous, e := a.props(path, nm+".Device.Wireless")
		if e != nil {
			return nil, e
		}
		if e = a.call(path, nm+".Device.Wireless.RequestScan", map[string]dbus.Variant{}).Err; e != nil {
			return nil, fmt.Errorf("Wi-Fi scan is unavailable or was requested too recently; try again shortly")
		}
		for i := 0; i < 24; i++ {
			p, e := a.props(path, nm+".Device.Wireless")
			if e != nil {
				return nil, e
			}
			if num(p["LastScan"]) != num(previous["LastScan"]) {
				break
			}
			time.Sleep(500 * time.Millisecond)
		}
		return map[string]any{"message": "Wi-Fi scan requested"}, nil
	}
	var choice wifiChoice
	if action == "network.wifi.connect" {
		choice, e = a.wifiSelection(path, props, p)
		if e != nil {
			return nil, e
		}
	}
	id, e := randomID()
	if e != nil {
		return nil, e
	}
	boot, e := bootID()
	if e != nil {
		return nil, e
	}
	radios, e := a.radio()
	if e != nil {
		return nil, e
	}
	s := &nmChange{state: state{ID: id, Kind: action, Interface: name, User: user, Status: "applying", Deadline: float64(time.Now().Unix()) + 120, Addresses: []string{}}, HashVersion: 1, Boot: boot, RadioBefore: radios.Enabled}
	if action == "network.wifi.radio" {
		before, e := a.radioSnapshot()
		if e != nil {
			return nil, e
		}
		s.AdaptersBefore = &before
	}
	if action == "network.wifi.connect" && choice.Profile == "" {
		s.NewUUID, e = randomUUID()
		if e != nil {
			return nil, e
		}
	}
	if e = a.call(nmPath, nm+".CheckpointCreate", []dbus.ObjectPath{path}, uint32(150), uint32(0)).Store(&s.Checkpoint); e != nil {
		return nil, e
	}
	if e = s.remember(); e != nil {
		_ = a.rollback(s.Checkpoint)
		return nil, e
	}
	apply := func() error {
		if e := s.arm(120); e != nil {
			return e
		}
		switch action {
		case "network.wifi.radio":
			enabled := p["enabled"].(bool)
			if enabled {
				if e := a.enableRadio(name); e != nil {
					return e
				}
				if e := a.resumeNMSharing(name); e != nil {
					return e
				}
			} else if e := a.configureRadio(name, false); e != nil {
				return e
			}
			s.RadioAfter = enabled
		case "network.wifi.disconnect":
			if e := a.call(path, nm+".Device.Disconnect").Err; e != nil {
				return e
			}
		case "network.wifi.connect":
			var profile, connection dbus.ObjectPath
			if choice.Profile != "" {
				profile = choice.Profile
				e = a.call(nmPath, nm+".ActivateConnection", profile, path, dbus.ObjectPath("/")).Store(&connection)
			} else {
				var result map[string]dbus.Variant
				e = a.call(nmPath, nm+".AddAndActivateConnection2", wifiConnection(choice, name, s.NewUUID), path, choice.AccessPoint, map[string]dbus.Variant{"persist": dbus.MakeVariant("memory")}).Store(&profile, &connection, &result)
			}
			if e != nil {
				return e
			}
			ready := false
			for i := 0; i < 90; i++ {
				p, e := a.props(connection, nm+".Connection.Active")
				if e != nil {
					return e
				}
				status := num(p["State"])
				if status == 2 {
					ready = true
					break
				}
				if status == 3 || status == 4 {
					return fmt.Errorf("Wi-Fi connection failed; check password, signal and router settings")
				}
				time.Sleep(500 * time.Millisecond)
			}
			if !ready {
				return fmt.Errorf("Wi-Fi connection timed out; check password, signal and router settings")
			}
			settings, e := a.getSettings(profile)
			if e != nil {
				return e
			}
			s.Profile = profile
			s.ProfileHash = signature(settings)
		}
		s.Status = "pending"
		return s.remember()
	}
	if e = apply(); e != nil {
		if recovery := a.rollbackWifi(s); recovery != nil {
			return nil, fmt.Errorf("Wi-Fi operation interrupted; recovery is required")
		}
		if e = s.disarm(); e != nil {
			return nil, e
		}
		return nil, fmt.Errorf("Wi-Fi operation failed; previous settings were restored")
	}
	return map[string]any{"message": "Network changes await confirmation", "change": public(&s.state)}, nil
}
func (a *adapter) rollbackWifi(s *nmChange) error {
	if s.AdaptersBefore != nil {
		if e := a.restoreRadios(*s.AdaptersBefore); e != nil {
			return e
		}
	} else if e := a.setProperty(nmPath, nm, "WirelessEnabled", s.RadioBefore); e != nil {
		return e
	}
	if s.RadioBefore {
		for i := 0; i < 20; i++ {
			_, p, e := a.wifiDevice(s.Interface)
			if e != nil {
				if missingDevice(e) {
					break
				}
				return e
			}
			if num(p["State"]) >= 30 {
				break
			}
			time.Sleep(500 * time.Millisecond)
		}
	}
	paths, e := a.checkpoints()
	if e != nil {
		return e
	}
	if slices.Contains(paths, s.Checkpoint) {
		if e = a.rollback(s.Checkpoint); e != nil {
			return e
		}
	}
	if s.NewUUID != "" {
		if e = a.deleteProfiles([]string{s.NewUUID}); e != nil {
			return e
		}
	}
	s.Status = "rolled-back"
	s.Error = ""
	return s.remember()
}
func (a *adapter) confirmWifi(s *nmChange) error {
	paths, e := a.checkpoints()
	if e != nil {
		return e
	}
	if !slices.Contains(paths, s.Checkpoint) {
		return fmt.Errorf("This network change has expired or is no longer pending")
	}
	switch s.Kind {
	case "network.wifi.radio":
		r, e := a.adapterRadio(s.Interface)
		if e != nil {
			return e
		}
		if r.Enabled != s.RadioAfter {
			return fmt.Errorf("Network configuration changed externally; roll back and review it again")
		}
	case "network.wifi.connect":
		_, profile, settings, _, _, e := a.active(s.Interface)
		if e != nil {
			return e
		}
		if profile != s.Profile || !s.matchesProfile(settings, s.ProfileHash) {
			return fmt.Errorf("Network configuration changed externally; roll back and review it again")
		}
		if s.NewUUID != "" {
			if e = a.call(profile, nm+".Settings.Connection.Save").Err; e != nil {
				return e
			}
			if _, e = nmCommand("nmcli", "connection", "modify", "uuid", s.NewUUID, "connection.autoconnect", "yes"); e != nil {
				return e
			}
		}
	case "network.wifi.disconnect":
		_, p, e := a.wifiDevice(s.Interface)
		if e != nil {
			return e
		}
		if obj(p["ActiveConnection"]) != "/" {
			return fmt.Errorf("Network configuration changed externally; roll back and review it again")
		}
	default:
		return fmt.Errorf("Unknown network operation")
	}
	if e = a.call(nmPath, nm+".CheckpointDestroy", s.Checkpoint).Err; e != nil {
		return e
	}
	s.Status = "confirmed"
	if e = s.remember(); e != nil {
		return e
	}
	return s.disarm()
}
