package network

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/godbus/dbus/v5"
)

func nmJSONCommand(out any, args ...string) error {
	raw, e := nmCommand(args...)
	if e != nil {
		return e
	}
	return json.Unmarshal(raw, out)
}
func nmParameters(value any) (map[string]any, error) {
	raw, e := json.Marshal(value)
	if e != nil {
		return nil, e
	}
	var p map[string]any
	e = json.Unmarshal(raw, &p)
	return p, e
}
func sharingEffective(action string, p map[string]any, old *nmGroup) (map[string]any, error) {
	if action != "network.share.wifi" {
		return p, nil
	}
	if old == nil {
		return nil, fmt.Errorf("Sharing group no longer exists")
	}
	name, _ := p["interface"].(string)
	if _, ok := old.Wifi[name]; !ok {
		return nil, fmt.Errorf("Select a Wi-Fi access point from this sharing group")
	}
	wifi, ok := p["wifi"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("Invalid network option")
	}
	effective, e := nmParameters(old)
	if e != nil {
		return nil, e
	}
	effective["wifi"].(map[string]any)[name] = wifi
	return effective, nil
}
func withoutNMPort(old *nmGroup, name string) (nmGroup, error) {
	if old == nil || !slices.Contains(old.Outputs, name) {
		return nmGroup{}, fmt.Errorf("Select a recipient interface from this sharing group")
	}
	raw, e := json.Marshal(old)
	if e != nil {
		return nmGroup{}, e
	}
	var g nmGroup
	if e = json.Unmarshal(raw, &g); e != nil {
		return g, e
	}
	g.Outputs = slices.DeleteFunc(g.Outputs, func(s string) bool { return s == name })
	delete(g.Wifi, name)
	delete(g.Profiles, name)
	delete(g.Identities, name)
	delete(g.Previous, name)
	return g, nil
}
func (a *adapter) reviewNMSharing(p map[string]any, old *nmGroup) (nmGroup, []any, error) {
	conf := nmGroup{Wifi: map[string]nmAP{}, Identities: map[string]string{}}
	fail := func(message string) (nmGroup, []any, error) { return conf, nil, fmt.Errorf("%s", message) }
	conf.Source, _ = p["source"].(string)
	outputs, ok := p["outputs"].([]any)
	if !ok || len(outputs) < 1 || len(outputs) > 16 {
		return fail("Select at least one destination interface")
	}
	for _, v := range outputs {
		name, ok := v.(string)
		if !ok {
			return fail("Select at least one destination interface")
		}
		if name == conf.Source || slices.Contains(conf.Outputs, name) {
			return fail("Source and destination interfaces must be different")
		}
		conf.Outputs = append(conf.Outputs, name)
	}
	groups, e := loadNMGroups()
	if e != nil {
		return conf, nil, e
	}
	names := nmGroupNames(conf)
	for _, g := range groups {
		if old != nil && g.ID == old.ID {
			continue
		}
		for _, name := range nmGroupNames(g) {
			if slices.Contains(names, name) {
				return fail("An interface is already used by another sharing group")
			}
		}
	}
	conf.Mode, _ = p["mode"].(string)
	if conf.Mode != "bridge" && conf.Mode != "nat" {
		return fail("Invalid sharing mode")
	}
	wifi := map[string]any{}
	if v, exists := p["wifi"]; exists {
		wifi, ok = v.(map[string]any)
		if !ok {
			return fail("Invalid network option")
		}
	}
	radios := []string{}
	snapshot := []any{}
	var sourceProps map[string]dbus.Variant
	saved, e := a.profiles()
	if e != nil {
		return conf, nil, e
	}
	for _, name := range names {
		if accessInterface(name) {
			return fail("Manage this connection in Network access settings")
		}
		if !validName.MatchString(name) || systemInterface(name) {
			return fail("System interfaces cannot be used for connection sharing")
		}
		path, props, e := a.device(name)
		if e != nil {
			return conf, nil, e
		}
		cap, e := a.nmCapabilities(name, props)
		if e != nil {
			return conf, nil, e
		}
		if (num(props["DeviceType"]) != 1 && num(props["DeviceType"]) != 2) || !cap.Available {
			return fail("Select a managed Ethernet or Wi-Fi interface")
		}
		if cap.PHY != "" {
			if slices.Contains(radios, cap.PHY) {
				return fail("These interfaces share one radio; choose a separate Wi-Fi adapter")
			}
			radios = append(radios, cap.PHY)
		}
		if old != nil {
			if _, ok := old.Identities[name]; ok {
				matches, e := a.matchesNMAdapter(*old, name, saved)
				if e != nil {
					return conf, nil, e
				}
				if !matches {
					return fail("A network adapter was replaced; recreate the sharing group")
				}
			}
		}
		var activeHash any
		if active := obj(props["ActiveConnection"]); active != "/" && active != "" {
			activeProps, e := a.props(active, nm+".Connection.Active")
			if e != nil {
				return conf, nil, e
			}
			settings, e := a.getSettings(obj(activeProps["Connection"]))
			if e != nil {
				return conf, nil, e
			}
			activeHash = signature(settings)
		}
		snapshot = append(snapshot, []any{name, cap, obj(props["ActiveConnection"]), activeHash})
		conf.Identities[name] = cap.Identity
		if name == conf.Source {
			sourceProps = props
			continue
		}
		if num(props["DeviceType"]) != 2 {
			continue
		}
		if !cap.AP || len(cap.Bands) == 0 {
			return fail("This Wi-Fi adapter cannot create an access point on permitted channels")
		}
		radio, e := a.adapterRadio(name)
		if e != nil {
			return conf, nil, e
		}
		if !radio.HardwareEnabled {
			return fail("Wi-Fi is blocked by a hardware switch")
		}
		ap := map[string]any{}
		if v, exists := wifi[name]; exists {
			ap, ok = v.(map[string]any)
			if !ok {
				return fail("Invalid network option")
			}
		}
		ssid, ok := ap["ssid"].(string)
		if !ok || !utf8.ValidString(ssid) || len(ssid) < 1 || len(ssid) > 32 || strings.IndexByte(ssid, 0) >= 0 {
			return fail("Wi-Fi name must contain 1 to 32 bytes")
		}
		password := ""
		if v, exists := ap["password"]; exists {
			password, ok = v.(string)
			if !ok {
				return fail("Use a Wi-Fi password of 8 to 63 printable ASCII characters")
			}
		}
		kept := false
		if old != nil {
			_, kept = old.Wifi[name]
			kept = kept && password == ""
		}
		if !kept {
			if len(password) < 8 || len(password) > 63 {
				return fail("Use a Wi-Fi password of 8 to 63 printable ASCII characters")
			}
			for _, c := range password {
				if c < 32 || c > 126 {
					return fail("Use a Wi-Fi password of 8 to 63 printable ASCII characters")
				}
			}
		}
		band := "bg"
		if v, exists := ap["band"]; exists {
			band, _ = v.(string)
		}
		if !slices.Contains(cap.Bands, band) {
			return fail("This Wi-Fi band is not available for an access point")
		}
		channel := 0
		if v, exists := ap["channel"]; exists {
			n, ok := v.(float64)
			if !ok || n != float64(int(n)) {
				return fail("This Wi-Fi channel is not available for an access point")
			}
			channel = int(n)
		}
		channels := cap.Channels[band]
		if len(channels) == 0 || (channel != 0 && !slices.Contains(channels, channel)) {
			return fail("This Wi-Fi channel is not available for an access point")
		}
		if channel == 0 {
			channel = channels[0]
		}
		conf.Wifi[name] = nmAP{ssid, band, channel}
		_ = path
	}
	if conf.Mode == "bridge" && num(sourceProps["DeviceType"]) != 1 {
		return fail("Transparent Wi-Fi bridging is not verified with your router; use a separate network")
	}
	if (old == nil || !old.Enabled) && num(sourceProps["State"]) != 100 {
		return fail("Connect the source interface before sharing")
	}
	if conf.Mode == "nat" {
		if old != nil && old.Subnet != "" {
			subnet, e := netip.ParsePrefix(old.Subnet)
			if e != nil {
				return conf, nil, e
			}
			var routes []struct {
				Dst string `json:"dst"`
				Dev string `json:"dev"`
			}
			if e = nmJSONCommand(&routes, "ip", "-j", "-4", "route", "show", "table", "all"); e != nil {
				return conf, nil, e
			}
			for _, r := range routes {
				if r.Dst == "" || r.Dst == "default" || r.Dev == old.Bridge {
					continue
				}
				prefix, e := netip.ParsePrefix(r.Dst)
				if e != nil {
					return conf, nil, e
				}
				if subnet.Overlaps(prefix) {
					return fail("The sharing subnet now overlaps another network; recreate the sharing group")
				}
			}
		}
		var rules []struct {
			Priority int `json:"priority"`
		}
		if e = nmJSONCommand(&rules, "ip", "-j", "-4", "rule", "show"); e != nil {
			return conf, nil, e
		}
		for _, r := range rules {
			if r.Priority > 0 && r.Priority < 18000 {
				return fail("Existing policy routing requires manual review before sharing")
			}
		}
	}
	if conf.Mode == "bridge" && (old == nil || old.Mode != "bridge" || !old.Enabled) {
		_, _, s, _, _, e := a.active(conf.Source)
		if e != nil {
			return conf, nil, e
		}
		if !editable(s) {
			return fail("Source uses advanced or unsaved settings; save a simple IP configuration first")
		}
		if _, ok := s["802-1x"]; ok {
			return fail("Authenticated Ethernet bridging requires manual configuration")
		}
		if str(s["connection"]["master"]) != "" || str(s["connection"]["controller"]) != "" {
			return fail("Source already belongs to a bridge or bond")
		}
	}
	conf.Autostart, ok = p["autostart"].(bool)
	if !ok {
		return fail("Invalid network option")
	}
	conf.Name, ok = p["name"].(string)
	if !ok {
		return fail("Invalid sharing name")
	}
	for _, c := range conf.Name {
		if c < 32 {
			return fail("Invalid sharing name")
		}
	}
	conf.Name = strings.TrimSpace(conf.Name)
	if len([]rune(conf.Name)) < 1 || len([]rune(conf.Name)) > 64 {
		return fail("Invalid sharing name")
	}
	for _, c := range conf.Name {
		if c < 32 {
			return fail("Invalid sharing name")
		}
	}
	if !nmToolsReady() {
		return fail("Install the network sharing dependencies first")
	}
	return conf, snapshot, nil
}
func (a *adapter) sharingPlan(action, user string, p map[string]any) (any, error) {
	s, e := readState()
	if e != nil {
		return nil, e
	}
	if active(s) {
		return nil, fmt.Errorf("Confirm or roll back the pending network change first")
	}
	groups, e := loadNMGroups()
	if e != nil {
		return nil, e
	}
	id, _ := p["id"].(string)
	old := nmGroupByID(groups, id)
	if id != "" && old == nil {
		return nil, fmt.Errorf("Sharing group no longer exists")
	}
	var target string
	var snapshot any
	if action == "network.share.save" || action == "network.share.wifi" {
		effective, e := sharingEffective(action, p, old)
		if e != nil {
			return nil, e
		}
		conf, state, e := a.reviewNMSharing(effective, old)
		if e != nil {
			return nil, e
		}
		target = conf.Source
		snapshot = state
	} else {
		if old == nil {
			return nil, fmt.Errorf("Sharing group no longer exists")
		}
		switch action {
		case "network.share.start":
			if old.Enabled {
				return nil, fmt.Errorf("Sharing is already enabled")
			}
			params, e := nmParameters(old)
			if e != nil {
				return nil, e
			}
			if _, _, e = a.reviewNMSharing(params, old); e != nil {
				return nil, e
			}
		case "network.share.stop":
			if !old.Enabled {
				return nil, fmt.Errorf("Sharing is already stopped")
			}
		case "network.share.remove-port":
			name, _ := p["interface"].(string)
			if _, e = withoutNMPort(old, name); e != nil {
				return nil, e
			}
		case "network.share.delete":
		default:
			return nil, fmt.Errorf("Unknown network operation")
		}
		target = old.Source
		snapshot = old
	}
	return map[string]any{"target": target, "confirmation": target, "details": []string{target}, "fingerprint": digest([]any{action, publicNetworkParams(p), snapshot})}, nil
}
