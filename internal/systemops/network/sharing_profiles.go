package network

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/godbus/dbus/v5"
	"panasms.local/backend/internal/systemops"
)

func (a *adapter) newNMProfile(fields settings, s *nmChange, role string) error {
	id, e := randomUUID()
	if e != nil {
		return e
	}
	fields["connection"]["uuid"] = dbus.MakeVariant(id)
	fields["connection"]["autoconnect"] = dbus.MakeVariant(false)
	s.NewUUIDs = append(s.NewUUIDs, id)
	if e = s.remember(); e != nil {
		return e
	}
	var path dbus.ObjectPath
	if e = a.call(nmPath+"/Settings", nm+".Settings.AddConnectionUnsaved", fields).Store(&path); e != nil {
		return e
	}
	s.NewProfiles[role] = id
	return s.remember()
}
func chooseNMSubnet(groups []nmGroup) (string, error) {
	var routes []struct {
		Dst string `json:"dst"`
	}
	if e := nmJSONCommand(&routes, "ip", "-j", "-4", "route", "show", "table", "all"); e != nil {
		return "", e
	}
	used := []netip.Prefix{}
	for _, r := range routes {
		if r.Dst == "" || r.Dst == "default" {
			continue
		}
		p, e := nmRoutePrefix(r.Dst)
		if e != nil {
			return "", e
		}
		used = append(used, p)
	}
	for _, g := range groups {
		if g.Subnet != "" {
			p, e := netip.ParsePrefix(g.Subnet)
			if e != nil {
				return "", e
			}
			used = append(used, p)
		}
	}
	for i := 42; i < 250; i++ {
		p := netip.MustParsePrefix(fmt.Sprintf("10.%d.0.0/24", i))
		overlaps := false
		for _, v := range used {
			overlaps = overlaps || p.Overlaps(v)
		}
		if !overlaps {
			return p.String(), nil
		}
	}
	return "", fmt.Errorf("No free private subnet found for sharing")
}
func freeNMSlot(groups []nmGroup) (int, error) {
	var rules []map[string]any
	if e := nmJSONCommand(&rules, "ip", "-j", "-4", "rule", "show"); e != nil {
		return 0, e
	}
	for i := 0; i < 100; i++ {
		used := false
		for _, g := range groups {
			used = used || g.Slot == i
		}
		for _, r := range rules {
			used = used || stateNumber(r["priority"]) == int64(18000+i)
		}
		if used {
			continue
		}
		raw, e := nmSystemCommand(context.Background(), []string{"ip", "-j", "-4", "route", "show", "table", strconv.Itoa(28000 + i)}, systemops.CommandOptions{Accepted: []int{0, 2}})
		if e != nil {
			return 0, e
		}
		var routes []any
		if len(strings.TrimSpace(string(raw))) > 0 {
			if e = json.Unmarshal(raw, &routes); e != nil {
				return 0, e
			}
		}
		if len(routes) == 0 {
			return i, nil
		}
	}
	return 0, fmt.Errorf("No free routing table available for sharing")
}
func cloneNMFields(fields map[string]dbus.Variant) map[string]dbus.Variant {
	result := map[string]dbus.Variant{}
	for k, v := range fields {
		result[k] = v
	}
	return result
}
func (a *adapter) buildNMGroup(conf nmGroup, p map[string]any, old *nmGroup, s *nmChange) (nmGroup, error) {
	g := conf
	groups, e := loadNMGroups()
	if e != nil {
		return g, e
	}
	g.Slot, e = freeNMSlot(groups)
	if e != nil {
		return g, e
	}
	id, e := randomID()
	if e != nil {
		return g, e
	}
	g.ID = id[:12]
	if old != nil {
		g.ID = old.ID
	}
	bridge, e := randomID()
	if e != nil {
		return g, e
	}
	g.Bridge = "osbr" + bridge[:8]
	g.Enabled = true
	g.Previous, e = a.originalNM(nmGroupNames(conf))
	if e != nil {
		return g, e
	}
	if old != nil {
		for name, id := range old.Previous {
			if slices.Contains(nmGroupNames(g), name) {
				g.Previous[name] = id
			}
		}
	}
	fields := settings{
		"connection": {"id": dbus.MakeVariant("PaNasMs " + g.Name), "type": dbus.MakeVariant("bridge"), "interface-name": dbus.MakeVariant(g.Bridge)},
		"bridge":     {"stp": dbus.MakeVariant(true)}, "ipv4": {"method": dbus.MakeVariant("shared")}, "ipv6": {"method": dbus.MakeVariant("disabled")},
	}
	if g.Mode == "bridge" {
		saved, e := a.profiles()
		if e != nil {
			return g, e
		}
		prior := g.Previous[g.Source]
		if prior == nil {
			return g, fmt.Errorf("Source uses advanced or unsaved settings; save a simple IP configuration first")
		}
		profile, ok := saved[*prior]
		if !ok {
			return g, fmt.Errorf("Sharing configuration changed externally; review it again")
		}
		for _, key := range []string{"ipv4", "ipv6"} {
			if value, ok := profile.Settings[key]; ok {
				fields[key] = cloneNMFields(value)
			} else {
				fields[key] = map[string]dbus.Variant{"method": dbus.MakeVariant("auto")}
			}
		}
		_, props, e := a.device(g.Source)
		if e != nil {
			return g, e
		}
		mac, e := hex.DecodeString(strings.ReplaceAll(str(props["HwAddress"]), ":", ""))
		if e != nil || len(mac) != 6 {
			return g, fmt.Errorf("Source has no valid hardware address")
		}
		fields["bridge"]["mac-address"] = dbus.MakeVariant(mac)
	} else {
		if old != nil && old.Subnet != "" {
			g.Subnet = old.Subnet
		} else {
			g.Subnet, e = chooseNMSubnet(groups)
			if e != nil {
				return g, e
			}
		}
		subnet, e := netip.ParsePrefix(g.Subnet)
		if e != nil {
			return g, e
		}
		fields["ipv4"]["address-data"] = dbus.MakeVariant([]map[string]dbus.Variant{{"address": dbus.MakeVariant(subnet.Masked().Addr().Next().String()), "prefix": dbus.MakeVariant(uint32(subnet.Bits()))}})
	}
	if e = a.newNMProfile(fields, s, "bridge"); e != nil {
		return g, e
	}
	for _, name := range nmPortNames(g) {
		_, props, e := a.device(name)
		if e != nil {
			return g, e
		}
		kind := "802-3-ethernet"
		if num(props["DeviceType"]) == 2 {
			kind = "802-11-wireless"
		}
		fields = settings{"connection": {"id": dbus.MakeVariant("PaNasMs " + g.Name + " " + name), "type": dbus.MakeVariant(kind), "interface-name": dbus.MakeVariant(name), "master": dbus.MakeVariant(g.Bridge), "slave-type": dbus.MakeVariant("bridge")}, kind: {}}
		mac := strings.ToLower(str(props["HwAddress"]))
		if macPattern.MatchString(mac) {
			raw, _ := hex.DecodeString(strings.ReplaceAll(mac, ":", ""))
			fields[kind]["mac-address"] = dbus.MakeVariant(raw)
		}
		if kind == "802-11-wireless" {
			ap := g.Wifi[name]
			fields[kind]["ssid"] = dbus.MakeVariant([]byte(ap.SSID))
			fields[kind]["mode"] = dbus.MakeVariant("ap")
			fields[kind]["band"] = dbus.MakeVariant(ap.Band)
			fields[kind]["channel"] = dbus.MakeVariant(uint32(ap.Channel))
			wifi, _ := p["wifi"].(map[string]any)
			conf, _ := wifi[name].(map[string]any)
			password, _ := conf["password"].(string)
			if password == "" {
				if old == nil {
					return g, fmt.Errorf("Use a Wi-Fi password of 8 to 63 printable ASCII characters")
				}
				saved, e := a.profiles()
				if e != nil {
					return g, e
				}
				prior, ok := saved[old.Profiles[name]]
				if !ok {
					return g, fmt.Errorf("Sharing configuration changed externally; review it again")
				}
				var secrets settings
				if e = a.call(prior.Path, nm+".Settings.Connection.GetSecrets", "802-11-wireless-security").Store(&secrets); e != nil {
					return g, e
				}
				password = str(secrets["802-11-wireless-security"]["psk"])
				if password == "" {
					return g, fmt.Errorf("Saved access point password is unavailable")
				}
			}
			fields["802-11-wireless-security"] = map[string]dbus.Variant{"key-mgmt": dbus.MakeVariant("wpa-psk"), "proto": dbus.MakeVariant([]string{"rsn"}), "psk": dbus.MakeVariant(password), "psk-flags": dbus.MakeVariant(uint32(0))}
		}
		if e = a.newNMProfile(fields, s, name); e != nil {
			return g, e
		}
	}
	g.Profiles = map[string]string{}
	for role, id := range s.NewProfiles {
		g.Profiles[role] = id
	}
	return g, nil
}

func nmRoutePrefix(destination string) (netip.Prefix, error) {
	if !strings.Contains(destination, "/") {
		address, e := netip.ParseAddr(destination)
		if e != nil {
			return netip.Prefix{}, e
		}
		return netip.PrefixFrom(address, address.BitLen()), nil
	}
	return netip.ParsePrefix(destination)
}
