package network

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/godbus/dbus/v5"
	"panasms.local/backend/internal/systemops"
)

func (a *adapter) originalNM(names []string) (map[string]*string, error) {
	result := map[string]*string{}
	for _, name := range names {
		_, p, e := a.device(name)
		if e != nil {
			if missingDevice(e) {
				result[name] = nil
				continue
			}
			return nil, e
		}
		active := obj(p["ActiveConnection"])
		if active != "" && active != "/" {
			props, e := a.props(active, nm+".Connection.Active")
			if e != nil {
				return nil, e
			}
			id := str(props["Uuid"])
			result[name] = &id
		} else {
			result[name] = nil
		}
	}
	return result, nil
}
func (a *adapter) restoreNM(previous map[string]*string) error {
	saved, e := a.profiles()
	if e != nil {
		return e
	}
	for name, id := range previous {
		path, p, e := a.device(name)
		if e != nil {
			if missingDevice(e) {
				continue
			}
			return e
		}
		if num(p["DeviceType"]) == 2 {
			disabled, e := a.wifiDisabled(name)
			if e != nil {
				return e
			}
			if disabled {
				continue
			}
		}
		active := obj(p["ActiveConnection"])
		profile, exists := nmProfile{}, false
		if id != nil {
			profile, exists = saved[*id]
		}
		if exists {
			if active != "" && active != "/" {
				props, e := a.props(active, nm+".Connection.Active")
				if e != nil {
					return e
				}
				if str(props["Uuid"]) == *id && num(p["State"]) == 100 {
					continue
				}
			}
			var connection dbus.ObjectPath
			if e = a.call(nmPath, nm+".ActivateConnection", profile.Path, path, dbus.ObjectPath("/")).Store(&connection); e != nil {
				return e
			}
			for i := 0; i < 30; i++ {
				props, e := a.props(connection, nm+".Connection.Active")
				if e != nil {
					return e
				}
				if num(props["State"]) == 2 || num(props["State"]) == 4 {
					break
				}
				time.Sleep(500 * time.Millisecond)
			}
		} else if active != "" && active != "/" {
			if e = a.call(path, nm+".Device.Disconnect").Err; e != nil {
				return e
			}
		}
	}
	return nil
}
func (a *adapter) activateNMGroup(g nmGroup, allowMissing bool) error {
	for _, name := range nmGroupNames(g) {
		if accessInterface(name) {
			return fmt.Errorf("Manage this connection in Network access settings")
		}
		if systemInterface(name) {
			return fmt.Errorf("System interfaces cannot be used for connection sharing")
		}
	}
	saved, e := a.profiles()
	if e != nil {
		return e
	}
	if e = nmRouting(g); e != nil {
		return e
	}
	props, e := a.props(nmPath, nm)
	if e != nil {
		return e
	}
	paths, e := objectPaths(props["ActiveConnections"])
	if e != nil {
		return e
	}
	activeIDs := map[string]bool{}
	for _, p := range paths {
		props, e := a.props(p, nm+".Connection.Active")
		if e != nil {
			return e
		}
		activeIDs[str(props["Uuid"])] = true
	}
	bridge, ok := saved[g.Profiles["bridge"]]
	if !ok {
		return fmt.Errorf("Sharing configuration changed externally; review it again")
	}
	if !activeIDs[g.Profiles["bridge"]] {
		if e = a.call(nmPath, nm+".ActivateConnection", bridge.Path, dbus.ObjectPath("/"), dbus.ObjectPath("/")).Err; e != nil {
			return e
		}
	}
	for _, name := range nmPortNames(g) {
		path, p, e := a.device(name)
		if e != nil {
			if allowMissing && missingDevice(e) {
				continue
			}
			return e
		}
		matches, e := a.matchesNMAdapter(g, name, saved)
		if e != nil {
			return e
		}
		if !matches {
			return fmt.Errorf("A network adapter was replaced; recreate the sharing group")
		}
		if num(p["DeviceType"]) == 2 {
			r, e := a.adapterRadio(name)
			if e != nil {
				return e
			}
			if !r.Enabled || !r.HardwareEnabled {
				continue
			}
		}
		if !boolean(p["Managed"]) {
			continue
		}
		profile, ok := saved[g.Profiles[name]]
		if !ok {
			return fmt.Errorf("Sharing configuration changed externally; review it again")
		}
		if !activeIDs[g.Profiles[name]] {
			if e = a.call(nmPath, nm+".ActivateConnection", profile.Path, path, dbus.ObjectPath("/")).Err; e != nil {
				return e
			}
		}
	}
	return nil
}
func (a *adapter) deactivateNMGroup(g nmGroup) error {
	props, e := a.props(nmPath, nm)
	if e != nil {
		return e
	}
	paths, e := objectPaths(props["ActiveConnections"])
	if e != nil {
		return e
	}
	ids := map[string]bool{}
	for _, id := range g.Profiles {
		ids[id] = true
	}
	for _, path := range paths {
		p, e := a.props(path, nm+".Connection.Active")
		if e != nil {
			return e
		}
		if ids[str(p["Uuid"])] {
			if e = a.call(nmPath, nm+".DeactivateConnection", path).Err; e != nil {
				return e
			}
		}
	}
	if e = a.restoreNM(g.Previous); e != nil {
		return e
	}
	return cleanupNMRouting(g)
}
func (a *adapter) detachNMPort(g nmGroup, name string) error {
	path, p, e := a.device(name)
	if e != nil {
		if missingDevice(e) {
			return nil
		}
		return e
	}
	profiles, e := a.profiles()
	if e != nil {
		return e
	}
	matches, e := a.matchesNMAdapter(g, name, profiles)
	if e != nil {
		return e
	}
	if !matches {
		return fmt.Errorf("A network adapter was replaced; recreate the sharing group")
	}
	if active := obj(p["ActiveConnection"]); active != "/" && active != "" {
		props, e := a.props(active, nm+".Connection.Active")
		if e != nil {
			return e
		}
		id := str(props["Uuid"])
		previous := ""
		if g.Previous[name] != nil {
			previous = *g.Previous[name]
		}
		if id != g.Profiles[name] && id != previous {
			return fmt.Errorf("Sharing configuration changed externally; roll back and review it again")
		}
		if id == g.Profiles[name] {
			if e = a.call(path, nm+".Device.Disconnect").Err; e != nil {
				return e
			}
		}
	}
	if _, wifi := g.Wifi[name]; wifi {
		if _, e = nmCommand("ip", "link", "set", "dev", name, "down"); e != nil {
			return e
		}
		if _, e = nmCommand("iw", "dev", name, "set", "type", "managed"); e != nil {
			return e
		}
		disabled, e := a.wifiDisabled(name)
		if e != nil {
			return e
		}
		if !disabled {
			if _, e = nmCommand("ip", "link", "set", "dev", name, "up"); e != nil {
				return e
			}
		}
	}
	return a.restoreNM(map[string]*string{name: g.Previous[name]})
}
func nmRouting(g nmGroup) error {
	if g.Mode != "nat" {
		return nil
	}
	table, priority := strconv.Itoa(28000+g.Slot), strconv.Itoa(18000+g.Slot)
	var rules []map[string]any
	if e := nmJSONCommand(&rules, "ip", "-j", "-4", "rule", "show"); e != nil {
		return e
	}
	found := false
	for _, r := range rules {
		if stateNumber(r["priority"]) == int64(18000+g.Slot) {
			if fmt.Sprint(r["table"]) != table || r["iif"] != g.Bridge {
				return fmt.Errorf("Routing rule conflicts with sharing")
			}
			found = true
		}
	}
	if _, e := nmCommand("ip", "-4", "route", "replace", "unreachable", "default", "metric", "42760", "table", table); e != nil {
		return e
	}
	if !found {
		if _, e := nmCommand("ip", "-4", "rule", "add", "priority", priority, "iif", g.Bridge, "lookup", table); e != nil {
			return e
		}
	}
	var all, current []map[string]any
	if e := nmJSONCommand(&all, "ip", "-j", "-4", "route", "show", "table", "main"); e != nil {
		return e
	}
	if e := nmJSONCommand(&current, "ip", "-j", "-4", "route", "show", "table", table); e != nil {
		return e
	}
	source := []map[string]any{}
	for _, r := range all {
		if r["dev"] == g.Source && (r["type"] == nil || r["type"] == "unicast") {
			source = append(source, r)
		}
	}
	for _, r := range current {
		if r["type"] == "unreachable" {
			continue
		}
		matches := false
		for _, s := range source {
			if routeDst(r) == routeDst(s) && r["gateway"] == s["gateway"] && r["dev"] == g.Source {
				matches = true
				break
			}
		}
		if !matches {
			if _, e := nmCommand("ip", "-4", "route", "del", routeDst(r), "table", table); e != nil {
				return e
			}
		}
	}
	slices.SortStableFunc(source, func(a, b map[string]any) int {
		if (a["gateway"] == nil) != (b["gateway"] == nil) {
			if a["gateway"] == nil {
				return -1
			}
			return 1
		}
		return 0
	})
	for _, r := range source {
		args := []string{"ip", "-4", "route", "replace", routeDst(r)}
		if gateway, ok := r["gateway"].(string); ok && gateway != "" {
			args = append(args, "via", gateway)
		}
		args = append(args, "dev", g.Source, "metric", strconv.FormatInt(stateNumber(r["metric"]), 10))
		if src, ok := r["prefsrc"].(string); ok && src != "" {
			args = append(args, "src", src)
		}
		if _, e := nmCommand(append(args, "table", table)...); e != nil {
			return e
		}
	}
	return nil
}
func routeDst(r map[string]any) string {
	s, _ := r["dst"].(string)
	if s == "" {
		return "default"
	}
	return s
}
func cleanupNMRouting(g nmGroup) error {
	if g.Mode != "nat" {
		return nil
	}
	table, priority := strconv.Itoa(28000+g.Slot), strconv.Itoa(18000+g.Slot)
	var rules []map[string]any
	if e := nmJSONCommand(&rules, "ip", "-j", "-4", "rule", "show"); e != nil {
		return e
	}
	for _, r := range rules {
		if stateNumber(r["priority"]) == int64(18000+g.Slot) && fmt.Sprint(r["table"]) == table && r["iif"] == g.Bridge {
			if _, e := nmCommand("ip", "-4", "rule", "del", "priority", priority, "iif", g.Bridge, "lookup", table); e != nil {
				return e
			}
		}
	}
	_, e := nmSystemCommand(context.Background(), []string{"ip", "-4", "route", "flush", "table", table}, systemops.CommandOptions{Accepted: []int{0, 2}})
	return e
}
func (a *adapter) waitNMGroup(g nmGroup, deadline time.Time) error {
	start := time.Now()
	for {
		states := map[string]int64{}
		for _, name := range append([]string{g.Bridge}, g.Outputs...) {
			_, p, e := a.device(name)
			if e != nil {
				return e
			}
			states[name] = num(p["State"])
		}
		failed, pending := []string{}, []string{}
		for name, status := range states {
			_, wifi := g.Wifi[name]
			if status == 120 || (wifi && status <= 30 && time.Since(start) >= 5*time.Second) {
				failed = append(failed, name)
			}
			if wifi && status != 100 {
				pending = append(pending, name)
			}
		}
		slices.Sort(failed)
		slices.Sort(pending)
		if len(failed) > 0 {
			return fmt.Errorf("Sharing activation failed for %s; previous settings will be restored", strings.Join(failed, ", "))
		}
		if states[g.Bridge] == 100 && len(pending) == 0 {
			return nil
		}
		if !time.Now().Before(deadline) {
			if len(pending) > 0 {
				return fmt.Errorf("Sharing activation timed out while starting Wi-Fi access points %s; previous settings will be restored", strings.Join(pending, ", "))
			}
			return fmt.Errorf("Sharing activation timed out while waiting for bridge %s to obtain network settings; previous settings will be restored", g.Bridge)
		}
		time.Sleep(500 * time.Millisecond)
	}
}
