package network

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/godbus/dbus/v5"
	"panasms.local/backend/internal/systemops/networknative"
)

type nmCapabilities struct {
	Identity   string           `json:"identity"`
	PHY        string           `json:"phy"`
	AP         bool             `json:"ap"`
	Bands      []string         `json:"bands"`
	Concurrent bool             `json:"concurrent"`
	Channels   map[string][]int `json:"channels"`
	Available  bool             `json:"available"`
}

func physicalNM(name string) (nmCapabilities, error) {
	c := nmCapabilities{Bands: []string{}, Channels: map[string][]int{}}
	if !validName.MatchString(name) {
		return c, fmt.Errorf("Invalid network interface")
	}
	c.Identity = name
	device := filepath.Join(netClassRoot, name, "device")
	if _, e := os.Stat(device); e == nil {
		p, e := filepath.EvalSymlinks(device)
		if e != nil {
			return c, e
		}
		c.Identity = p
	} else if !os.IsNotExist(e) {
		return c, e
	}
	phy := filepath.Join(netClassRoot, name, "phy80211")
	if _, e := os.Stat(phy); e == nil {
		p, e := filepath.EvalSymlinks(phy)
		if e != nil {
			return c, e
		}
		c.PHY = filepath.Base(p)
	} else if !os.IsNotExist(e) {
		return c, e
	}
	return c, nil
}
func (a *adapter) nmCapabilities(name string, p map[string]dbus.Variant) (nmCapabilities, error) {
	c, e := physicalNM(name)
	if e != nil {
		return c, e
	}
	c.Available = boolean(p["Managed"])
	if num(p["DeviceType"]) != 2 {
		return c, nil
	}
	disabled, e := a.wifiDisabled(name)
	if e != nil {
		return c, e
	}
	c.Available = c.Available || disabled
	path, _, e := a.device(name)
	if e != nil {
		return c, e
	}
	w, e := a.props(path, nm+".Device.Wireless")
	if e != nil {
		return c, e
	}
	c.AP = num(w["WirelessCapabilities"])&0x40 != 0
	if c.PHY != "" {
		if _, e := exec.LookPath("iw"); e != nil {
			return c, nil
		}
		raw, e := nmCommand("iw", "phy", c.PHY, "info")
		if e != nil {
			return c, e
		}
		c.Channels = networknative.Channels(string(raw))
		for _, band := range []string{"bg", "a"} {
			if len(c.Channels[band]) > 0 {
				c.Bands = append(c.Bands, band)
			}
		}
		sections := strings.Split(string(raw), "valid interface combinations:")
		combos := strings.Split(sections[len(sections)-1], "Device supports")[0]
		for _, block := range strings.Split(combos, "*") {
			if strings.Contains(block, "managed") && regexp.MustCompile(`\bAP\b`).MatchString(block) {
				c.Concurrent = true
			}
		}
	}
	return c, nil
}

var nmToolsReady = networkToolsReady

func networkToolsReady() bool {
	for _, tool := range []string{"iw", "dnsmasq", "ip", "nft"} {
		if _, e := exec.LookPath(tool); e != nil {
			return false
		}
	}
	return true
}
func (a *adapter) sharingInventory(rows []map[string]any) (map[string]any, error) {
	groups, e := readNMGroups()
	if e != nil {
		return nil, e
	}
	used := map[string]string{}
	for _, g := range groups {
		for _, name := range append([]string{g.Source}, g.Outputs...) {
			used[name] = g.ID
		}
	}
	byName := map[string]map[string]any{}
	for _, row := range rows {
		name, _ := row["name"].(string)
		byName[name] = row
		row["sharingGroup"] = nil
		if id, ok := used[name]; ok {
			row["sharingGroup"] = id
		}
		if a == nil || row["system"] == true || row["accessManaged"] == true || (row["kind"] != "ethernet" && row["kind"] != "wifi") {
			continue
		}
		_, props, e := a.device(name)
		if e == nil {
			c, err := a.nmCapabilities(name, props)
			e = err
			if e == nil {
				row["sharing"] = c
				continue
			}
		}
		row["sharing"] = map[string]any{"available": false, "ap": false, "bands": []string{}}
	}
	visible := []map[string]any{}
	for _, g := range groups {
		bridge, source := byName[g.Bridge], byName[g.Source]
		active := g.Enabled && stateNumber(bridge["nmState"]) == 100
		ready := stateNumber(source["nmState"]) == 100
		if g.Mode == "bridge" {
			ready = ready && source["carrier"] != false
		} else {
			ipv4 := false
			addresses, _ := source["addresses"].([]string)
			for _, address := range addresses {
				ipv4 = ipv4 || strings.Contains(address, ".")
			}
			ready = ready && ipv4
		}
		failed := false
		for _, name := range g.Outputs {
			r, ok := byName[name]
			_, wifi := g.Wifi[name]
			failed = failed || !ok || stateNumber(r["nmState"]) == 120 || (wifi && stateNumber(r["nmState"]) != 100)
		}
		status := "error"
		switch {
		case !g.Enabled:
			status = "stopped"
		case failed:
		case active && ready:
			status = "active"
		case active:
			status = "upstream"
		}
		addresses := bridge["addresses"]
		if addresses == nil {
			addresses = []string{}
		}
		visible = append(visible, map[string]any{"id": g.ID, "name": g.Name, "source": g.Source, "outputs": g.Outputs, "mode": g.Mode, "wifi": g.Wifi, "enabled": g.Enabled, "autostart": g.Autostart, "bridge": g.Bridge, "status": status, "addresses": addresses})
	}
	return map[string]any{"groups": visible, "ready": nmToolsReady()}, nil
}
func stateNumber(v any) int64 {
	switch n := v.(type) {
	case int64:
		return n
	case int:
		return int64(n)
	case float64:
		return int64(n)
	default:
		return 0
	}
}
func (a *adapter) matchesNMAdapter(g nmGroup, name string, saved map[string]nmProfile) (bool, error) {
	if p, ok := saved[g.Profiles[name]]; ok {
		kind := str(p.Settings["connection"]["type"])
		if bound := bytesValue(p.Settings[kind]["mac-address"]); len(bound) > 0 {
			path, props, e := a.device(name)
			if e != nil {
				return false, e
			}
			mac := str(props["HwAddress"])
			if num(props["DeviceType"]) == 2 {
				w, e := a.props(path, nm+".Device.Wireless")
				if e != nil {
					return false, e
				}
				mac = str(w["PermHwAddress"])
			}
			return strings.EqualFold(fmt.Sprintf("%x", bound), strings.ReplaceAll(mac, ":", "")), nil
		}
	}
	c, e := physicalNM(name)
	return c.Identity == g.Identities[name], e
}
func nmGroupByID(groups []nmGroup, id string) *nmGroup {
	for i := range groups {
		if groups[i].ID == id {
			return &groups[i]
		}
	}
	return nil
}
func nmGroupNames(g nmGroup) []string { return append([]string{g.Source}, g.Outputs...) }
func nmPortNames(g nmGroup) []string {
	if g.Mode == "bridge" {
		return nmGroupNames(g)
	}
	return slices.Clone(g.Outputs)
}
