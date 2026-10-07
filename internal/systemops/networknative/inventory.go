package networknative

import (
	"fmt"
	"slices"
)

func Inventory(rows []map[string]any) (map[string]any, error) {
	present, enabled, hardware := false, false, false
	for _, row := range rows {
		name, _ := row["name"].(string)
		if row["system"] != true && row["accessManaged"] != true {
			cap := Capability(name)
			row["sharing"] = cap
		}
		if !Wireless(name) {
			continue
		}
		present = true
		w, e := Wifi(name)
		if e != nil {
			return nil, fmt.Errorf("Wi-Fi inventory for %s: %w", name, e)
		}
		enabled = enabled || w.Enabled
		hardware = hardware || w.HardwareEnabled
		row["kind"] = "wifi"
		row["wifi"] = w
		row["managed"] = true
		row["configurationSource"] = "systemd-networkd"
		if Netplan() {
			row["configurationSource"] = "Netplan"
		}
		row["manager"] = "systemd-networkd"
		state := 30
		if !w.Enabled || !w.HardwareEnabled {
			state = 20
		} else if w.ActiveAP != "/" || w.Mode == 3 {
			state = 100
		}
		row["nmState"] = state
		c, e := wifiSettings(name)
		if e != nil {
			return nil, e
		}
		for _, p := range c.Profiles {
			if p.ID == c.Selected && w.ActiveAP != "/" {
				row["profile"] = p.Name
			}
		}
	}
	groups, e := Groups()
	if e != nil {
		return nil, e
	}
	visible := []map[string]any{}
	for _, g := range groups {
		status := "stopped"
		if g.Enabled {
			status = "active"
			if !sourceConnected(g.Source) && g.Mode == "nat" {
				status = "upstream"
			}
			if !exists("/sys/class/net/" + g.Bridge) {
				status = "error"
			}
			for _, name := range g.Outputs {
				if !exists("/sys/class/net/"+name) || (Wireless(name) && !APActive(name)) {
					status = "error"
				}
			}
		}
		aps := map[string]any{}
		for name, c := range g.Wifi {
			aps[name] = map[string]any{"ssid": c.SSID, "band": c.Band, "channel": c.Channel}
		}
		visible = append(visible, map[string]any{"id": g.ID, "name": g.Name, "source": g.Source, "outputs": g.Outputs, "mode": g.Mode, "wifi": aps, "enabled": g.Enabled, "autostart": g.Autostart, "bridge": g.Bridge, "status": status, "addresses": Addresses(g.Bridge)})
		for _, row := range rows {
			name, _ := row["name"].(string)
			if name == g.Source || slices.Contains(g.Outputs, name) {
				row["sharingGroup"] = g.ID
			}
		}
	}
	return map[string]any{"interfaces": rows, "wifi": map[string]any{"present": present, "enabled": enabled, "hardwareEnabled": hardware}, "sharing": map[string]any{"groups": visible, "ready": Active()}}, nil
}
