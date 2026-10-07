package network

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"time"

	"panasms.local/backend/internal/systemops/networkd"
	"panasms.local/backend/internal/systemops/networknative"
)

func Query(ctx context.Context) (json.RawMessage, error) {
	raw, e := command("ip", "-j", "address", "show")
	if e != nil {
		return nil, e
	}
	var links []struct {
		Name      string   `json:"ifname"`
		Index     int      `json:"ifindex"`
		State     string   `json:"operstate"`
		MAC       string   `json:"address"`
		MTU       int      `json:"mtu"`
		Flags     []string `json:"flags"`
		Kind      string   `json:"link_type"`
		Addresses []struct {
			Local  string `json:"local"`
			Prefix int    `json:"prefixlen"`
		} `json:"addr_info"`
	}
	if e = json.Unmarshal(raw, &links); e != nil {
		return nil, e
	}
	routes := []map[string]any{}
	for _, family := range []int{4, 6} {
		raw, e = command("ip", "-j", "-"+strconv.Itoa(family), "route", "show", "table", "all")
		if e != nil {
			return nil, e
		}
		var rows []map[string]any
		if e = json.Unmarshal(raw, &rows); e != nil {
			return nil, e
		}
		for _, r := range rows {
			r["family"] = family
			routes = append(routes, r)
		}
	}
	a, _ := connect()
	if a != nil {
		defer a.bus.Close()
	}
	rows := []map[string]any{}
	names := []string{}
	for _, l := range links {
		addresses := []string{}
		for _, v := range l.Addresses {
			addresses = append(addresses, fmt.Sprintf("%s/%d", v.Local, v.Prefix))
		}
		row := map[string]any{"name": l.Name, "index": l.Index, "state": l.State, "adminUp": slices.Contains(l.Flags, "UP"), "mac": l.MAC, "mtu": l.MTU, "addresses": addresses, "editable": false, "kind": l.Kind, "profile": "", "config": nil, "dns": []string{}, "system": systemInterface(l.Name), "accessManaged": accessInterface(l.Name)}
		if a != nil {
			path, props, err := a.device(l.Name)
			if err == nil {
				kinds := map[int64]string{1: "ethernet", 2: "wifi", 10: "bond", 11: "vlan", 13: "bridge", 19: "vxlan", 32: "loopback"}
				kind := kinds[num(props["DeviceType"])]
				if kind == "" {
					kind = "virtual"
				}
				row["kind"] = kind
				row["nmState"] = num(props["State"])
				row["managed"] = boolean(props["Managed"])
				if boolean(props["Managed"]) {
					row["manager"] = "NetworkManager"
					row["configurationSource"] = "NetworkManager"
				}
				if num(props["DeviceType"]) == 1 && num(props["Capabilities"])&2 != 0 {
					wired, err := a.props(path, nm+".Device.Wired")
					if err == nil {
						row["carrier"] = boolean(wired["Carrier"])
					}
				}
				dns := []string{}
				for _, family := range []int{4, 6} {
					p := obj(props["Ip"+strconv.Itoa(family)+"Config"])
					if p != "" && p != "/" {
						v, err := a.props(p, nm+".IP"+strconv.Itoa(family)+"Config")
						if err == nil {
							for _, entry := range dictionaries(v["NameserverData"]) {
								if v := str(entry["address"]); v != "" {
									dns = append(dns, v)
								}
							}
						}
					}
				}
				row["dns"] = dns
				if num(props["State"]) == 100 {
					_, _, saved, _, _, err := a.active(l.Name)
					if err == nil {
						row["profile"] = str(saved["connection"]["id"])
						row["uuid"] = str(saved["connection"]["uuid"])
						row["editable"] = editable(saved)
						if editable(saved) {
							row["config"] = config(saved)
						}
					}
				}
			}
		}
		if row["managed"] != true && row["system"] != true {
			names = append(names, l.Name)
		}
		rows = append(rows, row)
	}
	native := networkd.Query(names)
	for _, row := range rows {
		if v, ok := native[row["name"].(string)]; ok {
			b, _ := json.Marshal(v)
			var fields map[string]any
			_ = json.Unmarshal(b, &fields)
			for k, v := range fields {
				row[k] = v
			}
			delete(row, "nmState")
			row["managed"] = true
			if networknative.Wireless(row["name"].(string)) {
				row["kind"] = "wifi"
			} else {
				row["kind"] = "ethernet"
			}
		}
		if row["system"] == true || row["accessManaged"] == true {
			row["editable"] = false
		}
	}
	var extra map[string]any
	if a == nil && networknative.Active() {
		extra, e = networknative.Inventory(rows)
	} else {
		raw, e = legacy(ctx, "inventory", "", "", map[string]any{"interfaces": rows})
		if e == nil {
			e = json.Unmarshal(raw, &extra)
		}
	}
	if e != nil {
		return nil, e
	}
	unlock, e := networkd.Lock()
	if e != nil {
		return nil, e
	}
	s, e := current(a)
	unlock()
	if e != nil {
		return nil, e
	}
	backend := "readonly"
	if a != nil {
		backend = "NetworkManager"
	}
	if len(native) > 0 {
		backend = "systemd-networkd"
		if a != nil {
			backend = "mixed"
		}
	}
	return json.Marshal(map[string]any{"backend": backend, "interfaces": extra["interfaces"], "routes": routes, "change": public(s), "serverTime": time.Now().Unix(), "timeout": 120, "wifi": extra["wifi"], "sharing": extra["sharing"]})
}
