package networknative

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"time"
)

func sharingOperation(mode, action, user string, p map[string]any) (json.RawMessage, error) {
	groups, e := Groups()
	if e != nil {
		return nil, e
	}
	var old *Group
	for i := range groups {
		if groups[i].ID == p["id"] {
			old = &groups[i]
		}
	}
	if p["id"] != nil && p["id"] != "" && old == nil {
		return nil, fmt.Errorf("Sharing group no longer exists")
	}
	if old != nil && old.Provider != "networkd" {
		return nil, fmt.Errorf("This sharing group belongs to another network provider")
	}
	var g Group
	switch action {
	case "network.share.save":
		g, e = reviewGroup(p, old, groups)
	case "network.share.wifi":
		if old == nil {
			return nil, fmt.Errorf("Sharing group no longer exists")
		}
		name, _ := p["interface"].(string)
		if _, ok := old.Wifi[name]; !ok {
			return nil, fmt.Errorf("Select a Wi-Fi access point from this sharing group")
		}
		raw, _ := json.Marshal(old)
		var effective map[string]any
		_ = json.Unmarshal(raw, &effective)
		effective["wifi"].(map[string]any)[name] = p["wifi"]
		g, e = reviewGroup(effective, old, groups)
		g.Enabled = old.Enabled
	case "network.share.start", "network.share.stop", "network.share.delete", "network.share.remove-port":
		if old == nil {
			return nil, fmt.Errorf("Sharing group no longer exists")
		}
		b, _ := json.Marshal(old)
		_ = json.Unmarshal(b, &g)
		switch action {
		case "network.share.start":
			var effective map[string]any
			_ = json.Unmarshal(b, &effective)
			g, e = reviewGroup(effective, old, groups)
		case "network.share.stop", "network.share.delete":
			g.Enabled = false
		case "network.share.remove-port":
			name, _ := p["interface"].(string)
			if !slices.Contains(g.Outputs, name) {
				return nil, fmt.Errorf("Select a recipient interface from this sharing group")
			}
			g.Outputs = slices.DeleteFunc(g.Outputs, func(v string) bool { return v == name })
			delete(g.Wifi, name)
			delete(g.Identities, name)
			if len(g.Outputs) == 0 {
				g.Enabled = false
			} else {
				g.Files, e = renderGroup(g)
			}
		}
	default:
		return nil, fmt.Errorf("Unknown sharing operation")
	}
	if e != nil {
		return nil, e
	}
	if g.Enabled {
		if e = validateFiles(g.Files); e != nil {
			return nil, e
		}
	}
	if mode == "plan" {
		return json.Marshal(map[string]any{"target": g.Source, "confirmation": g.Source, "details": []string{g.Source}, "fingerprint": hash([]any{action, p, groups, g.Identities})})
	}
	after := []Group{}
	for _, v := range groups {
		if old == nil || v.ID != old.ID {
			after = append(after, v)
		}
	}
	if action != "network.share.delete" && len(g.Outputs) > 0 {
		after = append(after, g)
	}
	t := &transaction{ID: ident(), Kind: "network.native", Interface: g.Source, User: user, Status: "applying", Deadline: time.Now().Unix() + 150, Boot: boot(), Addresses: []string{}, GroupsBefore: groups, GroupsAfter: after, Sharing: true, Before: map[string]*string{}, Applied: map[string]*string{}}
	for _, v := range append(append([]Group{}, groups...), after...) {
		for path := range v.Files {
			saved, err := fileState(path)
			if err != nil {
				return nil, err
			}
			t.Before[path] = saved
		}
	}
	for name := range g.Wifi {
		path := wifiPath(name)
		previous, err := fileState(path)
		if err != nil {
			return nil, err
		}
		t.Before[path] = previous
	}
	if e = save(t); e != nil {
		return nil, e
	}
	if e = arm(t); e != nil {
		t.Status = "rolled-back"
		_ = save(t)
		return nil, e
	}
	if old != nil && old.Enabled {
		e = DeactivateGroup(*old)
	}
	if e == nil && g.Enabled {
		for name := range g.Wifi {
			c, err := wifiSettings(name)
			if err != nil {
				e = err
				break
			}
			c.Enabled = true
			if err := write(wifiPath(name), c); err != nil {
				e = err
				break
			}
		}
	}
	if e == nil && g.Enabled {
		e = ActivateGroup(g)
	}
	if e == nil && g.Enabled {
		e = waitGroup(g, time.Unix(t.Deadline-30, 0))
	}
	if e == nil {
		e = write(groupsPath, after)
	}
	if e != nil {
		original := e
		if restore := rollback(t); restore != nil {
			return nil, fmt.Errorf("Sharing failed and rollback needs attention: %v", restore)
		}
		return nil, fmt.Errorf("%v; previous settings restored", original)
	}
	for path := range t.Before {
		t.Applied[path], e = fileState(path)
		if e != nil {
			return nil, e
		}
	}
	t.Status = "pending"
	t.Addresses = Addresses(g.Bridge)
	if e = save(t); e != nil {
		return nil, e
	}
	return json.Marshal(map[string]any{"message": "Network changes await confirmation", "change": publicTransaction(t)})
}
func arm(t *transaction) error {
	helper, err := os.Executable()
	if err != nil {
		return err
	}
	return run("systemd-run", "--quiet", "--collect", "--unit=panasms-native-rollback-"+t.ID, "--on-active=150s", "--timer-property=AccuracySec=1s", "--property=Restart=on-failure", "--property=RestartSec=3s", helper, "network-native", "recover")
}

func changedGroups(groups, previous []Group) []Group {
	result := []Group{}
	for _, group := range groups {
		unchanged := false
		for _, old := range previous {
			if old.ID == group.ID && hash(old) == hash(group) {
				unchanged = true
				break
			}
		}
		if !unchanged {
			result = append(result, group)
		}
	}
	return result
}

func waitGroup(g Group, deadline time.Time) error {
	for time.Now().Before(deadline) {
		ready := hasGlobalAddress(Addresses(g.Bridge))
		for name := range g.Wifi {
			c, err := wifiSettings(name)
			if err != nil {
				return err
			}
			if c.Enabled {
				ready = ready && APActive(name)
			}
		}
		if ready {
			return nil
		}
		time.Sleep(time.Second)
	}
	return fmt.Errorf("Sharing activation timed out")
}
