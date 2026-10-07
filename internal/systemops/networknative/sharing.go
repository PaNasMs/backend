package networknative

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
	"panasms.local/backend/internal/systemops/networkd"
)

var groupsPath = "/var/lib/panasms-agent/network-sharing/groups.json"

type Group struct {
	BridgeText string              `json:"bridgeText,omitempty"`
	BridgeNode map[string]any      `json:"bridgeNode,omitempty"`
	ID         string              `json:"id"`
	Name       string              `json:"name"`
	Source     string              `json:"source"`
	Outputs    []string            `json:"outputs"`
	Mode       string              `json:"mode"`
	Wifi       map[string]APConfig `json:"wifi"`
	Enabled    bool                `json:"enabled"`
	Autostart  bool                `json:"autostart"`
	Bridge     string              `json:"bridge"`
	Subnet     string              `json:"subnet,omitempty"`
	Slot       int                 `json:"slot"`
	Provider   string              `json:"provider"`
	Identities map[string]string   `json:"identities"`
	Files      map[string]*string  `json:"files"`
	Previous   map[string]*string  `json:"previous"`
}

func Groups() ([]Group, error) {
	g := []Group{}
	e := read(groupsPath, &g)
	if os.IsNotExist(e) {
		e = nil
	}
	if e == nil {
		for _, group := range g {
			if group.Provider != "networkd" {
				return nil, fmt.Errorf("Existing NetworkManager sharing groups require migration before switching network providers")
			}
		}
	}
	return g, e
}
func sourceConnected(name string) bool {
	b, e := os.ReadFile("/sys/class/net/" + name + "/carrier")
	if e != nil || strings.TrimSpace(string(b)) != "1" {
		return false
	}
	for _, a := range Addresses(name) {
		ip, _, e := net.ParseCIDR(a)
		if e == nil && ip.To4() != nil && !ip.IsLinkLocalUnicast() {
			return true
		}
	}
	return false
}
func groupSubnet(groups []Group) (string, error) {
	raw, e := invoke("ip", "-j", "-4", "route", "show", "table", "all")
	if e != nil {
		return "", e
	}
	var rows []struct {
		Dst string `json:"dst"`
	}
	if e = json.Unmarshal(raw, &rows); e != nil {
		return "", e
	}
	used := []*net.IPNet{}
	for _, g := range groups {
		_, n, e := net.ParseCIDR(g.Subnet)
		if e == nil {
			used = append(used, n)
		}
	}
	for _, r := range rows {
		ip, n, e := net.ParseCIDR(r.Dst)
		if e == nil && r.Dst != "0.0.0.0/0" {
			n.IP = ip
			used = append(used, n)
		}
	}
	for i := 42; i < 250; i++ {
		s := fmt.Sprintf("10.%d.0.0/24", i)
		ip, n, _ := net.ParseCIDR(s)
		overlap := false
		for _, u := range used {
			overlap = overlap || u.Contains(ip) || n.Contains(u.IP)
		}
		if !overlap {
			return s, nil
		}
	}
	return "", fmt.Errorf("No free private subnet found for sharing")
}
func address(subnet string) string {
	ip, _, _ := net.ParseCIDR(subnet)
	ip = ip.To4()
	if ip == nil {
		return ""
	}
	ip[3] = 1
	return ip.String() + "/24"
}
func groupPath(id string) string   { return "/etc/netplan/99-panasms-share-" + id + ".yaml" }
func netplanID(name string) string { return "00-0-panasms-port-" + name }

func renderGroup(g Group) (map[string]*string, error) {
	files := map[string]*string{}
	members := append([]string{}, g.Outputs...)
	if g.Mode == "bridge" {
		members = append(members, g.Source)
	}
	bridge := map[string]any{"renderer": "networkd", "interfaces": []string{}, "optional": true, "dhcp4": false, "dhcp6": false, "accept-ra": false, "parameters": map[string]any{"stp": true, "forward-delay": 0}}
	bridgeText := "[Match]\nName=" + g.Bridge + "\n[Network]\nAddress=" + address(g.Subnet) + "\nDHCP=no\nIPv6AcceptRA=no\n"
	mac := ""
	if g.Mode == "bridge" {
		raw, node := g.BridgeText, g.BridgeNode
		var e error
		if raw == "" {
			raw, node, _, e = networkd.SharingSource(g.Source, g.Bridge)
		}
		if e != nil {
			return nil, e
		}
		bridgeText = raw
		b, e := os.ReadFile("/sys/class/net/" + g.Source + "/address")
		if e != nil {
			return nil, e
		}
		mac = strings.TrimSpace(string(b))
		if Netplan() {
			if node == nil {
				return nil, fmt.Errorf("Cannot migrate a non-Netplan source through Netplan")
			}
			for k, v := range node {
				switch k {
				case "match", "set-name", "renderer", "optional", "activation-mode":
				default:
					bridge[k] = v
				}
			}
			bridge["macaddress"] = mac
		}
	} else {
		bridge["addresses"] = []string{address(g.Subnet)}
	}
	if Netplan() {
		ports := map[string]any{}
		ids := []string{}
		for _, name := range members {
			id := netplanID(name)
			ids = append(ids, id)
			match := map[string]any{"name": name}
			if mac := identityMAC(g.Identities[name]); mac != "" {
				match["macaddress"] = mac
			}
			ports[id] = map[string]any{"match": match, "renderer": "networkd", "dhcp4": false, "dhcp6": false, "accept-ra": false, "addresses": []string{}, "routes": []any{}, "link-local": []string{}, "optional": true}
		}
		bridge["interfaces"] = ids
		raw, e := yaml.Marshal(map[string]any{"network": map[string]any{"version": 2, "ethernets": ports, "bridges": map[string]any{g.Bridge: bridge}}})
		if e != nil {
			return nil, e
		}
		files[groupPath(g.ID)] = text(string(raw))
	} else {
		macLine := ""
		if mac != "" {
			macLine = "MACAddress=" + mac + "\n"
		}
		files["/etc/systemd/network/00-panasms-share-"+g.ID+".netdev"] = text("[NetDev]\nName=" + g.Bridge + "\nKind=bridge\n" + macLine + "[Bridge]\nSTP=yes\nForwardDelaySec=0\n")
		files["/etc/systemd/network/00-panasms-share-"+g.ID+".network"] = text(bridgeText)
		for _, name := range members {
			matchMAC := ""
			if mac := identityMAC(g.Identities[name]); mac != "" {
				matchMAC = "\nPermanentMACAddress=" + mac
			}
			files["/etc/systemd/network/00-0-panasms-port-"+name+".network"] = text("[Match]\nName=" + name + matchMAC + "\n[Network]\nBridge=" + g.Bridge + "\nDHCP=no\nLinkLocalAddressing=no\nIPv6AcceptRA=no\n")
		}
	}
	for name, c := range g.Wifi {
		files[apPath(name)] = text(hostapdConfig(name, g.Bridge, c))
	}
	if g.Mode == "nat" {
		conf, e := dnsConfig(g.Bridge, address(g.Subnet))
		if e != nil {
			return nil, e
		}
		files["/etc/panasms/network/dnsmasq-"+g.Bridge+".conf"] = text(conf)
	}
	return files, nil
}
func reviewGroup(p map[string]any, old *Group, groups []Group) (Group, error) {
	b, _ := json.Marshal(p)
	var g Group
	if e := json.Unmarshal(b, &g); e != nil {
		return g, e
	}
	g = Group{Name: g.Name, Source: g.Source, Outputs: g.Outputs, Mode: g.Mode, Wifi: g.Wifi, Autostart: g.Autostart}
	if g.Mode != "nat" && g.Mode != "bridge" {
		return g, fmt.Errorf("Invalid sharing mode")
	}
	if len(g.Outputs) < 1 || len(g.Outputs) > 16 {
		return g, fmt.Errorf("Select at least one destination interface")
	}
	g.Name = strings.TrimSpace(g.Name)
	if len(g.Name) < 1 || len(g.Name) > 64 || strings.ContainsAny(g.Name, "\r\n\x00") {
		return g, fmt.Errorf("Invalid sharing name")
	}
	if _, ok := p["autostart"].(bool); !ok {
		return g, fmt.Errorf("Invalid network option")
	}
	g.Identities = map[string]string{}
	phys := map[string]bool{}
	seen := map[string]bool{}
	for _, name := range append([]string{g.Source}, g.Outputs...) {
		if seen[name] {
			return g, fmt.Errorf("Source and destination interfaces must be different")
		}
		seen[name] = true
		if e := CheckInterface(name); e != nil {
			return g, e
		}
		for _, other := range groups {
			if old != nil && other.ID == old.ID {
				continue
			}
			if other.Source == name || slices.Contains(other.Outputs, name) {
				return g, fmt.Errorf("An interface is already used by another sharing group")
			}
		}
		cap := Capability(name)
		if cap.Phy != "" {
			if phys[cap.Phy] {
				return g, fmt.Errorf("These interfaces share one radio; choose a separate Wi-Fi adapter")
			}
			phys[cap.Phy] = true
		}
		g.Identities[name] = Identity(name)
		if old != nil && old.Identities[name] != "" && old.Identities[name] != g.Identities[name] {
			return g, fmt.Errorf("A network adapter was replaced; recreate the sharing group")
		}
		if name != g.Source && Wireless(name) {
			c := g.Wifi[name]
			if c.Password == "" && old != nil {
				c.Password = old.Wifi[name].Password
			}
			v, e := validateAP(name, c)
			if e != nil {
				return g, e
			}
			if g.Wifi == nil {
				g.Wifi = map[string]APConfig{}
			}
			g.Wifi[name] = v
		}
	}
	for name := range g.Wifi {
		if !slices.Contains(g.Outputs, name) || !Wireless(name) {
			return g, fmt.Errorf("Select a Wi-Fi access point from this sharing group")
		}
	}
	if g.Mode == "bridge" && Wireless(g.Source) {
		return g, fmt.Errorf("Transparent Wi-Fi bridging is not verified with your router; use a separate network")
	}
	if old == nil || !old.Enabled {
		if !sourceConnected(g.Source) {
			return g, fmt.Errorf("Connect the source interface before sharing")
		}
	}
	g.Provider = "networkd"
	g.Enabled = true
	g.ID = ident()[:12]
	g.Bridge = "osbr" + g.ID[:8]
	g.Slot = -1
	if old != nil {
		g.ID, g.Bridge, g.Slot, g.Subnet = old.ID, old.Bridge, old.Slot, old.Subnet
	} else {
		for i := 0; i < 100; i++ {
			used := false
			for _, other := range groups {
				used = used || other.Slot == i
			}
			if !used {
				g.Slot = i
				break
			}
		}
	}
	if g.Slot < 0 {
		return g, fmt.Errorf("No free routing table available for sharing")
	}
	if g.Mode == "nat" && g.Subnet == "" {
		var e error
		g.Subnet, e = groupSubnet(groups)
		if e != nil {
			return g, e
		}
	}
	if g.Mode == "bridge" {
		if old != nil && old.Mode == g.Mode && old.Source == g.Source {
			g.BridgeText, g.BridgeNode = old.BridgeText, old.BridgeNode
		}
		if g.BridgeText == "" {
			var err error
			g.BridgeText, g.BridgeNode, _, err = networkd.SharingSource(g.Source, g.Bridge)
			if err != nil {
				return g, err
			}
		}
	}
	files, e := renderGroup(g)
	if e != nil {
		return g, e
	}
	g.Files = files
	g.Previous = map[string]*string{}
	for path := range files {
		v, err := fileState(path)
		if err != nil {
			return g, err
		}
		g.Previous[path] = v
		if old != nil {
			if original, ok := old.Previous[path]; ok {
				g.Previous[path] = original
			}
		}
	}
	return g, nil
}
func ActivateGroup(g Group) error {
	for name, id := range g.Identities {
		if exists("/sys/class/net/"+name) && Identity(name) != id {
			return fmt.Errorf("A sharing adapter was replaced")
		}
	}
	for path, v := range g.Files {
		if e := setFile(path, v); e != nil {
			return e
		}
	}
	if e := ApplyNetwork(); e != nil {
		return e
	}
	deadline := time.Now().Add(10 * time.Second)
	for !exists("/sys/class/net/" + g.Bridge) {
		if time.Now().After(deadline) {
			return fmt.Errorf("Network bridge did not become available")
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err := run("ip", "link", "set", "dev", g.Bridge, "up"); err != nil {
		return err
	}
	members := append([]string{g.Bridge}, g.Outputs...)
	if g.Mode == "bridge" {
		members = append(members, g.Source)
	}
	for _, name := range members {
		if exists("/sys/class/net/" + name) {
			if e := run("networkctl", "reconfigure", name); e != nil {
				return e
			}
		}
	}
	for name, c := range g.Wifi {
		if !exists("/sys/class/net/" + name) {
			continue
		}
		config, err := wifiSettings(name)
		if err != nil {
			return err
		}
		if !config.Enabled {
			if err := setRadio(name, false); err != nil {
				return err
			}
			continue
		}
		if exists("/sys/class/net/" + name) {
			if e := StartAP(name, g.Bridge, c); e != nil {
				return e
			}
		}
	}
	if g.Mode == "nat" {
		if e := run("systemctl", "restart", dnsUnit(g.Bridge)); e != nil {
			return e
		}
		return Routing(g)
	}
	return nil
}
func DeactivateGroup(g Group) error {
	for name := range g.Wifi {
		if e := StopAP(name); e != nil {
			return e
		}
	}
	_ = run("systemctl", "stop", dnsUnit(g.Bridge))
	for path, v := range g.Previous {
		if e := setFile(path, v); e != nil {
			return e
		}
	}
	if e := ApplyNetwork(); e != nil {
		return e
	}
	for _, name := range append([]string{g.Source}, g.Outputs...) {
		if exists("/sys/class/net/" + name) {
			_ = run("ip", "link", "set", "dev", name, "nomaster")
			if Wireless(name) {
				c, e := wifiSettings(name)
				if e != nil {
					return e
				}
				if e = ApplyWifi(c); e != nil {
					return e
				}
			} else if e := run("networkctl", "reconfigure", name); e != nil {
				return e
			}
		}
	}
	if exists("/sys/class/net/" + g.Bridge) {
		if e := run("ip", "link", "delete", g.Bridge); e != nil {
			return e
		}
	}
	return cleanupRouting(g)
}
func Routing(g Group) error {
	if g.Mode != "nat" {
		return nil
	}
	table, priority := strconv.Itoa(28000+g.Slot), strconv.Itoa(18000+g.Slot)
	raw, e := invoke("ip", "-j", "-4", "rule", "show")
	if e != nil {
		return e
	}
	var rules []map[string]any
	if e = json.Unmarshal(raw, &rules); e != nil {
		return e
	}
	found := false
	for _, r := range rules {
		if r["priority"] == float64(18000+g.Slot) {
			if fmt.Sprint(r["table"]) != table || r["iif"] != g.Bridge {
				return fmt.Errorf("Routing rule conflicts with sharing")
			}
			found = true
		}
	}
	if e = run("ip", "-4", "route", "replace", "unreachable", "default", "metric", "42760", "table", table); e != nil {
		return e
	}
	if !found {
		if e = run("ip", "-4", "rule", "add", "priority", priority, "iif", g.Bridge, "lookup", table); e != nil {
			return e
		}
	}
	raw, e = invoke("ip", "-j", "-4", "route", "show", "table", "main")
	if e != nil {
		return e
	}
	var routes []map[string]any
	if e = json.Unmarshal(raw, &routes); e != nil {
		return e
	}
	if e = syncRoutes(g, table, routes); e != nil {
		return e
	}
	if e = run("sysctl", "-w", "net.ipv4.ip_forward=1"); e != nil {
		return e
	}
	if e = dockerForwarding(g, false); e != nil {
		return e
	}
	return ensureNAT(g)
}

func cleanupRouting(g Group) error {
	if g.Mode != "nat" {
		return nil
	}
	if err := dockerForwarding(g, true); err != nil {
		return err
	}
	_ = run("ip", "-4", "rule", "del", "priority", strconv.Itoa(18000+g.Slot), "iif", g.Bridge, "lookup", strconv.Itoa(28000+g.Slot))
	_ = run("ip", "-4", "route", "flush", "table", strconv.Itoa(28000+g.Slot))
	if run("nft", "list", "table", "ip", "panasms_"+g.ID) == nil {
		return run("nft", "delete", "table", "ip", "panasms_"+g.ID)
	}
	return nil
}
