package networkd

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

func netplanPath(name string) string { return "/etc/netplan/90-panasms-" + name + ".yaml" }
func netplanID(name string) string   { return "00-panasms-" + name }
func readNetplan(s *snapshot) error {
	raw, e := invoke("netplan", "status", "--format", "json", s.Link.Name)
	if e != nil {
		return e
	}
	var statuses map[string]struct {
		ID      string `json:"id"`
		Backend string `json:"backend"`
	}
	if e = json.Unmarshal(raw, &statuses); e != nil {
		return e
	}
	status := statuses[s.Link.Name]
	if status.ID == "" || status.Backend != "networkd" {
		return fmt.Errorf("Could not identify the Netplan definition")
	}
	raw, e = invoke("netplan", "get")
	if e != nil {
		return e
	}
	var doc struct {
		Network struct {
			Ethernets map[string]map[string]any `yaml:"ethernets"`
		} `yaml:"network"`
	}
	if e = yaml.Unmarshal(raw, &doc); e != nil {
		return e
	}
	s.Netplan = doc.Network.Ethernets[status.ID]
	if s.Netplan == nil {
		return fmt.Errorf("This Netplan interface type is not supported by the IP editor")
	}
	s.Backend = "netplan"
	s.Path = netplanPath(s.Link.Name)
	s.Files = map[string]string{}
	for _, dir := range []string{"/lib/netplan", "/etc/netplan", "/run/netplan"} {
		paths, e := filepath.Glob(dir + "/*.yaml")
		if e != nil {
			return e
		}
		for _, p := range paths {
			info, e := os.Lstat(p)
			if e != nil {
				return e
			}
			if !info.Mode().IsRegular() || info.Size() > 1024*1024 {
				return fmt.Errorf("Unsupported Netplan configuration file")
			}
			b, e := os.ReadFile(p)
			if e != nil {
				return e
			}
			s.Files[p] = string(b)
		}
	}
	return nil
}
func renderNetplan(s snapshot, c Config) (string, error) {
	if e := validate(c); e != nil {
		return "", e
	}
	node := map[string]any{}
	for k, v := range s.Netplan {
		node[k] = v
	}
	node["match"] = map[string]any{"name": s.Link.Name, "macaddress": net.HardwareAddr(s.Link.HardwareAddress).String()}
	delete(node, "set-name")
	node["renderer"] = "networkd"
	node["dhcp4"] = c.IPv4.Method == "auto"
	node["dhcp6"] = c.IPv6.Method == "auto"
	if c.IPv6.Method == "auto" && s.Config.IPv6.Method == "auto" {
		node["dhcp6"] = s.Netplan["dhcp6"] == true
	}
	node["accept-ra"] = c.IPv6.Method == "auto"
	if c.IPv6.Method == "auto" && s.Config.IPv6.Method == "auto" {
		if value, ok := s.Netplan["accept-ra"]; ok {
			node["accept-ra"] = value
		}
	}
	linklocal := []string{}
	if c.IPv4.Method == "link-local" {
		linklocal = append(linklocal, "ipv4")
	}
	if c.IPv6.Method != "disabled" {
		linklocal = append(linklocal, "ipv6")
	}
	node["link-local"] = linklocal
	if c.MTU > 0 {
		node["mtu"] = c.MTU
	} else {
		delete(node, "mtu")
	}
	node["addresses"] = append(append([]string{}, c.IPv4.Addresses...), c.IPv6.Addresses...)
	dns := map[string]any{}
	if old, ok := node["nameservers"].(map[string]any); ok {
		for k, v := range old {
			dns[k] = v
		}
	}
	dns["addresses"] = append(append([]string{}, c.IPv4.DNS...), c.IPv6.DNS...)
	node["nameservers"] = dns
	delete(node, "gateway4")
	delete(node, "gateway6")
	routes := []map[string]any{}
	for i, f := range []IPConfig{c.IPv4, c.IPv6} {
		key := []string{"dhcp4-overrides", "dhcp6-overrides"}[i]
		overrides := map[string]any{}
		if old, ok := node[key].(map[string]any); ok {
			for k, v := range old {
				overrides[k] = v
			}
		}
		overrides["use-dns"] = !f.IgnoreAutoDNS
		overrides["use-routes"] = !f.NeverDefault
		if f.Metric >= 0 {
			overrides["route-metric"] = f.Metric
		} else {
			delete(overrides, "route-metric")
		}
		overrides["use-mtu"] = c.MTU == 0
		node[key] = overrides
		if f.Gateway != "" {
			to := "0.0.0.0/0"
			if i == 1 {
				to = "::/0"
			}
			routes = append(routes, map[string]any{"to": to, "via": f.Gateway})
		}
		for _, r := range f.Routes {
			entry := map[string]any{"to": r.Destination}
			if r.Gateway != "" {
				entry["via"] = r.Gateway
			}
			if r.Metric >= 0 {
				entry["metric"] = r.Metric
			}
			routes = append(routes, entry)
		}
	}
	if c.IPv4.Method == "auto" && c.IPv6.Method == "auto" && digest(node["dhcp4-overrides"]) != digest(node["dhcp6-overrides"]) {
		return "", fmt.Errorf("Netplan requires matching DHCPv4 and DHCPv6 overrides when both are enabled")
	}
	node["routes"] = routes
	raw, e := yaml.Marshal(map[string]any{"network": map[string]any{"version": 2, "ethernets": map[string]any{netplanID(s.Link.Name): node}}})
	return "# Managed by PaNasMs. Original Netplan definitions are retained.\n" + string(raw), e
}
func validateNetplan(path, content string) error {
	root, e := os.MkdirTemp("", "panasms-netplan-")
	if e != nil {
		return e
	}
	defer os.RemoveAll(root)
	for _, dir := range []string{"/lib/netplan", "/etc/netplan", "/run/netplan"} {
		paths, _ := filepath.Glob(dir + "/*.yaml")
		for _, p := range paths {
			b, e := os.ReadFile(p)
			if e != nil {
				return e
			}
			dst := filepath.Join(root, p)
			if e = os.MkdirAll(filepath.Dir(dst), 0700); e != nil {
				return e
			}
			if e = os.WriteFile(dst, b, 0600); e != nil {
				return e
			}
		}
	}
	dst := filepath.Join(root, path)
	if e = os.MkdirAll(filepath.Dir(dst), 0700); e != nil {
		return e
	}
	if e = os.WriteFile(dst, []byte(content), 0600); e != nil {
		return e
	}
	_, e = invoke("netplan", "generate", "--root-dir", root)
	return e
}
func isNetplanFile(path string) bool { return strings.HasPrefix(filepath.Base(path), "10-netplan-") }
