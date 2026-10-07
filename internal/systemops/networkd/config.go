package networkd

import (
	"bufio"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

type Route struct {
	Destination string `json:"destination"`
	Gateway     string `json:"gateway"`
	Metric      int64  `json:"metric"`
}
type IPConfig struct {
	Method        string   `json:"method"`
	Addresses     []string `json:"addresses"`
	DNS           []string `json:"dns"`
	Gateway       string   `json:"gateway"`
	IgnoreAutoDNS bool     `json:"ignoreAutoDns"`
	NeverDefault  bool     `json:"neverDefault"`
	Metric        int64    `json:"metric"`
	Routes        []Route  `json:"routes"`
}
type Config struct {
	IPv4 IPConfig `json:"ipv4"`
	IPv6 IPConfig `json:"ipv6"`
	MTU  int      `json:"mtu"`
}
type section struct {
	name   string
	values map[string][]string
}

func emptyIP() IPConfig {
	return IPConfig{Method: "disabled", Addresses: []string{}, DNS: []string{}, Metric: -1, Routes: []Route{}}
}
func last(s section, k string) string {
	v := s.values[k]
	if len(v) == 0 {
		return ""
	}
	return v[len(v)-1]
}
func parse(text string) ([]section, error) {
	rows := []section{}
	scanner := bufio.NewScanner(strings.NewReader(text))
	for scanner.Scan() {
		s := strings.TrimSpace(scanner.Text())
		if s == "" || strings.HasPrefix(s, "#") || strings.HasPrefix(s, ";") {
			continue
		}
		if strings.HasSuffix(s, "\\") {
			return nil, fmt.Errorf("Multiline network settings require manual review")
		}
		if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
			rows = append(rows, section{s[1 : len(s)-1], map[string][]string{}})
			continue
		}
		key, value, ok := strings.Cut(s, "=")
		if !ok || len(rows) == 0 {
			return nil, fmt.Errorf("Invalid network configuration")
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		m := rows[len(rows)-1].values
		if value == "" {
			m[key] = nil
		} else {
			m[key] = append(m[key], value)
		}
	}
	return rows, scanner.Err()
}
func readConfig(text string) (Config, error) {
	c := Config{IPv4: emptyIP(), IPv6: emptyIP()}
	c.IPv6.Method = "auto"
	sections, err := parse(text)
	if err != nil {
		return c, err
	}
	allowed := map[string]string{"Match": "Name MACAddress PermanentMACAddress Type Driver Path", "Link": "MTUBytes RequiredForOnline RequiredFamilyForOnline ActivationPolicy", "Network": "DHCP LinkLocalAddressing IPv6PrivacyExtensions IPv6AcceptRA DNS Domains DNSDefaultRoute Address Gateway", "DHCP": "RouteMetric UseMTU UseDNS UseRoutes UseGateway ClientIdentifier", "DHCPv4": "RouteMetric UseMTU UseDNS UseRoutes UseGateway ClientIdentifier", "DHCPv6": "RouteMetric UseDNS UseRoutes UseGateway", "IPv6AcceptRA": "UseDNS UseGateway RouteMetric", "Address": "Address", "Route": "Destination Gateway Metric"}
	for _, s := range sections {
		keys, ok := allowed[s.name]
		if !ok {
			return c, fmt.Errorf("Advanced network section %s requires manual review", s.name)
		}
		for k := range s.values {
			if !strings.Contains(" "+keys+" ", " "+k+" ") {
				return c, fmt.Errorf("Advanced network setting %s.%s requires manual review", s.name, k)
			}
		}
		switch s.name {
		case "Link":
			if v := last(s, "MTUBytes"); v != "" {
				c.MTU, err = strconv.Atoi(v)
				if err != nil {
					return c, err
				}
			}
		case "Network":
			switch last(s, "DHCP") {
			case "yes", "true":
				c.IPv4.Method = "auto"
				c.IPv6.Method = "auto"
			case "ipv4":
				c.IPv4.Method = "auto"
			case "ipv6":
				c.IPv6.Method = "auto"
			case "", "no", "false":
			default:
				return c, fmt.Errorf("Unsupported DHCP mode")
			}
			if last(s, "IPv6AcceptRA") == "no" && c.IPv6.Method != "auto" {
				c.IPv6.Method = "disabled"
			}
			if last(s, "IPv6AcceptRA") == "no" && (last(s, "DHCP") == "no" || last(s, "DHCP") == "ipv4" || last(s, "DHCP") == "") {
				c.IPv6.Method = "disabled"
			}
			for _, v := range s.values["Address"] {
				if err = addAddress(&c, v); err != nil {
					return c, err
				}
			}
			for _, v := range s.values["DNS"] {
				for _, a := range strings.Fields(v) {
					ip, e := netip.ParseAddr(a)
					if e != nil {
						return c, e
					}
					if ip.Is4() {
						c.IPv4.DNS = append(c.IPv4.DNS, a)
					} else {
						c.IPv6.DNS = append(c.IPv6.DNS, a)
					}
				}
			}
			for _, v := range s.values["Gateway"] {
				ip, e := netip.ParseAddr(v)
				if e != nil {
					return c, e
				}
				if ip.Is4() {
					c.IPv4.Gateway = v
				} else {
					c.IPv6.Gateway = v
				}
			}
			ll := last(s, "LinkLocalAddressing")
			if (ll == "ipv4" || ll == "yes") && c.IPv4.Method == "disabled" {
				c.IPv4.Method = "link-local"
			}
			if (ll == "ipv6" || ll == "yes") && c.IPv6.Method == "disabled" {
				c.IPv6.Method = "link-local"
			}
		case "Address":
			if err = addAddress(&c, last(s, "Address")); err != nil {
				return c, err
			}
		case "DHCP", "DHCPv4", "DHCPv6", "IPv6AcceptRA":
			families := []*IPConfig{&c.IPv4, &c.IPv6}
			if s.name == "DHCPv4" {
				families = families[:1]
			}
			if s.name == "DHCPv6" || s.name == "IPv6AcceptRA" {
				families = families[1:]
			}
			for _, f := range families {
				if v := last(s, "RouteMetric"); v != "" {
					f.Metric, err = strconv.ParseInt(v, 10, 64)
					if err != nil {
						return c, err
					}
				}
				if v := last(s, "UseDNS"); v != "" {
					f.IgnoreAutoDNS = v == "no" || v == "false"
				}
				if v := last(s, "UseGateway"); v != "" {
					f.NeverDefault = v == "no" || v == "false"
				}
				if last(s, "UseRoutes") == "no" || last(s, "UseRoutes") == "false" {
					f.NeverDefault = true
				}
			}
		case "Route":
			r := Route{Destination: last(s, "Destination"), Gateway: last(s, "Gateway"), Metric: -1}
			if r.Destination == "" {
				if a, e := netip.ParseAddr(r.Gateway); e == nil && a.Is6() {
					r.Destination = "::/0"
				} else {
					r.Destination = "0.0.0.0/0"
				}
			}
			if v := last(s, "Metric"); v != "" {
				r.Metric, err = strconv.ParseInt(v, 10, 64)
				if err != nil {
					return c, err
				}
			}
			p, e := netip.ParsePrefix(r.Destination)
			if e != nil {
				return c, e
			}
			if p.Addr().Is4() {
				c.IPv4.Routes = append(c.IPv4.Routes, r)
			} else {
				c.IPv6.Routes = append(c.IPv6.Routes, r)
			}
		}
	}
	for _, f := range []*IPConfig{&c.IPv4, &c.IPv6} {
		if (f.Method == "disabled" || f.Method == "link-local") && len(f.Addresses) > 0 {
			f.Method = "manual"
		}
	}
	return c, nil
}
func addAddress(c *Config, v string) error {
	p, e := netip.ParsePrefix(v)
	if e != nil {
		return e
	}
	if p.Addr().Is4() {
		c.IPv4.Addresses = append(c.IPv4.Addresses, v)
	} else {
		c.IPv6.Addresses = append(c.IPv6.Addresses, v)
	}
	return nil
}
func validate(c Config) error {
	if c.MTU != 0 && (c.MTU < 576 || c.MTU > 9000 || (c.IPv6.Method != "disabled" && c.IPv6.Method != "ignore" && c.MTU < 1280)) {
		return fmt.Errorf("Invalid MTU")
	}
	if (c.IPv4.Method == "disabled") && (c.IPv6.Method == "disabled" || c.IPv6.Method == "ignore") {
		return fmt.Errorf("At least one IP protocol must remain enabled")
	}
	for i, f := range []IPConfig{c.IPv4, c.IPv6} {
		if !strings.Contains(" auto manual disabled link-local ", " "+f.Method+" ") && !(i == 1 && f.Method == "ignore") {
			return fmt.Errorf("Unsupported IP method")
		}
		if f.Method == "ignore" {
			return fmt.Errorf("Ignoring IPv6 is not supported by networkd; use automatic or disabled")
		}
		if f.Metric < -1 || f.Metric > 4294967295 || len(f.Addresses) > 16 || len(f.DNS) > 16 || len(f.Routes) > 64 {
			return fmt.Errorf("Invalid network options")
		}
		if f.Method == "manual" && len(f.Addresses) == 0 {
			return fmt.Errorf("A static configuration needs at least one address")
		}
		check := func(a string) error {
			p, e := netip.ParseAddr(a)
			if e != nil || p.Is4() != (i == 0) || p.IsUnspecified() || p.IsMulticast() || p.Zone() != "" {
				return fmt.Errorf("Invalid IP address")
			}
			return nil
		}
		for _, a := range f.Addresses {
			p, e := netip.ParsePrefix(a)
			if e != nil {
				return e
			}
			if e = check(p.Addr().String()); e != nil {
				return e
			}
		}
		for _, a := range f.DNS {
			if e := check(a); e != nil {
				return e
			}
		}
		if f.Gateway != "" {
			if e := check(f.Gateway); e != nil {
				return e
			}
			if f.NeverDefault {
				return fmt.Errorf("Local-only connection cannot have a gateway")
			}
		}
		for _, r := range f.Routes {
			p, e := netip.ParsePrefix(r.Destination)
			if e != nil || p.Addr().Is4() != (i == 0) || p != p.Masked() || r.Metric < -1 || r.Metric > 4294967295 {
				return fmt.Errorf("Invalid route")
			}
			if f.NeverDefault && p.Bits() == 0 {
				return fmt.Errorf("Local-only connection cannot have a default route")
			}
			if r.Gateway != "" {
				if e := check(r.Gateway); e != nil {
					return e
				}
			}
		}
		if f.Method == "disabled" || f.Method == "link-local" {
			if len(f.Addresses)+len(f.DNS)+len(f.Routes) > 0 || f.Gateway != "" {
				return fmt.Errorf("Clear addresses and routes for this IP method")
			}
		}
	}
	return nil
}
func render(name, mac, original string, c Config) (string, error) {
	if e := validate(c); e != nil {
		return "", e
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# Managed by PaNasMs; original network configuration is retained.\n[Match]\nName=%s\nMACAddress=%s\n\n[Link]\n", name, mac)
	if c.MTU != 0 {
		fmt.Fprintf(&b, "MTUBytes=%d\n", c.MTU)
	}
	originalSections, _ := parse(original)
	for _, s := range originalSections {
		if s.name == "Link" {
			for _, key := range []string{"RequiredForOnline", "RequiredFamilyForOnline", "ActivationPolicy"} {
				if value := last(s, key); value != "" {
					fmt.Fprintf(&b, "%s=%s\n", key, value)
				}
			}
		}
	}
	before, _ := readConfig(original)
	oldDHCP := "no"
	oldRA := ""
	for _, section := range originalSections {
		if section.name == "Network" {
			if v := last(section, "DHCP"); v != "" {
				oldDHCP = v
			}
			oldRA = last(section, "IPv6AcceptRA")
		}
	}
	dhcp4 := c.IPv4.Method == "auto"
	dhcp6 := c.IPv6.Method == "auto"
	if dhcp4 && before.IPv4.Method == "auto" {
		dhcp4 = oldDHCP == "yes" || oldDHCP == "true" || oldDHCP == "ipv4"
	}
	if dhcp6 && before.IPv6.Method == "auto" {
		dhcp6 = oldDHCP == "yes" || oldDHCP == "true" || oldDHCP == "ipv6"
	}
	dhcp := "no"
	if dhcp4 {
		dhcp = "ipv4"
	}
	if dhcp6 {
		if dhcp == "ipv4" {
			dhcp = "yes"
		} else {
			dhcp = "ipv6"
		}
	}
	ll := "no"
	if c.IPv6.Method != "disabled" {
		ll = "ipv6"
	}
	if c.IPv4.Method == "link-local" {
		if ll == "ipv6" {
			ll = "yes"
		} else {
			ll = "ipv4"
		}
	}
	ra := "no"
	if c.IPv6.Method == "auto" {
		ra = "yes"
		if before.IPv6.Method == "auto" && oldRA != "" {
			ra = oldRA
		}
	}
	fmt.Fprintf(&b, "\n[Network]\nDHCP=%s\nLinkLocalAddressing=%s\nIPv6AcceptRA=%s\n", dhcp, ll, ra)
	sections, _ := parse(original)
	for _, s := range sections {
		if s.name == "Network" {
			for _, key := range []string{"IPv6PrivacyExtensions", "Domains", "DNSDefaultRoute"} {
				for _, v := range s.values[key] {
					fmt.Fprintf(&b, "%s=%s\n", key, v)
				}
			}
		}
	}
	for _, f := range []IPConfig{c.IPv4, c.IPv6} {
		for _, v := range f.Addresses {
			fmt.Fprintf(&b, "Address=%s\n", v)
		}
		for _, v := range f.DNS {
			fmt.Fprintf(&b, "DNS=%s\n", v)
		}
		if f.Gateway != "" {
			fmt.Fprintf(&b, "Gateway=%s\n", f.Gateway)
		}
	}
	yes := func(v bool) string {
		if v {
			return "yes"
		}
		return "no"
	}
	for i, f := range []IPConfig{c.IPv4, c.IPv6} {
		sectionName := []string{"DHCPv4", "DHCPv6"}[i]
		fmt.Fprintf(&b, "\n[%s]\nUseDNS=%s\n", sectionName, yes(!f.IgnoreAutoDNS))
		if i == 0 {
			fmt.Fprintf(&b, "UseGateway=%s\n", yes(!f.NeverDefault))
		}
		if i == 0 && f.Metric >= 0 {
			fmt.Fprintf(&b, "RouteMetric=%d\n", f.Metric)
		}
		if i == 0 {
			fmt.Fprintf(&b, "UseMTU=%s\n", yes(c.MTU == 0))
			for _, s := range sections {
				if s.name == "DHCP" || s.name == "DHCPv4" {
					if v := last(s, "ClientIdentifier"); v != "" {
						fmt.Fprintf(&b, "ClientIdentifier=%s\n", v)
					}
				}
			}
		}
		for _, r := range f.Routes {
			fmt.Fprintf(&b, "\n[Route]\nDestination=%s\n", r.Destination)
			if r.Gateway != "" {
				fmt.Fprintf(&b, "Gateway=%s\n", r.Gateway)
			}
			if r.Metric >= 0 {
				fmt.Fprintf(&b, "Metric=%d\n", r.Metric)
			}
		}
	}
	fmt.Fprintf(&b, "\n[IPv6AcceptRA]\nUseDNS=%s\nUseGateway=%s\n", yes(!c.IPv6.IgnoreAutoDNS), yes(!c.IPv6.NeverDefault))
	if c.IPv6.Metric >= 0 {
		fmt.Fprintf(&b, "RouteMetric=%d\n", c.IPv6.Metric)
	}
	return b.String(), nil
}
