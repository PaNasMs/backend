package networknative

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type AccessPoint struct {
	ID        string `json:"id"`
	SSID      string `json:"ssid"`
	SSIDHex   string `json:"ssidHex"`
	Security  string `json:"security"`
	Signal    int    `json:"signal"`
	Frequency int    `json:"frequency"`
	BSSID     string `json:"bssid"`
}
type WifiProfile struct {
	ID       string `json:"uuid"`
	SSID     string `json:"ssid"`
	Name     string `json:"name"`
	Security string `json:"security"`
	Password string `json:"password,omitempty"`
}
type WifiState struct {
	Enabled         bool          `json:"enabled"`
	HardwareEnabled bool          `json:"hardwareEnabled"`
	Networks        []AccessPoint `json:"networks"`
	Saved           []WifiProfile `json:"saved"`
	ActiveAP        string        `json:"activeAP"`
	LastScan        int64         `json:"lastScan"`
	Mode            int           `json:"mode"`
	Clients         int           `json:"clients"`
}
type wifiConfig struct {
	Name      string        `json:"name"`
	Identity  string        `json:"identity"`
	Enabled   bool          `json:"enabled"`
	Connected bool          `json:"connected"`
	Profiles  []WifiProfile `json:"profiles"`
	Selected  string        `json:"selected"`
}

func wifiPath(name string) string { return root + "/wifi/" + name + ".json" }
func wifiSettings(name string) (wifiConfig, error) {
	c := wifiConfig{Name: name, Identity: Identity(name), Enabled: true, Connected: true, Profiles: []WifiProfile{}}
	e := read(wifiPath(name), &c)
	if os.IsNotExist(e) {
		e = nil
	}
	if e == nil && c.Identity != Identity(name) {
		e = fmt.Errorf("A network adapter was replaced; review its settings")
	}
	return c, e
}
func radio(name string) (bool, bool) {
	enabled, hardware := true, true
	paths, _ := filepath.Glob("/sys/class/net/" + name + "/phy80211/rfkill*")
	for _, p := range paths {
		b, e := os.ReadFile(p + "/soft")
		enabled = enabled && e == nil && strings.TrimSpace(string(b)) == "0"
		b, e = os.ReadFile(p + "/hard")
		hardware = hardware && e == nil && strings.TrimSpace(string(b)) == "0"
	}
	return enabled, hardware
}
func setRadio(name string, enabled bool) error {
	paths, _ := filepath.Glob("/sys/class/net/" + name + "/phy80211/rfkill*")
	for _, p := range paths {
		n, e := strconv.ParseUint(strings.TrimPrefix(filepath.Base(p), "rfkill"), 10, 32)
		if e != nil {
			return e
		}
		f, e := os.OpenFile("/dev/rfkill", os.O_WRONLY, 0)
		if e != nil {
			return e
		}
		b := make([]byte, 8)
		binary.LittleEndian.PutUint32(b, uint32(n))
		b[4] = 1
		b[5] = 2
		if !enabled {
			b[6] = 1
		}
		_, e = f.Write(b)
		f.Close()
		if e != nil {
			return e
		}
	}
	return nil
}
func wpa(name, request string) ([]byte, error) {
	dir, e := os.MkdirTemp("/run", "panasms-wpa-")
	if e != nil {
		return nil, e
	}
	defer os.RemoveAll(dir)
	c, e := net.DialUnix("unixgram", &net.UnixAddr{Name: dir + "/client", Net: "unixgram"}, &net.UnixAddr{Name: "/run/wpa_supplicant/" + name, Net: "unixgram"})
	if e != nil {
		return nil, e
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, e = c.Write([]byte(request)); e != nil {
		return nil, e
	}
	b := make([]byte, 65536)
	n, e := c.Read(b)
	if e != nil {
		return nil, e
	}
	if strings.HasPrefix(string(b[:n]), "FAIL") {
		return nil, fmt.Errorf("Wi-Fi control request failed")
	}
	return b[:n], nil
}
func parseScan(raw []byte) []AccessPoint {
	rows := []AccessPoint{}
	var p *AccessPoint
	privacy, rsn, wpa1, sae, owe, eap := false, false, false, false, false, false
	flush := func() {
		if p == nil || p.SSID == "" {
			return
		}
		switch {
		case eap:
			p.Security = "enterprise"
		case sae:
			p.Security = "wpa3"
		case owe:
			p.Security = "owe"
		case rsn:
			p.Security = "wpa2"
		case wpa1:
			p.Security = "wpa1"
		case privacy:
			p.Security = "wep"
		default:
			p.Security = "open"
		}
		p.SSIDHex = hex.EncodeToString([]byte(p.SSID))
		rows = append(rows, *p)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		l := strings.TrimSpace(line)
		if strings.HasPrefix(l, "BSS ") {
			flush()
			mac := strings.Fields(strings.TrimPrefix(l, "BSS "))[0]
			mac = strings.Split(mac, "(")[0]
			p = &AccessPoint{ID: mac, BSSID: mac}
			privacy, rsn, wpa1, sae, owe, eap = false, false, false, false, false, false
			continue
		}
		if p == nil {
			continue
		}
		switch {
		case strings.HasPrefix(l, "SSID: "):
			p.SSID = decodeSSID(strings.TrimPrefix(l, "SSID: "))
		case strings.HasPrefix(l, "freq: "):
			frequency, _ := strconv.ParseFloat(strings.TrimPrefix(l, "freq: "), 64)
			p.Frequency = int(frequency)
		case strings.HasPrefix(l, "signal: "):
			var dbm float64
			fmt.Sscanf(l, "signal: %f", &dbm)
			p.Signal = max(0, min(100, int(2*(dbm+100))))
		case strings.HasPrefix(l, "capability:"):
			privacy = strings.Contains(l, "Privacy")
		case strings.HasPrefix(l, "RSN:"):
			rsn = true
		case strings.HasPrefix(l, "WPA:"):
			wpa1 = true
		case strings.Contains(l, "Authentication suites:"):
			sae = strings.Contains(l, "SAE")
			owe = strings.Contains(l, "OWE")
			eap = strings.Contains(l, "IEEE 802.1X")
		}
	}
	flush()
	slices.SortFunc(rows, func(a, b AccessPoint) int { return b.Signal - a.Signal })
	return rows
}
func decodeSSID(s string) string {
	var b strings.Builder
	for len(s) > 0 {
		if len(s) >= 4 && s[:2] == `\x` {
			v, e := hex.DecodeString(s[2:4])
			if e == nil {
				b.Write(v)
				s = s[4:]
				continue
			}
		}
		b.WriteByte(s[0])
		s = s[1:]
	}
	return b.String()
}
func Wifi(name string) (WifiState, error) {
	c, e := wifiSettings(name)
	if e != nil {
		return WifiState{}, e
	}
	soft, hard := radio(name)
	w := WifiState{Enabled: c.Enabled && soft, HardwareEnabled: hard, Networks: []AccessPoint{}, Saved: []WifiProfile{}, ActiveAP: "/", LastScan: -1, Mode: 2}
	_ = read(root+"/scan/"+name+".json", &w.Networks)
	if info, e := os.Stat(root + "/scan/" + name + ".json"); e == nil {
		w.LastScan = info.ModTime().UnixMilli()
	}
	for _, p := range c.Profiles {
		p.Password = ""
		w.Saved = append(w.Saved, p)
	}
	if raw, e := wpa(name, "STATUS"); e == nil {
		state := fields(raw)
		if state["wpa_state"] == "COMPLETED" {
			w.ActiveAP = state["bssid"]
		}
	}
	raw, _ := invoke("iw", "dev", name, "info")
	if strings.Contains(string(raw), "type AP") {
		w.Mode = 3
		raw, e = invoke("iw", "dev", name, "station", "dump")
		if e != nil {
			w.Clients = -1
		} else {
			w.Clients = strings.Count(string(raw), "Station ")
		}
	}
	return w, nil
}
func Scan(name string) error {
	if !Wireless(name) {
		return fmt.Errorf("Select a Wi-Fi adapter")
	}
	c, e := wifiSettings(name)
	if e != nil {
		return e
	}
	soft, hard := radio(name)
	if !c.Enabled || !soft || !hard {
		return fmt.Errorf("Enable Wi-Fi before scanning")
	}
	if e = run("ip", "link", "set", "dev", name, "up"); e != nil {
		return e
	}
	raw, e := invoke("iw", "dev", name, "scan")
	if e != nil {
		return fmt.Errorf("Wi-Fi scan is unavailable; try again shortly")
	}
	return write(root+"/scan/"+name+".json", parseScan(raw))
}
func selectWifi(c wifiConfig, p map[string]any) (WifiProfile, error) {
	if id, _ := p["connection"].(string); id != "" {
		for _, v := range c.Profiles {
			if v.ID == id {
				return v, nil
			}
		}
		return WifiProfile{}, fmt.Errorf("Saved Wi-Fi connection is no longer available")
	}
	v := WifiProfile{}
	v.SSID, _ = p["ssid"].(string)
	v.Security, _ = p["security"].(string)
	v.Password, _ = p["password"].(string)
	if ap, _ := p["accessPoint"].(string); ap != "" {
		var rows []AccessPoint
		if e := read(root+"/scan/"+c.Name+".json", &rows); e != nil {
			return v, e
		}
		found := false
		for _, row := range rows {
			if row.ID == ap && row.SSIDHex == p["ssidHex"] {
				v.SSID, v.Security = row.SSID, row.Security
				found = true
				break
			}
		}
		if !found {
			return v, fmt.Errorf("Wi-Fi network changed; refresh the list")
		}
	}
	if len(v.SSID) < 1 || len(v.SSID) > 32 || strings.ContainsAny(v.SSID, "\x00\r\n") {
		return v, fmt.Errorf("Wi-Fi name must contain 1 to 32 bytes")
	}
	switch v.Security {
	case "open", "owe":
		if v.Password != "" {
			return v, fmt.Errorf("This network does not use a password")
		}
	case "wpa2", "wpa3":
		minLength := 8
		if v.Security == "wpa3" {
			minLength = 1
		}
		if strings.ContainsAny(v.Password, "\x00\r\n") || ((len(v.Password) < minLength || len(v.Password) > 63) && !(v.Security == "wpa2" && regexp.MustCompile(`^[a-fA-F0-9]{64}$`).MatchString(v.Password))) {
			return v, fmt.Errorf("Invalid Wi-Fi password length")
		}
	default:
		return v, fmt.Errorf("This Wi-Fi security type is not supported yet")
	}
	v.ID = hash([]string{v.SSID, v.Security})[:24]
	v.Name = v.SSID
	return v, nil
}
func wifiNetplanPath(name string) string { return "/etc/netplan/90-panasms-wifi-" + name + ".yaml" }
func wifiID(name string) string          { return name }
func wifiFiles(c wifiConfig) (map[string]*string, error) {
	if len(c.Profiles) == 0 {
		return map[string]*string{}, nil
	}
	var b strings.Builder
	b.WriteString("ctrl_interface=/run/wpa_supplicant\nupdate_config=0\n")
	for _, p := range c.Profiles {
		if p.ID != c.Selected {
			continue
		}
		fmt.Fprintf(&b, "network={\n ssid=%s\n scan_ssid=1\n", hex.EncodeToString([]byte(p.SSID)))
		if p.ID == c.Selected {
			b.WriteString(" priority=10\n")
		}
		switch p.Security {
		case "open":
			b.WriteString(" key_mgmt=NONE\n")
		case "owe":
			b.WriteString(" key_mgmt=OWE\n ieee80211w=2\n")
		case "wpa3":
			fmt.Fprintf(&b, " key_mgmt=SAE\n ieee80211w=2\n sae_password=%s\n", strconv.Quote(p.Password))
		case "wpa2":
			psk := strconv.Quote(p.Password)
			if len(p.Password) == 64 {
				psk = p.Password
			}
			fmt.Fprintf(&b, " key_mgmt=WPA-PSK\n psk=%s\n", psk)
		}
		b.WriteString("}\n")
	}
	files := map[string]*string{"/etc/wpa_supplicant/panasms-" + c.Name + ".conf": text(b.String())}
	if Netplan() {
		node := map[string]any{"match": map[string]any{"name": c.Name}, "renderer": "networkd", "dhcp4": true, "dhcp6": true, "optional": true}
		if raw, err := os.ReadFile(wifiNetplanPath(c.Name)); err == nil {
			var doc struct {
				Network struct {
					Ethernets map[string]map[string]any `yaml:"ethernets"`
				} `yaml:"network"`
			}
			if err = yaml.Unmarshal(raw, &doc); err != nil {
				return nil, err
			}
			if saved := doc.Network.Ethernets["00-panasms-wifi-"+c.Name]; saved != nil {
				node = saved
			}
		} else if !os.IsNotExist(err) {
			return nil, err
		}
		delete(node, "activation-mode")
		if !c.Enabled || !c.Connected {
			node["activation-mode"] = "off"
		}
		raw, err := yaml.Marshal(map[string]any{"network": map[string]any{"version": 2, "ethernets": map[string]any{"00-panasms-wifi-" + c.Name: node}}})
		if err != nil {
			return nil, err
		}
		files[wifiNetplanPath(c.Name)] = text(string(raw))
	} else {
		files["/etc/systemd/network/00-panasms-wifi-"+c.Name+".network"] = text("[Match]\nName=" + c.Name + "\n[Network]\nDHCP=yes\nIPv6AcceptRA=yes\n[DHCPv4]\nRouteMetric=600\n[DHCPv6]\nRouteMetric=600\n")
		path := "/etc/systemd/network/00-panasms-wifi-" + c.Name + ".network"
		if existing, err := fileState(path); err != nil {
			return nil, err
		} else if existing != nil {
			files[path] = existing
		}
	}
	return files, nil
}
func wifiUnit(name string) string { return "panasms-wpa@" + unitInstance(name) + ".service" }

func ApplyWifi(c wifiConfig) error {
	if e := setRadio(c.Name, c.Enabled); e != nil {
		return e
	}
	files, e := wifiFiles(c)
	if e != nil {
		return e
	}
	for p, v := range files {
		if e = setFile(p, v); e != nil {
			return e
		}
	}
	if Netplan() {
		if e = run("netplan", "generate"); e != nil {
			return e
		}
	}
	if e = run("systemctl", "daemon-reload"); e != nil {
		return e
	}
	if e = run("networkctl", "reload"); e != nil {
		return e
	}
	unit := wifiUnit(c.Name)
	if !c.Enabled || !c.Connected || len(c.Profiles) == 0 {
		_ = run("systemctl", "stop", unit)
		return run("ip", "link", "set", "dev", c.Name, "down")
	}
	if e = run("ip", "link", "set", "dev", c.Name, "up"); e != nil {
		return e
	}
	if e = run("systemctl", "restart", unit); e != nil {
		return e
	}
	return run("networkctl", "reconfigure", c.Name)
}
func wifiOperation(action string, p map[string]any) (wifiConfig, error) {
	name, _ := p["interface"].(string)
	if !Wireless(name) {
		return wifiConfig{}, fmt.Errorf("Select a Wi-Fi adapter")
	}
	if e := CheckInterface(name); e != nil {
		return wifiConfig{}, e
	}
	c, e := wifiSettings(name)
	if e != nil {
		return c, e
	}
	switch action {
	case "network.wifi.radio":
		enabled, ok := p["enabled"].(bool)
		if !ok {
			return c, fmt.Errorf("Invalid network option")
		}
		_, hard := radio(name)
		if enabled && !hard {
			return c, fmt.Errorf("Wi-Fi is blocked by a hardware switch")
		}
		c.Enabled = enabled
	case "network.wifi.disconnect":
		c.Connected = false
	case "network.wifi.connect":
		soft, hard := radio(name)
		if !c.Enabled || !soft || !hard {
			return c, fmt.Errorf("Enable Wi-Fi before connecting")
		}
		v, e := selectWifi(c, p)
		if e != nil {
			return c, e
		}
		c.Profiles = slices.DeleteFunc(c.Profiles, func(x WifiProfile) bool { return x.ID == v.ID })
		c.Profiles = append(c.Profiles, v)
		c.Selected = v.ID
		c.Connected = true
	case "network.wifi.scan":
	default:
		return c, fmt.Errorf("Unknown Wi-Fi operation")
	}
	return c, nil
}

func applyRadioOrWifi(c wifiConfig) error {
	groups, err := Groups()
	if err != nil {
		return err
	}
	for _, g := range groups {
		if ap, ok := g.Wifi[c.Name]; ok && g.Enabled {
			if c.Enabled {
				return StartAP(c.Name, g.Bridge, ap)
			}
			if err := StopAP(c.Name); err != nil {
				return err
			}
			if err := setRadio(c.Name, false); err != nil {
				return err
			}
			return run("ip", "link", "set", "dev", c.Name, "down")
		}
	}
	return ApplyWifi(c)
}
