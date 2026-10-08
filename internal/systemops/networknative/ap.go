package networknative

import (
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type APConfig struct {
	SSID     string `json:"ssid"`
	Password string `json:"password,omitempty"`
	Band     string `json:"band"`
	Channel  int    `json:"channel"`
}
type Capabilities struct {
	Available  bool             `json:"available"`
	AP         bool             `json:"ap"`
	Bands      []string         `json:"bands"`
	Channels   map[string][]int `json:"channels"`
	Phy        string           `json:"phy"`
	Identity   string           `json:"identity"`
	Concurrent bool             `json:"concurrent"`
}

var channelLine = regexp.MustCompile(`\* (\d+)(?:\.\d+)? MHz \[(\d+)\]`)

func Channels(raw string) map[string][]int {
	m := map[string][]int{}
	for _, line := range strings.Split(raw, "\n") {
		v := channelLine.FindStringSubmatch(line)
		if v == nil || strings.Contains(line, "disabled") || strings.Contains(line, "no IR") || strings.Contains(line, "radar detection") {
			continue
		}
		f, _ := strconv.Atoi(v[1])
		c, _ := strconv.Atoi(v[2])
		band := ""
		if f > 2400 && f < 2500 && c >= 1 && c <= 13 {
			band = "bg"
		}
		if f > 5000 && f < 5900 && ((c >= 36 && c <= 64 && c%4 == 0) || (c >= 100 && c <= 144 && c%4 == 0) || (c >= 149 && c <= 177 && (c-149)%4 == 0)) {
			band = "a"
		}
		if band != "" {
			m[band] = append(m[band], c)
		}
	}
	return m
}
func Capability(name string) Capabilities {
	c := Capabilities{Available: CheckInterface(name) == nil, Identity: Identity(name), Bands: []string{}, Channels: map[string][]int{}}
	if !Wireless(name) {
		return c
	}
	p, _ := filepath.EvalSymlinks("/sys/class/net/" + name + "/phy80211")
	c.Phy = filepath.Base(p)
	raw, e := invoke("iw", "phy", c.Phy, "info")
	if e != nil {
		return c
	}
	for _, l := range strings.Split(string(raw), "\n") {
		if strings.TrimSpace(l) == "* AP" {
			c.AP = true
		}
	}
	c.Channels = Channels(string(raw))
	for _, b := range []string{"bg", "a"} {
		if len(c.Channels[b]) > 0 {
			c.Bands = append(c.Bands, b)
		}
	}
	c.AP = c.AP && len(c.Bands) > 0
	return c
}
func validateAP(name string, c APConfig) (APConfig, error) {
	cap := Capability(name)
	if !cap.AP {
		return c, fmt.Errorf("This Wi-Fi adapter cannot create an access point on permitted channels")
	}
	if c.Band == "auto" {
		c.Band = cap.Bands[0]
	}
	if !slices.Contains(cap.Bands, c.Band) {
		return c, fmt.Errorf("This Wi-Fi band is not available for an access point")
	}
	if c.Channel == 0 {
		c.Channel = cap.Channels[c.Band][0]
	}
	if !slices.Contains(cap.Channels[c.Band], c.Channel) {
		return c, fmt.Errorf("This Wi-Fi channel is not available for an access point")
	}
	if len(c.SSID) < 1 || len(c.SSID) > 32 || strings.ContainsAny(c.SSID, "\x00\r\n") {
		return c, fmt.Errorf("Wi-Fi name must contain 1 to 32 bytes")
	}
	if len(c.Password) < 8 || len(c.Password) > 63 {
		return c, fmt.Errorf("Use a Wi-Fi password of 8 to 63 printable ASCII characters")
	}
	for _, r := range c.Password {
		if r < 32 || r > 126 {
			return c, fmt.Errorf("Use a Wi-Fi password of 8 to 63 printable ASCII characters")
		}
	}
	_, hard := radio(name)
	if !hard {
		return c, fmt.Errorf("Wi-Fi is blocked by a hardware switch")
	}
	return c, nil
}
func hostapdConfig(name, bridge string, c APConfig) string {
	mode := "g"
	if c.Band == "a" {
		mode = "a"
	}
	bridgeLine := ""
	if bridge != "" {
		bridgeLine = "bridge=" + bridge + "\n"
	}
	return fmt.Sprintf("interface=%s\ndriver=nl80211\n%s\nctrl_interface=/run/panasms-hostapd\nssid2=%s\nhw_mode=%s\nchannel=%d\nwpa=2\nwpa_key_mgmt=WPA-PSK\nrsn_pairwise=CCMP\nwpa_passphrase=%s\n", name, bridgeLine, hex.EncodeToString([]byte(c.SSID)), mode, c.Channel, c.Password)
}
func apPath(name string) string { return "/etc/panasms/network/hostapd-" + name + ".conf" }
func apUnit(name string) string { return "panasms-hostapd@" + unitInstance(name) + ".service" }
func StartAP(name, bridge string, c APConfig) error {
	var e error
	c, e = validateAP(name, c)
	if e != nil {
		return e
	}
	if e = setFile(apPath(name), text(hostapdConfig(name, bridge, c))); e != nil {
		return e
	}
	if e = setRadio(name, true); e != nil {
		return e
	}
	_ = run("systemctl", "stop", wifiUnit(name))
	_ = run("systemctl", "stop", "wpa_supplicant@"+unitInstance(name)+".service")
	if e = run("ip", "link", "set", "dev", name, "up"); e != nil {
		return e
	}
	return run("systemctl", "restart", apUnit(name))
}
func StopAP(name string) error {
	if e := run("systemctl", "stop", apUnit(name)); e != nil {
		return e
	}
	return setFile(apPath(name), nil)
}
func APActive(name string) bool { return run("systemctl", "is-active", "--quiet", apUnit(name)) == nil }
func ApplyNetwork() error {
	if Netplan() {
		if e := run("netplan", "generate"); e != nil {
			return e
		}
	}
	if e := run("systemctl", "daemon-reload"); e != nil {
		return e
	}
	return run("networkctl", "reload")
}
func dnsConfig(name, addr string) (string, error) {
	ip, network, e := net.ParseCIDR(addr)
	if e != nil || ip.To4() == nil {
		return "", fmt.Errorf("Invalid sharing subnet")
	}
	ip = ip.To4()
	base := network.IP.To4()
	start, end := append(net.IP{}, base...), append(net.IP{}, base...)
	start[3] += 20
	end[3] += 200
	return fmt.Sprintf("interface=%s\nexcept-interface=lo\nbind-dynamic\nlisten-address=%s\ndhcp-range=%s,%s,255.255.255.0,12h\ndhcp-option=option:router,%s\ndhcp-option=option:dns-server,%s\ndhcp-leasefile=/run/panasms-dnsmasq-%s.leases\ndomain-needed\nbogus-priv\n", name, ip.String(), start.String(), end.String(), ip.String(), ip.String(), name), nil
}
func directFile(id string) string {
	if Netplan() {
		return "/etc/netplan/99-panasms-direct-" + id + ".yaml"
	}
	return "/etc/systemd/network/00-panasms-direct-" + id + ".network"
}
func DirectStart(id, name, addr string, ap *APConfig) (result error) {
	var e error
	if !validName.MatchString(name) || !regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`).MatchString(id) {
		return fmt.Errorf("Invalid direct network interface")
	}
	var content string
	if Netplan() {
		raw, e := yaml.Marshal(map[string]any{"network": map[string]any{"version": 2, "ethernets": map[string]any{"00-panasms-direct-" + id: map[string]any{"match": map[string]string{"name": name}, "renderer": "networkd", "addresses": []string{addr}, "dhcp4": false, "dhcp6": false, "accept-ra": false, "optional": true}}}})
		if e != nil {
			return e
		}
		content = string(raw)
	} else {
		content = "[Match]\nName=" + name + "\n[Network]\nAddress=" + addr + "\nDHCP=no\nIPv6AcceptRA=no\n"
	}
	if e = validateFiles(map[string]*string{directFile(id): text(content)}); e != nil {
		return e
	}
	previous, e := fileState(directFile(id))
	if e != nil {
		return e
	}
	defer func() {
		if result == nil {
			return
		}
		if previous == nil {
			if rollback := DirectStop(id, name); rollback != nil {
				result = fmt.Errorf("%v; direct access recovery failed: %w", result, rollback)
			}
		} else {
			if rollback := setFile(directFile(id), previous); rollback != nil {
				result = fmt.Errorf("%v; direct access configuration recovery failed: %w", result, rollback)
			}
		}
	}()
	if e = setFile(directFile(id), text(content)); e != nil {
		return e
	}
	if e = ApplyNetwork(); e != nil {
		return e
	}
	if e = run("ip", "link", "set", "dev", name, "up"); e != nil {
		return e
	}
	if e = run("networkctl", "reconfigure", name); e != nil {
		return e
	}
	conf, e := dnsConfig(name, addr)
	if e != nil {
		return e
	}
	if e = setFile("/etc/panasms/network/dnsmasq-"+name+".conf", text(conf)); e != nil {
		return e
	}
	if e = run("systemctl", "restart", dnsUnit(name)); e != nil {
		return e
	}
	if ap != nil {
		return StartAP(name, "", *ap)
	}
	return nil
}
func DirectStop(id, name string) error {
	if !validName.MatchString(name) || !regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`).MatchString(id) {
		return fmt.Errorf("Invalid direct network interface")
	}
	_ = run("systemctl", "stop", dnsUnit(name))
	if APActive(name) {
		if e := StopAP(name); e != nil {
			return e
		}
	}
	if e := setFile(directFile(id), nil); e != nil {
		return e
	}
	if e := ApplyNetwork(); e != nil {
		return e
	}
	if Wireless(name) {
		c, e := wifiSettings(name)
		if e != nil {
			return e
		}
		return ApplyWifi(c)
	}
	return run("networkctl", "reconfigure", name)
}
func DirectActive(id string) bool { return exists(directFile(id)) }
func DirectInterface(id string) string {
	b, _ := os.ReadFile(directFile(id))
	if Netplan() {
		var d struct {
			Network struct {
				Ethernets map[string]struct {
					Match struct {
						Name string `yaml:"name"`
					} `yaml:"match"`
				} `yaml:"ethernets"`
			} `yaml:"network"`
		}
		if yaml.Unmarshal(b, &d) == nil {
			for _, v := range d.Network.Ethernets {
				return v.Match.Name
			}
		}
	}
	return fields(b)["Name"]
}
