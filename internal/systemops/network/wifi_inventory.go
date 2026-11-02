package network

import (
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/godbus/dbus/v5"
)

type wifiPoint struct {
	ID        dbus.ObjectPath `json:"id"`
	SSID      string          `json:"ssid"`
	SSIDHex   string          `json:"ssidHex"`
	Security  string          `json:"security"`
	Signal    int64           `json:"signal"`
	Frequency int64           `json:"frequency"`
	BSSID     string          `json:"bssid"`
}
type wifiSaved struct {
	UUID string `json:"uuid"`
	Name string `json:"name"`
	SSID string `json:"ssid"`
}
type wifiChoice struct {
	Profile     dbus.ObjectPath
	Hash        string
	SSID        []byte
	Security    string
	AccessPoint dbus.ObjectPath
	Password    string
	Hidden      bool
}

func bytesValue(v dbus.Variant) []byte { b, _ := v.Value().([]byte); return b }
func ssidText(b []byte) string         { return strings.ToValidUTF8(string(b), "\ufffd") }
func objectPaths(v dbus.Variant) ([]dbus.ObjectPath, error) {
	if v.Value() == nil {
		return []dbus.ObjectPath{}, nil
	}
	var paths []dbus.ObjectPath
	e := dbus.Store([]any{v.Value()}, &paths)
	return paths, e
}
func wifiSecurity(p map[string]dbus.Variant) string {
	flags := num(p["WpaFlags"]) | num(p["RsnFlags"])
	switch {
	case flags&0x400 != 0:
		return "wpa3"
	case flags&0x100 != 0:
		return "wpa2"
	case flags&(0x800|0x1000) != 0:
		return "owe"
	case flags&(0x200|0x2000) != 0:
		return "enterprise"
	case num(p["Flags"])&1 != 0:
		return "unsupported"
	default:
		return "open"
	}
}
func (a *adapter) wifiPoints(path dbus.ObjectPath) ([]wifiPoint, error) {
	var aps []dbus.ObjectPath
	if e := a.call(path, nm+".Device.Wireless.GetAllAccessPoints").Store(&aps); e != nil {
		return nil, e
	}
	rows := []wifiPoint{}
	for _, ap := range aps {
		p, e := a.props(ap, nm+".AccessPoint")
		if e != nil {
			continue
		}
		raw := bytesValue(p["Ssid"])
		if len(raw) == 0 {
			continue
		}
		strength := num(p["Strength"])
		if b, ok := p["Strength"].Value().(byte); ok {
			strength = int64(b)
		}
		rows = append(rows, wifiPoint{ap, ssidText(raw), hex.EncodeToString(raw), wifiSecurity(p), strength, num(p["Frequency"]), str(p["HwAddress"])})
	}
	slices.SortFunc(rows, func(a, b wifiPoint) int {
		if a.Signal != b.Signal {
			return int(b.Signal - a.Signal)
		}
		return strings.Compare(a.SSID, b.SSID)
	})
	return rows, nil
}
func (a *adapter) getSettings(path dbus.ObjectPath) (settings, error) {
	var s settings
	e := a.call(path, nm+".Settings.Connection.GetSettings").Store(&s)
	return s, e
}
func (a *adapter) wifiSaved(p map[string]dbus.Variant) ([]wifiSaved, error) {
	paths, e := objectPaths(p["AvailableConnections"])
	if e != nil {
		return nil, e
	}
	rows := []wifiSaved{}
	for _, path := range paths {
		s, e := a.getSettings(path)
		if e != nil {
			return nil, e
		}
		if str(s["connection"]["type"]) != "802-11-wireless" || str(s["802-11-wireless"]["mode"]) == "ap" {
			continue
		}
		rows = append(rows, wifiSaved{str(s["connection"]["uuid"]), str(s["connection"]["id"]), ssidText(bytesValue(s["802-11-wireless"]["ssid"]))})
	}
	return rows, nil
}
func (a *adapter) wifiInventory(rows []map[string]any) (map[string]any, error) {
	r, e := a.radio()
	if e != nil {
		return nil, e
	}
	present := false
	for _, row := range rows {
		if row["kind"] != "wifi" {
			continue
		}
		present = true
		name, _ := row["name"].(string)
		data := map[string]any{"networks": []wifiPoint{}, "saved": []wifiSaved{}, "activeAP": "/", "lastScan": -1}
		path, p, deviceErr := a.wifiDevice(name)
		if deviceErr == nil {
			w, err := a.props(path, nm+".Device.Wireless")
			if err == nil {
				points, pe := a.wifiPoints(path)
				saved, se := a.wifiSaved(p)
				if pe == nil && se == nil {
					data = map[string]any{"networks": points, "saved": saved, "activeAP": obj(w["ActiveAccessPoint"]), "lastScan": num(w["LastScan"]), "mode": num(w["Mode"])}
					if num(w["Mode"]) == 3 {
						raw, e := nmCommand("iw", "dev", name, "station", "dump")
						if e != nil {
							return nil, e
						}
						count := 0
						for _, line := range strings.Split(string(raw), "\n") {
							if strings.HasPrefix(line, "Station ") {
								count++
							}
						}
						data["clients"] = count
					}
				}
			}
		}
		radio, e := a.adapterRadio(name)
		if errors.Is(e, errWifiPolicyUnavailable) {
			continue
		}
		if e != nil {
			return nil, e
		}
		data["enabled"], data["hardwareEnabled"] = radio.Enabled, radio.HardwareEnabled
		row["wifi"] = data
	}
	return map[string]any{"enabled": r.Enabled, "hardwareEnabled": r.HardwareEnabled, "present": present}, nil
}
func wifiCredentials(raw []byte, kind string, password any, hidden bool, ap dbus.ObjectPath) (wifiChoice, error) {
	c := wifiChoice{SSID: raw, Security: kind, AccessPoint: ap, Hidden: hidden}
	if len(raw) < 1 || len(raw) > 32 || strings.IndexByte(string(raw), 0) >= 0 {
		return c, fmt.Errorf("Wi-Fi name must contain 1 to 32 bytes")
	}
	if !slices.Contains([]string{"open", "owe", "wpa2", "wpa3"}, kind) {
		return c, fmt.Errorf("This Wi-Fi security type is not supported yet")
	}
	pass, ok := password.(string)
	if !ok || strings.IndexByte(pass, 0) >= 0 {
		return c, fmt.Errorf("Invalid Wi-Fi password")
	}
	if kind == "wpa2" || kind == "wpa3" {
		min := 8
		if kind == "wpa3" {
			min = 1
		}
		valid := len(pass) >= min && len(pass) <= 63
		if kind == "wpa2" && len(pass) == 64 {
			_, e := hex.DecodeString(pass)
			valid = e == nil
		}
		if !valid {
			return c, fmt.Errorf("Invalid Wi-Fi password length")
		}
	} else if pass != "" {
		return c, fmt.Errorf("This Wi-Fi network does not use a password")
	}
	c.Password = pass
	return c, nil
}
func (a *adapter) wifiSelection(path dbus.ObjectPath, p map[string]dbus.Variant, params map[string]any) (wifiChoice, error) {
	if value, ok := params["connection"]; ok && value != "" && value != nil {
		connection, ok := value.(string)
		if !ok {
			return wifiChoice{}, fmt.Errorf("Invalid saved Wi-Fi connection")
		}
		paths, e := objectPaths(p["AvailableConnections"])
		if e != nil {
			return wifiChoice{}, e
		}
		for _, profile := range paths {
			s, e := a.getSettings(profile)
			if e != nil {
				return wifiChoice{}, e
			}
			if str(s["connection"]["uuid"]) == connection && str(s["connection"]["type"]) == "802-11-wireless" {
				return wifiChoice{Profile: profile, Hash: signature(s)}, nil
			}
		}
		return wifiChoice{}, fmt.Errorf("Saved Wi-Fi connection is no longer available")
	}
	ap, _ := params["accessPoint"].(string)
	var raw []byte
	kind, _ := params["security"].(string)
	if ap != "" {
		points, e := a.wifiPoints(path)
		if e != nil {
			return wifiChoice{}, e
		}
		found := false
		for _, point := range points {
			if string(point.ID) == ap && params["ssidHex"] == point.SSIDHex {
				raw, _ = hex.DecodeString(point.SSIDHex)
				kind = point.Security
				found = true
				break
			}
		}
		if !found {
			return wifiChoice{}, fmt.Errorf("Wi-Fi network changed; refresh the list")
		}
	} else {
		name, ok := params["ssid"].(string)
		if !ok || !utf8.ValidString(name) {
			return wifiChoice{}, fmt.Errorf("Wi-Fi name must contain 1 to 32 bytes")
		}
		raw = []byte(name)
	}
	password, ok := params["password"]
	if !ok {
		password = ""
	}
	pathAP := dbus.ObjectPath(ap)
	if ap == "" {
		pathAP = "/"
	}
	return wifiCredentials(raw, kind, password, ap == "", pathAP)
}
func wifiConnection(c wifiChoice, name, id string) settings {
	s := settings{
		"connection":      {"id": dbus.MakeVariant(ssidText(c.SSID)), "uuid": dbus.MakeVariant(id), "type": dbus.MakeVariant("802-11-wireless"), "interface-name": dbus.MakeVariant(name), "autoconnect": dbus.MakeVariant(false)},
		"802-11-wireless": {"ssid": dbus.MakeVariant(c.SSID), "mode": dbus.MakeVariant("infrastructure"), "hidden": dbus.MakeVariant(c.Hidden)},
		"ipv4":            {"method": dbus.MakeVariant("auto"), "route-metric": dbus.MakeVariant(int64(600))},
		"ipv6":            {"method": dbus.MakeVariant("auto"), "route-metric": dbus.MakeVariant(int64(600))},
	}
	if c.Security != "open" {
		key := map[string]string{"wpa2": "wpa-psk", "wpa3": "sae", "owe": "owe"}[c.Security]
		s["802-11-wireless-security"] = map[string]dbus.Variant{"key-mgmt": dbus.MakeVariant(key)}
		if c.Password != "" {
			s["802-11-wireless-security"]["psk"] = dbus.MakeVariant(c.Password)
			s["802-11-wireless-security"]["psk-flags"] = dbus.MakeVariant(uint32(0))
		}
	}
	return s
}
