package network

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/godbus/dbus/v5"
	"panasms.local/backend/internal/systemops/networkd"
)

const nm = "org.freedesktop.NetworkManager"
const nmPath = dbus.ObjectPath("/org/freedesktop/NetworkManager")

type settings map[string]map[string]dbus.Variant
type adapter struct{ bus *dbus.Conn }

func connect() (*adapter, error) {
	b, e := dbus.ConnectSystemBus()
	if e != nil {
		return nil, e
	}
	var exists bool
	e = b.BusObject().Call("org.freedesktop.DBus.NameHasOwner", 0, nm).Store(&exists)
	if e != nil || !exists {
		b.Close()
		return nil, fmt.Errorf("NetworkManager is not running")
	}
	return &adapter{b}, nil
}
func (a *adapter) call(p dbus.ObjectPath, method string, args ...any) *dbus.Call {
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	return a.bus.Object(nm, p).CallWithContext(ctx, method, 0, args...)
}
func (a *adapter) props(p dbus.ObjectPath, iface string) (map[string]dbus.Variant, error) {
	var v map[string]dbus.Variant
	err := a.call(p, "org.freedesktop.DBus.Properties.GetAll", iface).Store(&v)
	return v, err
}
func str(v dbus.Variant) string          { s, _ := v.Value().(string); return s }
func obj(v dbus.Variant) dbus.ObjectPath { p, _ := v.Value().(dbus.ObjectPath); return p }
func num(v dbus.Variant) int64 {
	switch n := v.Value().(type) {
	case uint32:
		return int64(n)
	case uint64:
		return int64(n)
	case int64:
		return n
	case int32:
		return int64(n)
	}
	return 0
}
func boolean(v dbus.Variant) bool { b, _ := v.Value().(bool); return b }
func dictionaries(v dbus.Variant) []map[string]dbus.Variant {
	var out []map[string]dbus.Variant
	if v.Value() == nil {
		return out
	}
	_ = dbus.Store([]any{v.Value()}, &out)
	return out
}
func (a *adapter) device(name string) (dbus.ObjectPath, map[string]dbus.Variant, error) {
	var p dbus.ObjectPath
	if !validName.MatchString(name) {
		return p, nil, fmt.Errorf("Invalid network interface")
	}
	e := a.call(nmPath, nm+".GetDeviceByIpIface", name).Store(&p)
	if e != nil {
		return p, nil, e
	}
	v, e := a.props(p, nm+".Device")
	if e == nil && str(v["Interface"]) != name {
		e = fmt.Errorf("Network interface changed")
	}
	return p, v, e
}
func (a *adapter) active(name string) (dbus.ObjectPath, dbus.ObjectPath, settings, settings, uint64, error) {
	p, v, e := a.device(name)
	if e != nil {
		return p, "", nil, nil, 0, e
	}
	if !boolean(v["Managed"]) || num(v["State"]) != 100 {
		return p, "", nil, nil, 0, fmt.Errorf("Select a connected interface managed by NetworkManager")
	}
	active, e := a.props(obj(v["ActiveConnection"]), nm+".Connection.Active")
	if e != nil {
		return p, "", nil, nil, 0, e
	}
	profile := obj(active["Connection"])
	var saved, applied settings
	var version uint64
	if e = a.call(profile, nm+".Settings.Connection.GetSettings").Store(&saved); e != nil {
		return p, profile, nil, nil, 0, e
	}
	e = a.call(p, nm+".Device.GetAppliedConnection", uint32(0)).Store(&applied, &version)
	return p, profile, saved, applied, version, e
}
func publicIP(s settings, family int) networkd.IPConfig {
	d := s["ipv"+strconv.Itoa(family)]
	c := networkd.IPConfig{Method: str(d["method"]), Addresses: []string{}, DNS: []string{}, Routes: []networkd.Route{}, Gateway: str(d["gateway"]), IgnoreAutoDNS: boolean(d["ignore-auto-dns"]), NeverDefault: boolean(d["never-default"]), Metric: -1}
	if c.Method == "" {
		c.Method = "auto"
	}
	if _, ok := d["route-metric"]; ok {
		c.Metric = num(d["route-metric"])
	}
	for _, v := range dictionaries(d["address-data"]) {
		c.Addresses = append(c.Addresses, fmt.Sprintf("%s/%d", str(v["address"]), num(v["prefix"])))
	}
	for _, v := range dictionaries(d["route-data"]) {
		r := networkd.Route{Destination: fmt.Sprintf("%s/%d", str(v["dest"]), num(v["prefix"])), Gateway: str(v["next-hop"]), Metric: -1}
		if _, ok := v["metric"]; ok {
			r.Metric = num(v["metric"])
		}
		c.Routes = append(c.Routes, r)
	}
	if family == 4 {
		var v []uint32
		if d["dns"].Value() != nil {
			_ = dbus.Store([]any{d["dns"].Value()}, &v)
		}
		for _, n := range v {
			b := make([]byte, 4)
			binary.NativeEndian.PutUint32(b, n)
			c.DNS = append(c.DNS, net.IP(b).String())
		}
	} else {
		var v [][]byte
		if d["dns"].Value() != nil {
			_ = dbus.Store([]any{d["dns"].Value()}, &v)
		}
		for _, b := range v {
			c.DNS = append(c.DNS, net.IP(b).String())
		}
	}
	return c
}
func config(s settings) networkd.Config {
	return networkd.Config{IPv4: publicIP(s, 4), IPv6: publicIP(s, 6), MTU: int(num(s[str(s["connection"]["type"])]["mtu"]))}
}
func editable(s settings) bool {
	kind := str(s["connection"]["type"])
	if kind != "802-3-ethernet" && kind != "802-11-wireless" {
		return false
	}
	for _, f := range []string{"ipv4", "ipv6"} {
		d := s[f]
		m := str(d["method"])
		if !strings.Contains(" auto manual disabled ignore link-local ", " "+m+" ") {
			return false
		}
		if _, ok := d["dns-data"]; ok {
			return false
		}
		for _, field := range []string{"address-data", "route-data"} {
			allowed := " address prefix "
			if field == "route-data" {
				allowed = " dest prefix next-hop metric "
			}
			for _, row := range dictionaries(d[field]) {
				for k := range row {
					if !strings.Contains(allowed, " "+k+" ") {
						return false
					}
				}
			}
		}
	}
	return true
}
func patched(s settings, c networkd.Config) settings {
	out := settings{}
	for k, row := range s {
		out[k] = map[string]dbus.Variant{}
		for k2, v := range row {
			out[k][k2] = v
		}
	}
	for i, v := range []networkd.IPConfig{c.IPv4, c.IPv6} {
		family := 4 + i*2
		k := "ipv" + strconv.Itoa(family)
		d := out[k]
		if d == nil {
			d = map[string]dbus.Variant{}
			out[k] = d
		}
		for _, key := range []string{"addresses", "routes", "dns-data", "gateway"} {
			delete(d, key)
		}
		d["method"] = dbus.MakeVariant(v.Method)
		d["ignore-auto-dns"] = dbus.MakeVariant(v.IgnoreAutoDNS)
		d["never-default"] = dbus.MakeVariant(v.NeverDefault)
		d["route-metric"] = dbus.MakeVariant(v.Metric)
		addresses := []map[string]dbus.Variant{}
		for _, v := range v.Addresses {
			p, _ := netip.ParsePrefix(v)
			addresses = append(addresses, map[string]dbus.Variant{"address": dbus.MakeVariant(p.Addr().String()), "prefix": dbus.MakeVariant(uint32(p.Bits()))})
		}
		d["address-data"] = dbus.MakeVariant(addresses)
		routes := []map[string]dbus.Variant{}
		for _, r := range v.Routes {
			p, _ := netip.ParsePrefix(r.Destination)
			row := map[string]dbus.Variant{"dest": dbus.MakeVariant(p.Addr().String()), "prefix": dbus.MakeVariant(uint32(p.Bits()))}
			if r.Gateway != "" {
				row["next-hop"] = dbus.MakeVariant(r.Gateway)
			}
			if r.Metric >= 0 {
				row["metric"] = dbus.MakeVariant(uint32(r.Metric))
			}
			routes = append(routes, row)
		}
		d["route-data"] = dbus.MakeVariant(routes)
		if v.Gateway != "" {
			d["gateway"] = dbus.MakeVariant(v.Gateway)
		}
		if family == 4 {
			dns := []uint32{}
			for _, v := range v.DNS {
				dns = append(dns, binary.NativeEndian.Uint32(net.ParseIP(v).To4()))
			}
			d["dns"] = dbus.MakeVariant(dns)
		} else {
			dns := [][]byte{}
			for _, v := range v.DNS {
				dns = append(dns, []byte(net.ParseIP(v).To16()))
			}
			d["dns"] = dbus.MakeVariant(dns)
		}
	}
	kind := str(s["connection"]["type"])
	if out[kind] == nil {
		out[kind] = map[string]dbus.Variant{}
	}
	out[kind]["mtu"] = dbus.MakeVariant(uint32(c.MTU))
	return out
}
func signature(s settings) string {
	out := map[string]map[string]any{}
	for k, row := range s {
		out[k] = map[string]any{}
		for key, v := range row {
			if k != "connection" || key != "timestamp" {
				out[k][key] = plain(v.Value())
			}
		}
	}
	return digest(out)
}
func (a *adapter) checkpoints() ([]dbus.ObjectPath, error) {
	v, e := a.props(nmPath, nm)
	if e != nil {
		return nil, e
	}
	var paths []dbus.ObjectPath
	e = dbus.Store([]any{v["Checkpoints"].Value()}, &paths)
	return paths, e
}
func (a *adapter) rollback(p dbus.ObjectPath) error {
	var result map[string]uint32
	if e := a.call(nmPath, nm+".CheckpointRollback", p).Store(&result); e != nil {
		return e
	}
	for _, v := range result {
		if v != 0 {
			return fmt.Errorf("Network rollback could not restore every interface; check the local console")
		}
	}
	return nil
}
func (a *adapter) persist(s settings, c networkd.Config) error {
	args := []string{"nmcli", "--wait", "30", "connection", "modify", "uuid", str(s["connection"]["uuid"])}
	for i, f := range []networkd.IPConfig{c.IPv4, c.IPv6} {
		prefix := "ipv" + strconv.Itoa(4+i*2) + "."
		routes := []string{}
		for _, r := range f.Routes {
			v := r.Destination
			if r.Gateway != "" || r.Metric >= 0 {
				g := r.Gateway
				if g == "" {
					g = "0.0.0.0"
					if i == 1 {
						g = "::"
					}
				}
				v += " " + g
			}
			if r.Metric >= 0 {
				v += " " + strconv.FormatInt(r.Metric, 10)
			}
			routes = append(routes, v)
		}
		fields := [][2]string{{"method", f.Method}, {"addresses", strings.Join(f.Addresses, ",")}, {"gateway", f.Gateway}, {"dns", strings.Join(f.DNS, ",")}, {"ignore-auto-dns", strconv.FormatBool(f.IgnoreAutoDNS)}, {"never-default", strconv.FormatBool(f.NeverDefault)}, {"route-metric", strconv.FormatInt(f.Metric, 10)}, {"routes", strings.Join(routes, ",")}}
		for _, kv := range fields {
			args = append(args, prefix+kv[0], kv[1])
		}
	}
	args = append(args, str(s["connection"]["type"])+".mtu", strconv.Itoa(c.MTU))
	_, e := command(args...)
	return e
}

func plain(value any) any {
	if v, ok := value.(dbus.Variant); ok {
		return plain(v.Value())
	}
	v := reflect.ValueOf(value)
	if !v.IsValid() {
		return nil
	}
	switch v.Kind() {
	case reflect.Map:
		out := map[string]any{}
		iter := v.MapRange()
		for iter.Next() {
			out[fmt.Sprint(iter.Key().Interface())] = plain(iter.Value().Interface())
		}
		return out
	case reflect.Slice, reflect.Array:
		out := make([]any, v.Len())
		for i := range out {
			out[i] = plain(v.Index(i).Interface())
		}
		return out
	}
	return value
}
