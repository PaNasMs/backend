package oled

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"panasms.local/backend/internal/system"
)

type Disk struct {
	Label       string
	Temperature *float64
}
type Snapshot struct {
	BootSeconds float64
	Host, IP    string
	CPU         *float64
	Disks       []Disk
	Uptime      string
}

func ReadSnapshot(s Settings) Snapshot {
	var data Snapshot
	data.Host, _ = os.Hostname()
	if s.ShowIP || s.ShowEvents {
		data.IP = primaryIP()
	}
	if s.ShowCPU {
		data.CPU = system.CPUTemperature()
	}
	if s.ShowDisks {
		const path = "/run/panasms-cooling/status.json"
		temperatures := system.ReadDiskTemperatures(path, time.Now())
		raw, _ := os.ReadFile(path)
		var status struct {
			Disks []struct {
				Device string `json:"device"`
			} `json:"disks"`
		}
		_ = json.Unmarshal(raw, &status)
		for _, d := range status.Disks {
			label := d.Device
			if resolved, e := filepath.EvalSymlinks(label); e == nil {
				label = resolved
			}
			disk := Disk{Label: filepath.Base(label)}
			if value, ok := temperatures[d.Device]; ok {
				disk.Temperature = &value
			}
			data.Disks = append(data.Disks, disk)
		}
		sort.Slice(data.Disks, func(i, j int) bool { return data.Disks[i].Label < data.Disks[j].Label })
	}
	{
		raw, _ := os.ReadFile("/proc/uptime")
		fields := strings.Fields(string(raw))
		if len(fields) > 0 {
			seconds, e := strconv.ParseFloat(fields[0], 64)
			if e == nil {
				data.BootSeconds = seconds
				minutes := int64(seconds) / 60
				data.Uptime = fmt.Sprintf("%dD %02d:%02d", minutes/1440, minutes/60%24, minutes%60)
			}
		}
	}
	return data
}
func lines(s Settings, host, ip string, cpu *float64, disks map[string]float64) []string {
	result := []string{host}
	if s.ShowIP {
		if ip == "" {
			ip = "--"
		}
		value := "IP " + ip
		if len(value) > 20 {
			result = append(result, ip[:min(20, len(ip))], ip[min(20, len(ip)):])
		} else {
			result = append(result, value)
		}
	}
	if s.ShowCPU {
		result = append(result, "CPU "+temperature(cpu))
	}
	if s.ShowDisks {
		var max *float64
		for _, v := range disks {
			if max == nil || v > *max {
				t := v
				max = &t
			}
		}
		result = append(result, "HDD MAX "+temperature(max))
	}
	return result
}
func temperature(v *float64) string {
	if v == nil {
		return "--"
	}
	return fmt.Sprintf("%.1f C", *v)
}
func primaryIP() string {
	type route struct {
		name   string
		metric int
	}
	var routes []route
	raw, _ := os.ReadFile("/proc/net/route")
	for _, row := range strings.Split(string(raw), "\n") {
		f := strings.Fields(row)
		if len(f) < 8 || f[1] != "00000000" {
			continue
		}
		metric, e := strconv.Atoi(f[6])
		if e == nil {
			routes = append(routes, route{f[0], metric})
		}
	}
	sort.SliceStable(routes, func(i, j int) bool { return routes[i].metric < routes[j].metric })
	interfaces, _ := net.Interfaces()
	names := []string{}
	for _, r := range routes {
		names = append(names, r.name)
	}
	for _, iface := range interfaces {
		if _, e := os.Stat("/sys/class/net/" + iface.Name + "/device"); e == nil {
			names = append(names, iface.Name)
		}
	}
	ipv6 := ""
	for _, name := range names {
		iface, e := net.InterfaceByName(name)
		if e != nil || iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			ip, _, e := net.ParseCIDR(addr.String())
			if e != nil || !ip.IsGlobalUnicast() {
				continue
			}
			if ip.To4() != nil {
				return ip.String()
			}
			if ipv6 == "" {
				ipv6 = ip.String()
			}
		}
	}
	return ipv6
}
