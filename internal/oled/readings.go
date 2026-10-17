package oled

import (
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"panasms.local/backend/internal/system"
)

func Readings(s Settings) []string {
	host, _ := os.Hostname()
	var cpu *float64
	disks := map[string]float64{}
	if s.ShowCPU {
		cpu = system.CPUTemperature()
	}
	if s.ShowDisks {
		disks = system.ReadDiskTemperatures("/run/panasms-cooling/status.json", time.Now())
	}
	ip := ""
	if s.ShowIP {
		ip = primaryIP()
	}
	return lines(s, host, ip, cpu, disks)
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
