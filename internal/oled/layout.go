package oled

import "strings"

func Compose(s Settings, data Snapshot, page int) []Text {
	switch s.Layout {
	case "large":
		scene := rows(ipRows(s, data.IP), 2, 9)
		if s.ShowCPU {
			scene = append(scene, fitted("CPU "+strings.ReplaceAll(temperature(data.CPU), " ", ""), 25, 2))
		}
		if s.ShowDisks {
			scene = append(scene, fitted("HDD "+strings.ReplaceAll(temperature(hottest(data.Disks)), " ", ""), 45, 2))
		}
		return scene
	case "disks":
		values := ipRows(s, data.IP)
		if s.ShowCPU {
			values = append(values, "CPU "+temperature(data.CPU))
		}
		if s.ShowDisks {
			capacity := 6 - len(values)
			if len(data.Disks) == 0 {
				values = append(values, "HDD --")
			} else {
				pages := (len(data.Disks) + capacity - 1) / capacity
				start := page % pages * capacity
				for _, disk := range data.Disks[start:min(start+capacity, len(data.Disks))] {
					value := temperature(disk.Temperature)
					values = append(values, short(disk.Label, 19-len(value))+" "+value)
				}
			}
		}
		return rows(values, 2, 10)
	case "pages":
		var pages [][]Text
		if s.ShowIP {
			pages = append(pages, append([]Text{{label(s.Language, "network"), 2, 2, 1}}, rows(ipRows(s, data.IP), 25, 10)...))
		}
		if s.ShowCPU {
			pages = append(pages, []Text{{label(s.Language, "cpu-temperature"), 2, 2, 1}, fitted(temperature(data.CPU), 24, 3)})
		}
		if s.ShowDisks {
			if len(data.Disks) == 0 {
				pages = append(pages, []Text{{label(s.Language, "disk-temperature"), 2, 2, 1}, fitted("--", 24, 3)})
			}
			for _, disk := range data.Disks {
				pages = append(pages, []Text{{short(label(s.Language, "disk")+" "+disk.Label, 20), 2, 2, 1}, fitted(temperature(disk.Temperature), 24, 3)})
			}
		}
		if len(pages) == 0 {
			return rows([]string{data.Host}, 2, 12)
		}
		return append(pages[page%len(pages)], Text{short(data.Host, 20), 2, 52, 1})
	default:
		values := []string{data.Host}
		values = append(values, ipRows(s, data.IP)...)
		if s.ShowCPU {
			values = append(values, "CPU "+temperature(data.CPU))
		}
		if s.ShowDisks {
			values = append(values, "HDD MAX "+temperature(hottest(data.Disks)))
		}
		uptime := data.Uptime
		if uptime == "" {
			uptime = "--"
		}
		values = append(values, "UP "+uptime)
		pitch := 12
		if len(values) > 5 {
			pitch = 10
		}
		return rows(values, 2, pitch)
	}
}
func ipRows(s Settings, ip string) []string {
	if !s.ShowIP {
		return nil
	}
	if ip == "" {
		ip = "--"
	}
	if len(ip) <= 17 {
		return []string{"IP " + ip}
	}
	return []string{ip[:min(20, len(ip))], ip[min(20, len(ip)):]}
}
func hottest(disks []Disk) *float64 {
	var result *float64
	for _, disk := range disks {
		if disk.Temperature != nil && (result == nil || *disk.Temperature > *result) {
			result = disk.Temperature
		}
	}
	return result
}
func short(value string, length int) string {
	runes := []rune(value)
	return string(runes[:min(length, len(runes))])
}
func rows(values []string, y, pitch int) []Text {
	var scene []Text
	for i, value := range values {
		scene = append(scene, Text{short(value, 20), 2, y + i*pitch, 1})
	}
	return scene
}
func fitted(value string, y, scale int) Text {
	scale = min(scale, 124/max(1, len([]rune(value))*6))
	return Text{short(value, 20), 2, y, max(1, scale)}
}
