package storagequery

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func readText(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func mediaInfo(row map[string]any, sys string) map[string]any {
	block := filepath.Join(sys, row["kname"].(string))
	node := filepath.Join(block, "device")
	info := map[string]any{"readOnly": readText(filepath.Join(block, "ro")) == "1"}
	card := ""
	if row["tran"] == "mmc" {
		card = readText(filepath.Join(node, "type"))
	}
	copyAttrs := func(parent string, attrs map[string]string) {
		for key, attr := range attrs {
			if value := readText(filepath.Join(parent, attr)); value != "" {
				info[key] = value
			}
		}
	}
	switch {
	case card == "SD" || card == "MMC":
		info["kind"] = "sd"
		if card == "MMC" {
			info["kind"] = "emmc"
		}
		copyAttrs(node, map[string]string{"name": "name", "manufacturerId": "manfid", "manufactured": "date", "revision": "hwrev"})
	case row["tran"] == "usb":
		info["kind"] = "usb"
		parent, err := filepath.EvalSymlinks(node)
		if err == nil {
			for parent != filepath.Dir(parent) {
				vendor, product := readText(filepath.Join(parent, "idVendor")), readText(filepath.Join(parent, "idProduct"))
				if vendor != "" && product != "" {
					info["usbId"] = vendor + ":" + product
					copyAttrs(parent, map[string]string{"usbVersion": "version", "linkMbps": "speed", "manufacturer": "manufacturer", "name": "product"})
					break
				}
				parent = filepath.Dir(parent)
			}
		}
		if readText(filepath.Join(block, "removable")) == "1" {
			info["kind"] = "usb-flash"
		}
	default:
		info["kind"] = "ssd"
		if row["tran"] == "nvme" {
			info["kind"] = "nvme"
		} else if readOnly(row["rota"]) {
			info["kind"] = "hdd"
		}
	}
	return info
}

func cachedHealth(path, sys, state string) any {
	node := filepath.Join(sys, filepath.Base(path))
	disk := node
	if _, err := os.Stat(filepath.Join(node, "partition")); err == nil {
		resolved, err := filepath.EvalSymlinks(node)
		if err != nil {
			return nil
		}
		disk = filepath.Dir(resolved)
	}
	seq, dev := readText(filepath.Join(disk, "diskseq")), readText(filepath.Join(node, "dev"))
	if seq == "" || dev == "" {
		return nil
	}
	data, err := os.ReadFile(filepath.Join(state, filepath.Base(path)+".json"))
	if err != nil {
		return nil
	}
	var result map[string]any
	if json.Unmarshal(data, &result) != nil || result["identity"] != seq+":"+dev {
		return nil
	}
	return result
}

var calendarPattern = regexp.MustCompile(`(?m)^OnCalendar=(Mon|Tue|Wed|Thu|Fri|Sat|Sun) \*-\*-\* (\d{2}):00:00$`)
var smartTestPattern = regexp.MustCompile(`(?m)^ExecStart=/usr/sbin/smartctl -t (short|long) `)
var schedulePattern = regexp.MustCompile(`(?m)^# PaNasMs schedule: (.+)$`)

func smartSchedules(serial, root string, now time.Time) (any, []map[string]any, error) {
	schedules := []map[string]any{}
	if serial == "" {
		return nil, schedules, nil
	}
	hash := sha256.Sum256([]byte(serial))
	base := fmt.Sprintf("panasms-smart-%x", hash[:8])
	calendar := calendarPattern.FindStringSubmatch(readText(filepath.Join(root, base+".timer")))
	test := smartTestPattern.FindStringSubmatch(readText(filepath.Join(root, base+".service")))
	var legacy any
	order := []string{}
	byTest := map[string]map[string]any{}
	if len(calendar) > 0 && len(test) > 0 {
		weekday := strings.Index("MonTueWedThuFriSatSun", calendar[1]) / 3
		hour, _ := strconv.Atoi(calendar[2])
		legacy = map[string]any{"test": test[1], "weekday": weekday, "hour": hour}
		byTest[test[1]] = map[string]any{"test": test[1], "weekday": float64(weekday), "hour": float64(hour), "weeks": float64(1)}
		order = append(order, test[1])
	}
	for _, test := range []string{"short", "long"} {
		if _, err := os.Stat(filepath.Join(root, base+"-"+test+".timer")); err != nil {
			continue
		}
		match := schedulePattern.FindStringSubmatch(readText(filepath.Join(root, base+"-"+test+".service")))
		if len(match) == 0 {
			continue
		}
		var schedule map[string]any
		if err := json.Unmarshal([]byte(match[1]), &schedule); err != nil {
			return nil, nil, err
		}
		if _, exists := byTest[test]; !exists {
			order = append(order, test)
		}
		byTest[test] = schedule
	}
	for _, test := range order {
		schedule := byTest[test]
		next, err := nextScheduled(schedule, now)
		if err != nil {
			return nil, nil, err
		}
		schedule["nextScheduledAt"] = next
		schedules = append(schedules, schedule)
	}
	return legacy, schedules, nil
}

func nextScheduled(schedule map[string]any, now time.Time) (any, error) {
	weekday, wok := schedule["weekday"].(float64)
	hour, hok := schedule["hour"].(float64)
	weeks := float64(1)
	if value, ok := schedule["weeks"]; ok {
		weeks, _ = value.(float64)
	}
	if !wok || !hok || weekday < 0 || weekday > 6 || weekday != float64(int(weekday)) || hour < 0 || hour > 23 || hour != float64(int(hour)) || (weeks != 1 && weeks != 2) {
		return nil, fmt.Errorf("Invalid schedule")
	}
	day := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	var start time.Time
	if date, ok := schedule["startDate"].(string); ok && date != "" {
		var err error
		start, err = time.ParseInLocation("2006-01-02", date, now.Location())
		if err != nil {
			return nil, err
		}
		if start.After(day) {
			day = start
		}
	}
	for offset := 0; offset < 29; offset++ {
		candidateDay := day.AddDate(0, 0, offset)
		if (int(candidateDay.Weekday())+6)%7 != int(weekday) {
			continue
		}
		if !start.IsZero() {
			// Count civil days; local DST transitions are not 24-hour intervals.
			a := time.Date(candidateDay.Year(), candidateDay.Month(), candidateDay.Day(), 0, 0, 0, 0, time.UTC)
			b := time.Date(start.Year(), start.Month(), start.Day(), 0, 0, 0, 0, time.UTC)
			elapsed := int(a.Sub(b).Hours() / 24)
			if elapsed < 0 || elapsed%(int(weeks)*7) != 0 {
				continue
			}
		}
		candidate := time.Date(candidateDay.Year(), candidateDay.Month(), candidateDay.Day(), int(hour), 0, 0, 0, now.Location())
		if candidate.After(now) {
			return candidate.Format("2006-01-02T15:04:05-07:00"), nil
		}
	}
	return nil, nil
}
