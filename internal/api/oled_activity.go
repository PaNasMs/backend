package api

import (
	"fmt"
	"log"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"panasms.local/backend/internal/management"
	"panasms.local/backend/internal/oled"
	"panasms.local/backend/internal/store"
	"panasms.local/backend/internal/system"
)

func oledActivity(storage system.Storage, storageOK bool, jobs []management.Job, alerts []store.Alert, now time.Time) oled.Activity {
	a := oled.Activity{ObservedAt: now, StorageOK: storageOK}
	for _, ar := range storage.Arrays {
		state := "unknown"
		switch ar.State {
		case "clean", "active", "active-idle", "read-auto":
			if ar.Degraded == "0" {
				state = "healthy"
			}
		case "readonly":
			state = "read-only"
		case "inactive", "clear", "suspended":
			state = "inactive"
		}
		if ar.Degraded != "" && ar.Degraded != "0" || ar.Missing > 0 {
			state = "degraded"
		}
		name := filepath.Base(ar.Device)
		if name == "." {
			name = ar.Name
		}
		a.Arrays = append(a.Arrays, oled.ArrayStatus{Name: name, State: state})
		if state != "healthy" {
			severity := "critical"
			if state == "unknown" || state == "read-only" {
				severity = "warning"
			}
			a.Events = append(a.Events, oled.Event{ID: "raid:" + name, Revision: state, Kind: "raid-problem", Target: name, Severity: severity, Active: true, At: now})
		}
		kind := "raid-" + ar.Sync
		switch ar.Sync {
		case "recover", "resync", "reshape", "check", "repair", "frozen":
			status := "running"
			if ar.Sync == "frozen" {
				status = "paused"
				kind = "raid-resync"
			}
			a.Tasks = append(a.Tasks, oled.Task{ID: "raid:" + name, Kind: kind, Target: name, State: status, Percent: ar.SyncPercent, Remaining: ar.SyncRemaining})
		default:
			if ar.ReshapePending {
				a.Tasks = append(a.Tasks, oled.Task{ID: "raid:" + name, Kind: "raid-reshape", Target: name, State: "paused"})
			}
		}
	}
	seenMounts := map[string]bool{}
	for _, m := range storage.Mounts {
		source, _ := m["source"].(string)
		target, _ := m["target"].(string)
		device, _ := m["maj:min"].(string)
		if device == "" {
			device = source
		}
		if !strings.HasPrefix(source, "/dev/") || seenMounts[device] {
			continue
		}
		seenMounts[device] = true
		var available *float64
		switch v := m["avail"].(type) {
		case float64:
			if v >= 0 {
				available = &v
			}
		case string:
			if n, e := strconv.ParseFloat(v, 64); e == nil && n >= 0 {
				available = &n
			}
		}
		name := filepath.Base(strings.Split(source, "[")[0])
		if target == "/" {
			name = "SYSTEM"
		}
		a.Volumes = append(a.Volumes, oled.Volume{Name: name, Available: available})
	}
	acknowledgedJobs := map[string]bool{}
	for _, alert := range alerts {
		if !alert.Active && strings.HasPrefix(alert.ID, "job:") {
			acknowledgedJobs[strings.TrimPrefix(alert.ID, "job:")] = true
		}
	}
	for _, j := range jobs {
		started, _ := time.Parse(time.RFC3339Nano, j.Created)
		updated, _ := time.Parse(time.RFC3339Nano, j.Updated)
		kind := oledJobKind(j.Action)
		if j.Status == "running" || j.Status == "queued" {
			if now.Sub(started) < 10*time.Second {
				continue
			}
			state := j.Status
			if j.CancelRequested {
				state = "cancelling"
			}
			a.Tasks = append(a.Tasks, oled.Task{ID: "job:" + j.ID, Kind: kind, State: state, Percent: j.Percent, Started: started})
		} else if !acknowledgedJobs[j.ID] && now.Sub(updated) >= 0 && now.Sub(updated) < 2*time.Minute && updated.Sub(started) >= 10*time.Second {
			severity := "success"
			if j.Status != "succeeded" {
				severity = "warning"
			}
			a.Events = append(a.Events, oled.Event{ID: "job:" + j.ID, Revision: j.Updated, Kind: j.Status, Target: kind, Severity: severity, At: updated})
		}
	}
	for _, alert := range alerts {
		kind := oledAlertKind(alert)
		if kind == "" {
			continue
		}
		at, _ := time.Parse(time.RFC3339Nano, alert.Updated)
		if !alert.Active && (now.Sub(at) >= 2*time.Minute || now.Before(at) || strings.HasPrefix(alert.ID, "job:")) {
			continue
		}
		target := ""
		if strings.HasPrefix(alert.ID, "smart:/dev/") || strings.HasPrefix(alert.ID, "heat:/dev/") {
			target = filepath.Base(alert.ID)
		}
		severity := alert.Severity
		if !alert.Active && (strings.HasPrefix(alert.ID, "smart:") || strings.HasPrefix(alert.ID, "heat:") || alert.ID == "cpu-hot" || alert.ID == "system-full" || alert.ID == "cooling-stale") {
			kind = "problem-resolved"
			severity = "success"
		}
		a.Events = append(a.Events, oled.Event{ID: alert.ID, Revision: alert.Updated, Kind: kind, Target: target, Severity: severity, Active: alert.Active, At: at})
	}
	unique := map[string]oled.Event{}
	for _, e := range a.Events {
		unique[e.ID] = e
	}
	a.Events = nil
	for _, e := range unique {
		a.Events = append(a.Events, e)
	}
	sort.Slice(a.Events, func(i, j int) bool { return a.Events[i].ID < a.Events[j].ID })
	return a
}
func oledJobKind(action string) string {
	switch {
	case strings.Contains(action, "copy"):
		return "copy"
	case strings.Contains(action, "move"):
		return "move"
	case strings.Contains(action, "delete") || strings.Contains(action, "trash"):
		return "delete"
	case strings.Contains(action, "upload"):
		return "upload"
	case strings.Contains(action, "backup"):
		return "backup"
	case strings.HasPrefix(action, "system.update"):
		return "update"
	default:
		return "operation"
	}
}
func oledAlertKind(a store.Alert) string {
	switch {
	case a.ID == "cpu-hot", a.ID == "system-full", a.ID == "cooling-stale":
		return a.ID
	case strings.HasPrefix(a.ID, "smart:"):
		return "smart"
	case strings.HasPrefix(a.ID, "heat:"):
		return "heat"
	case strings.HasPrefix(a.ID, "job:"):
		return "failed"
	case strings.HasPrefix(a.ID, "transfer:"):
		if a.Message == "Transfer completed" {
			return "succeeded"
		}
		return "failed"
	case strings.HasPrefix(a.ID, "update:available:"):
		return "update-available"
	case strings.HasPrefix(a.ID, "update:result:"):
		return "update-result"
	case strings.HasPrefix(a.ID, "device:"):
		if strings.HasPrefix(a.Message, "Drive connected:") {
			return "device-connected"
		}
		if strings.HasPrefix(a.Message, "Drive disconnected:") {
			return "device-disconnected"
		}
		return "device-ejected"
	}
	return ""
}
func (s *Server) publishOLED(storage system.Storage, storageOK bool, jobs []management.Job, update *oled.Task) {
	now := time.Now().UTC()
	alerts, err := s.Store.Alerts()
	if err != nil {
		return
	}
	activity := oledActivity(storage, storageOK, jobs, alerts, now)
	activity.Tasks = append(activity.Tasks, s.transferSnapshot(now)...)
	if update != nil {
		activity.Tasks = append(activity.Tasks, *update)
	}
	sort.Slice(activity.Tasks, func(i, j int) bool { return activity.Tasks[i].ID < activity.Tasks[j].ID })
	if err := oled.WriteActivity(oled.ActivityPath, activity); err != nil {
		log.Printf("OLED activity unavailable: %v", err)
	}
}

func transferEventID(id uint64) string { return fmt.Sprintf("transfer:%d", id) }
