package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"panasms.local/backend/internal/cooling"
	"panasms.local/backend/internal/management"
	"panasms.local/backend/internal/system"
	"strings"
	"time"
)

func (s *Server) monitor(ctx context.Context, m system.Metrics) {
	s.Store.Alert("cpu-hot", "CPU temperature ≥ 80 °C", m.CPUTemperature != nil && *m.CPUTemperature >= 80)
	s.Store.Alert("system-full", "Less than 5% free space on the system drive", m.SystemTotal > 0 && float64(m.SystemAvailable)/float64(m.SystemTotal) < 0.05)
	state, e := cooling.Read()
	if e == nil {
		raw, _ := json.Marshal(state)
		var v struct {
			Available bool `json:"available"`
			Status    struct {
				Disks []struct {
					smartAlertDisk
					State       string   `json:"state"`
					Temperature *float64 `json:"temperature"`
				} `json:"disks"`
			} `json:"status"`
		}
		json.Unmarshal(raw, &v)
		s.Store.Alert("cooling-stale", "Cooling telemetry is out of date", !v.Available)
		for _, d := range v.Status.Disks {
			message := "SMART warning: " + d.Path
			if d.Health == "failed" {
				message = "SMART: disk failure: " + d.Path
			}
			if len(d.Warnings) > 0 {
				message += " · " + strings.Join(d.Warnings, ", ")
			}
			for _, a := range d.Attributes {
				if a.ID == 199 && a.Raw.Value != nil {
					message += fmt.Sprintf(" · CRC: %d", *a.Raw.Value)
				}
			}
			s.Store.Alert("smart:"+d.Path, message, d.Health == "warning" || d.Health == "failed")
			s.Store.Alert("heat:"+d.Path, "Disk temperature ≥ 50 °C: "+d.Path, d.Temperature != nil && *d.Temperature >= 50)
		}
	}
	// The agent serves this internal read-only feed only to the verified core UID.
	req, e := http.NewRequestWithContext(ctx, "GET", "http://agent/job-feed", nil)
	if e != nil {
		return
	}
	values := req.URL.Query()
	if alerts, err := s.Store.Alerts(); err == nil {
		for _, alert := range alerts {
			if alert.Active && strings.HasPrefix(alert.ID, "job:") {
				values.Add("alert", strings.TrimPrefix(alert.ID, "job:"))
			}
		}
	}
	req.URL.RawQuery = values.Encode()
	resp, e := s.Agent.Do(req)
	if e != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return
	}
	raw, e := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if e != nil {
		return
	}
	var jobs []management.Job
	if json.Unmarshal(raw, &jobs) != nil {
		return
	}
	digest := sha256.Sum256(raw)
	s.jobsRevision.Store(hex.EncodeToString(digest[:]))
	for _, j := range jobs {
		if (strings.HasPrefix(j.Action, "user.") || strings.HasPrefix(j.Action, "group.")) && (j.Status == "succeeded" || j.Status == "failed" || j.Status == "interrupted" || j.Status == "cancelled") {
			target := j.Target
			if strings.HasPrefix(j.Action, "group.") {
				target = j.User
			}
			s.Store.AuditJob(j.ID, target, j.User, j.Action, j.Status, j.Updated)
		}
		if j.Status == "failed" || j.Status == "interrupted" || j.Status == "cancelled" {
			s.Store.Alert("job:"+j.ID, "Operation "+j.Action+": "+j.Stage, j.NeedsReview)
		}
	}
	s.monitorDevices(ctx, jobs)
	if alerts, err := s.Store.Alerts(); err == nil {
		data, _ := json.Marshal(alerts)
		sum := sha256.Sum256(data)
		s.notificationsRevision.Store(hex.EncodeToString(sum[:]))
	}
	s.Store.PruneAlerts(time.Now().Add(-30 * 24 * time.Hour))
}

type deviceSnapshot struct {
	Path, Name string
	Size       float64
	Busy       bool
}

func diskSnapshots(storage system.Storage) map[string]deviceSnapshot {
	result := map[string]deviceSnapshot{}
	var busy func(map[string]any) bool
	busy = func(d map[string]any) bool {
		if mounts, ok := d["mountpoints"].([]any); ok {
			for _, m := range mounts {
				if m != nil && m != "" {
					return true
				}
			}
		}
		kind, _ := d["type"].(string)
		if strings.HasPrefix(kind, "raid") || kind == "crypt" {
			return true
		}
		if children, ok := d["children"].([]any); ok {
			for _, child := range children {
				if row, ok := child.(map[string]any); ok && busy(row) {
					return true
				}
			}
		}
		return false
	}
	for _, d := range storage.Devices {
		if d["type"] != "disk" {
			continue
		}
		path, _ := d["path"].(string)
		serial, _ := d["serial"].(string)
		name, _ := d["model"].(string)
		name = strings.TrimSpace(name)
		if name == "" {
			name, _ = d["name"].(string)
		}
		size, _ := d["size"].(float64)
		result[path+":"+serial] = deviceSnapshot{path, name, size, busy(d)}
	}
	return result
}
func (s *Server) deviceEvent(message string, warning bool) {
	id := fmt.Sprintf("device:%d", time.Now().UnixNano())
	s.Store.Alert(id, message, true)
	if !warning {
		s.Store.Alert(id, message, false)
	}
}
func (s *Server) monitorDevices(ctx context.Context, jobs []management.Job) {
	snapshot, err := system.StorageRead(ctx)
	if err != nil {
		return
	}
	s.recordDevices(diskSnapshots(snapshot), jobs)
}

func (s *Server) recordDevices(current map[string]deviceSnapshot, jobs []management.Job) {
	if s.knownDevices == nil {
		s.knownDevices = current
		s.seenEjects = map[string]bool{}
		for _, j := range jobs {
			if j.Status == "succeeded" {
				s.seenEjects[j.ID] = true
			}
		}
		return
	}
	expected := map[string]bool{}
	for _, j := range jobs {
		if j.Action != "disk.eject" {
			continue
		}
		stamp, err := time.Parse(time.RFC3339Nano, j.Updated)
		if err == nil && time.Since(stamp) < 30*time.Second && (j.Status == "running" || j.Status == "succeeded") {
			expected[j.Target] = true
		}
		if j.Status == "succeeded" && !s.seenEjects[j.ID] {
			s.seenEjects[j.ID] = true
			s.deviceEvent("Drive "+j.Target+" can be disconnected", false)
		}
	}
	for key, d := range current {
		if _, ok := s.knownDevices[key]; !ok {
			s.deviceEvent(fmt.Sprintf("Drive connected: %s · %.1f GiB", d.Name, d.Size/(1024*1024*1024)), false)
		}
	}
	for key, d := range s.knownDevices {
		if _, ok := current[key]; !ok && !expected[d.Path] {
			message := "Drive disconnected: " + d.Name
			if d.Busy {
				message += ". It had mounted volumes or array members; check storage."
			}
			s.deviceEvent(message, d.Busy)
		}
	}
	s.knownDevices = current
}
