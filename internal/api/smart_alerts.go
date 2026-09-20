package api

import (
	"context"
	"encoding/json"
	"panasms.local/backend/internal/cooling"
	"panasms.local/backend/internal/store"
	"panasms.local/backend/internal/system"
	"sort"
	"strings"
)

type smartAlertDisk struct {
	Path       string   `json:"path"`
	Device     string   `json:"device"`
	Health     string   `json:"health"`
	Warnings   []string `json:"warnings"`
	Attributes []struct {
		ID  int `json:"id"`
		Raw struct {
			Value *uint64 `json:"value"`
		} `json:"raw"`
	} `json:"attributes"`
}

func applyCRCAcknowledgements(alerts []store.Alert, baselines map[string]uint64, disks []smartAlertDisk, storage system.Storage) {
	keys := map[string]string{}
	var visit func(map[string]any)
	visit = func(d map[string]any) {
		path, _ := d["path"].(string)
		model, _ := d["model"].(string)
		serial, _ := d["serial"].(string)
		if serial != "" {
			keys[path] = strings.TrimSpace(model) + ":" + serial
		}
		children, _ := d["children"].([]any)
		for _, child := range children {
			if row, ok := child.(map[string]any); ok {
				visit(row)
			}
		}
	}
	for _, d := range storage.Devices {
		visit(d)
	}
	accepted := map[string]bool{}
	for _, d := range disks {
		baseline, ok := baselines[keys[d.Device]]
		if !ok || d.Health != "warning" || len(d.Warnings) != 1 || d.Warnings[0] != "UDMA_CRC_Error_Count" {
			continue
		}
		for _, a := range d.Attributes {
			if a.ID == 199 && a.Raw.Value != nil && *a.Raw.Value == baseline {
				accepted["smart:"+d.Path] = true
			}
		}
	}
	for i := range alerts {
		if alerts[i].Active && accepted[alerts[i].ID] {
			alerts[i].Active = false
			alerts[i].Message = "CRC count acknowledged: " + strings.TrimPrefix(alerts[i].ID, "smart:")
		}
	}
	sort.SliceStable(alerts, func(i, j int) bool {
		if alerts[i].Active != alerts[j].Active {
			return alerts[i].Active
		}
		return alerts[i].Updated > alerts[j].Updated
	})
}

func (s *Server) notifications(ctx context.Context, user string) ([]store.Alert, error) {
	alerts, err := s.Store.Alerts()
	if err != nil {
		return nil, err
	}
	prefs, err := s.Store.Preferences(user)
	if err != nil {
		return nil, err
	}
	if len(prefs.SmartCrcBaselines) > 0 {
		if state, err := cooling.Read(); err == nil {
			raw, err := json.Marshal(state)
			var v struct {
				Status struct {
					Disks []smartAlertDisk `json:"disks"`
				} `json:"status"`
			}
			if err == nil && json.Unmarshal(raw, &v) == nil {
				if snapshot, err := system.StorageRead(ctx); err == nil {
					applyCRCAcknowledgements(alerts, prefs.SmartCrcBaselines, v.Status.Disks, snapshot)
				}
			}
		}
	}
	return s.Store.VisibleAlerts(user, alerts)
}
