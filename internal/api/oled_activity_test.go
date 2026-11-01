package api

import (
	"encoding/json"
	"panasms.local/backend/internal/management"
	"panasms.local/backend/internal/store"
	"panasms.local/backend/internal/system"
	"strings"
	"testing"
	"time"
)

func TestOLEDUsesStorageAndJobsWithoutPrivatePaths(t *testing.T) {
	now := time.Now().UTC()
	p := 35.0
	storage := system.Storage{Arrays: []system.Array{{Device: "/dev/md127", State: "clean", Degraded: "0", Sync: "recover", SyncPercent: &p}}, Mounts: []map[string]any{{"source": "/dev/md127", "target": "/srv/private", "maj:min": "9:127", "avail": float64(0)}, {"source": "/dev/md127", "target": "/srv/private/bind", "maj:min": "9:127", "avail": float64(0)}, {"source": "tmpfs", "target": "/tmp", "maj:min": "0:1", "avail": float64(100)}}}
	jobs := []management.Job{{ID: "j", Action: "files.copy", User: "secret-user", Target: "/private/secret-file", Stage: "Secret details", Status: "running", Percent: &p, Created: now.Add(-time.Minute).Format(time.RFC3339)}}
	a := oledActivity(storage, true, jobs, []store.Alert{{ID: "smart:/dev/sda", Message: "Secret serial", Active: true, Severity: "warning", Updated: now.Format(time.RFC3339)}}, now)
	if len(a.Tasks) != 2 || len(a.Volumes) != 1 || a.Volumes[0].Available == nil || *a.Volumes[0].Available != 0 || a.Arrays[0].State != "healthy" {
		t.Fatalf("%+v", a)
	}
	raw, _ := json.Marshal(a)
	for _, secret := range []string{"secret", "Secret", "/private", "/srv"} {
		if strings.Contains(string(raw), secret) {
			t.Fatal(string(raw))
		}
	}
	storage.Arrays[0].Degraded = "1"
	a = oledActivity(storage, true, nil, nil, now)
	if a.Arrays[0].State != "degraded" || len(a.Events) != 1 || !a.Events[0].Active {
		t.Fatal(a)
	}
	storage.Arrays[0].State = ""
	storage.Arrays[0].Degraded = "0"
	a = oledActivity(storage, true, nil, nil, now)
	if a.Arrays[0].State != "unknown" {
		t.Fatal(a)
	}
}
func TestTransferProgressUnknownSizeAndCleanup(t *testing.T) {
	s := testServer(t)
	transfer := s.startTransfer("upload", 100)
	transfer.started = time.Now().Add(-time.Minute)
	transfer.loaded.Store(50)
	tasks := s.transferSnapshot(time.Now())
	if len(tasks) != 1 || tasks[0].Percent == nil || *tasks[0].Percent != 50 {
		t.Fatal(tasks)
	}
	transfer.total = -1
	tasks = s.transferSnapshot(time.Now())
	if tasks[0].Percent != nil {
		t.Fatal(tasks)
	}
	s.finishTransfer(transfer, false)
	if len(s.transferSnapshot(time.Now())) != 0 {
		t.Fatal("leaked transfer")
	}
	alerts, err := s.Store.Alerts()
	if err != nil || len(alerts) != 1 || oledAlertKind(alerts[0]) != "failed" {
		t.Fatal(alerts, err)
	}
}
