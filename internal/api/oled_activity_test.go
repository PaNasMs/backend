package api

import (
	"encoding/json"
	"panasms.local/backend/internal/auth"
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

func TestOLEDExcludesOldInactiveAlertsAndAcknowledgedJobFailures(t *testing.T) {
	now := time.Now().UTC()
	old := now.Add(-3 * time.Minute).Format(time.RFC3339)
	recent := now.Add(-time.Second).Format(time.RFC3339)
	alerts := []store.Alert{{ID: "device:old", Updated: old, Message: "Drive connected: old"}, {ID: "device:new", Updated: recent, Message: "Drive connected: new"}, {ID: "heat:/dev/sda", Updated: old, Active: true, Severity: "warning"}, {ID: "job:acknowledged", Updated: recent}}
	jobs := []management.Job{{ID: "acknowledged", Action: "files.copy", Status: "failed", Created: old, Updated: recent}, {ID: "other", Action: "files.copy", Status: "succeeded", Created: old, Updated: recent}}
	a := oledActivity(system.Storage{}, true, jobs, alerts, now)
	if len(a.Events) != 3 {
		t.Fatalf("old or acknowledged event retained: %+v", a.Events)
	}
	for _, e := range a.Events {
		if e.ID != "device:new" && e.ID != "heat:/dev/sda" && e.ID != "job:other" {
			t.Fatal(e)
		}
	}
}

func TestOLEDAcknowledgedCRCUsesCurrentAdminsAndPreservesOtherWarnings(t *testing.T) {
	s := testServer(t)
	storage := system.Storage{Devices: []map[string]any{{"path": "/dev/sdd", "model": "WDC", "serial": "serial"}}}
	prefs := store.DefaultPreferences()
	prefs.SmartCrcBaselines = map[string]uint64{"WDC:serial": 7}
	if err := s.Store.Save("owner", prefs); err != nil {
		t.Fatal(err)
	}
	disk := smartAlertDisk{Path: "/dev/disk/by-id/disk", Device: "/dev/sdd", Health: "warning", Warnings: []string{"UDMA_CRC_Error_Count"}}
	if err := json.Unmarshal([]byte(`[{"id":199,"raw":{"value":7}}]`), &disk.Attributes); err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{"member", "admin"} {
		s.lookupIdentity = func(user string, _ map[string]bool) (auth.Identity, error) {
			return auth.Identity{Username: user, Role: role}, nil
		}
		now := time.Now().UTC()
		alerts := []store.Alert{{ID: "smart:" + disk.Path, Active: true, Updated: now.Format(time.RFC3339)}, {ID: "heat:" + disk.Path, Active: true, Updated: now.Format(time.RFC3339)}}
		s.applyOLEDCRCAcknowledgements(alerts, []smartAlertDisk{disk}, storage)
		a := oledActivity(storage, true, nil, alerts, now)
		want := 2
		if role == "admin" {
			want = 1
		}
		if len(a.Events) != want {
			t.Fatalf("%s: %+v", role, a.Events)
		}
	}
	*disk.Attributes[0].Raw.Value = 8
	alerts := []store.Alert{{ID: "smart:" + disk.Path, Active: true}}
	s.applyOLEDCRCAcknowledgements(alerts, []smartAlertDisk{disk}, storage)
	if !alerts[0].Active {
		t.Fatal("new CRC errors hidden")
	}
}
