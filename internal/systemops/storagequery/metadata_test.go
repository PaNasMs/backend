package storagequery

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCachedHealthRequiresSameKernelIncarnation(t *testing.T) {
	root := t.TempDir()
	sys, state := filepath.Join(root, "sys"), filepath.Join(root, "state")
	for _, dir := range []string{filepath.Join(sys, "sda"), state} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for path, data := range map[string]string{filepath.Join(sys, "sda/diskseq"): "7", filepath.Join(sys, "sda/dev"): "8:0", filepath.Join(state, "sda.json"): `{"identity":"7:8:0","status":"warning","reason":"accepted","checkedAt":12}`} {
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	got := cachedHealth("/dev/sda", sys, state)
	if got == nil || got.(map[string]any)["status"] != "warning" || got.(map[string]any)["checkedAt"] != float64(12) {
		t.Fatalf("%v", got)
	}
	if err := os.WriteFile(filepath.Join(sys, "sda/diskseq"), []byte("8"), 0600); err != nil {
		t.Fatal(err)
	}
	if got := cachedHealth("/dev/sda", sys, state); got != nil {
		t.Fatalf("reused device inherited health: %v", got)
	}
	if got := cachedHealth("/dev/missing", sys, state); got != nil {
		t.Fatalf("unknown health became known: %v", got)
	}
}

func TestNextScheduledUsesCivilWeeksAcrossDST(t *testing.T) {
	zone, err := time.LoadLocation("Europe/Warsaw")
	if err != nil {
		t.Fatal(err)
	}
	var schedule map[string]any
	if err := json.Unmarshal([]byte(`{"test":"long","weekday":0,"hour":10,"weeks":2,"startDate":"2026-10-19"}`), &schedule); err != nil {
		t.Fatal(err)
	}
	next, err := nextScheduled(schedule, time.Date(2026, 10, 20, 12, 0, 0, 0, zone))
	if err != nil || next != "2026-11-02T10:00:00+01:00" {
		t.Fatalf("%v %v", next, err)
	}
	next, err = nextScheduled(schedule, time.Date(2026, 11, 2, 10, 0, 0, 0, zone))
	if err != nil || next != "2026-11-16T10:00:00+01:00" {
		t.Fatalf("%v %v", next, err)
	}
	schedule["weeks"] = float64(0)
	if _, err := nextScheduled(schedule, time.Now()); err == nil {
		t.Fatal("invalid recurrence accepted")
	}
}

func TestSmartSchedulesLegacyAndOverrideRemainReadOnly(t *testing.T) {
	root := t.TempDir()
	// sha256("disk") prefix is the legacy persisted timer identity.
	base := "panasms-smart-1044dec7206e8d7c"
	for name, data := range map[string]string{
		base + ".timer":         "OnCalendar=Mon *-*-* 10:00:00\n",
		base + ".service":       "ExecStart=/usr/sbin/smartctl -t short /dev/sda\n",
		base + "-short.timer":   "timer\n",
		base + "-short.service": "# PaNasMs schedule: {\"test\":\"short\",\"weekday\":1,\"hour\":11,\"weeks\":1}\n",
	} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	legacy, schedules, err := smartSchedules("disk", root, time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC))
	if err != nil || legacy == nil || len(schedules) != 1 || schedules[0]["nextScheduledAt"] != "2026-11-03T11:00:00+00:00" {
		t.Fatalf("%v %v %v", legacy, schedules, err)
	}
}
