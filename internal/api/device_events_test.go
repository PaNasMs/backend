package api

import (
	"panasms.local/backend/internal/management"
	"testing"
	"time"
)

func TestDeviceEventsBaselineAndTransitions(t *testing.T) {
	s := testServer(t)
	disk := deviceSnapshot{Path: "/dev/sdz", Name: "Test USB", Size: 1024, Busy: true}
	s.recordDevices(map[string]deviceSnapshot{"old": disk}, nil)
	alerts, _ := s.Store.Alerts()
	if len(alerts) != 0 {
		t.Fatal("baseline emitted alert")
	}
	s.recordDevices(map[string]deviceSnapshot{}, nil)
	alerts, _ = s.Store.Alerts()
	if len(alerts) != 1 || !alerts[0].Active {
		t.Fatal("busy disconnect not warned")
	}
	s.recordDevices(map[string]deviceSnapshot{}, nil)
	alerts, _ = s.Store.Alerts()
	if len(alerts) != 1 {
		t.Fatal("duplicate event")
	}
	s.recordDevices(map[string]deviceSnapshot{"new": disk}, nil)
	alerts, _ = s.Store.Alerts()
	if len(alerts) != 2 {
		t.Fatal("attach event missing")
	}
}
func TestExpectedEjectionDoesNotWarn(t *testing.T) {
	s := testServer(t)
	s.recordDevices(map[string]deviceSnapshot{"usb": {Path: "/dev/sdz", Busy: true}}, nil)
	j := management.Job{ID: "eject-test", Action: "disk.eject", Target: "/dev/sdz", Status: "succeeded", Updated: time.Now().UTC().Format(time.RFC3339)}
	s.recordDevices(map[string]deviceSnapshot{}, []management.Job{j})
	s.recordDevices(map[string]deviceSnapshot{}, []management.Job{j})
	alerts, _ := s.Store.Alerts()
	if len(alerts) != 1 || alerts[0].Active {
		t.Fatalf("expected one safe event: %+v", alerts)
	}
}
