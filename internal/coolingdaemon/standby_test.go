package coolingdaemon

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const sleepingJSON = `{"smartctl":{"messages":[{"string":"Device is in STANDBY mode"}]}}`

func TestStandbyPowerState(t *testing.T) {
	for _, tc := range []struct {
		name, raw, state string
		code             int
		err              error
	}{
		{"standby", sleepingJSON, "sleeping", 3, nil},
		{"active", `{}`, "active", 0, nil},
		{"open error", `{}`, "unknown", 2, nil},
		{"unsupported", `{}`, "unknown", 5, nil},
		{"ambiguous status", `{}`, "unknown", 3, nil},
		{"broken json", `oops`, "unknown", 0, nil},
		{"timeout", ``, "unknown", -1, context.DeadlineExceeded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newStandbyReader(filepath.Join(t.TempDir(), "cache"))
			r.command = func(_ context.Context, args ...string) ([]byte, int, error) {
				if strings.Join(args, " ") != "-n standby,3,5 -d ata -i -j disk" {
					t.Fatal(args)
				}
				return []byte(tc.raw), tc.code, tc.err
			}
			state, err := r.powerState(context.Background(), "disk")
			if state != tc.state || (err != nil) != (tc.state == "unknown") {
				t.Fatalf("%s %v", state, err)
			}
		})
	}
}

func TestStandbyProbeOutcomes(t *testing.T) {
	for _, tc := range []struct {
		name           string
		postCode       int
		postRaw        string
		readErr        error
		readRaw        string
		concurrent     bool
		activityErr    bool
		wantState      string
		wantCapability string
	}{
		{name: "readable", postCode: 3, postRaw: sleepingJSON, wantState: "sleeping", wantCapability: "true"},
		{name: "wakes disk", postRaw: `{}`, wantState: "unknown", wantCapability: "false"},
		{name: "concurrent wake", postRaw: `{}`, concurrent: true, wantState: "unknown"},
		{name: "concurrent read asleep again", postCode: 3, postRaw: sleepingJSON, concurrent: true, wantState: "sleeping"},
		{name: "timeout sleeping", postCode: 3, postRaw: sleepingJSON, readErr: context.DeadlineExceeded, wantState: "sleeping"},
		{name: "timeout wakes", postRaw: `{}`, readErr: context.DeadlineExceeded, wantState: "unknown"},
		{name: "missing temperature", postCode: 3, postRaw: sleepingJSON, readRaw: `{}`, wantState: "sleeping"},
		{name: "post check open error", postCode: 2, postRaw: `{}`, wantState: "unknown"},
		{name: "activity unavailable", activityErr: true, wantState: "sleeping"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "cache")
			r := newStandbyReader(path)
			now := time.Unix(1000, 0)
			r.now = func() time.Time { return now }
			calls, stats := 0, 0
			r.activity = func(string) (string, error) {
				stats++
				if tc.activityErr {
					return "", fmt.Errorf("unavailable")
				}
				if tc.concurrent && stats > 1 {
					return "changed", nil
				}
				return "unchanged", nil
			}
			r.command = func(_ context.Context, args ...string) ([]byte, int, error) {
				calls++
				switch calls {
				case 1:
					return []byte(sleepingJSON), 3, nil
				case 2:
					raw := tc.readRaw
					if raw == "" {
						raw = `{"temperature":{"current":44}}`
					}
					return []byte(raw), 0, tc.readErr
				case 3:
					return []byte(tc.postRaw), tc.postCode, nil
				default:
					t.Fatal("unexpected extra probe")
					return nil, 0, nil
				}
			}
			row := r.read(context.Background(), "disk", Disk{Path: "disk", State: "sleeping", Stale: true})
			if row.State != tc.wantState {
				t.Fatalf("%+v", row)
			}
			capability := r.cache.Disks["disk"]
			got := ""
			if capability.Readable != nil {
				got = fmt.Sprint(*capability.Readable)
			}
			if got != tc.wantCapability {
				t.Fatalf("capability %s, want %s", got, tc.wantCapability)
			}
			if tc.wantCapability == "true" {
				if !row.SleepTemperature || row.Stale || row.Temperature == nil || *row.Temperature != 44 || !row.SmartStale {
					t.Fatalf("%+v", row)
				}
			} else {
				if row.SleepTemperature {
					t.Fatal("stale reading marked fresh")
				}
				previous := calls
				r.read(context.Background(), "disk", Disk{State: "sleeping"})
				if calls != previous {
					t.Fatal("retried before cooldown / retried unsupported disk")
				}
				reloaded := newStandbyReader(path)
				if tc.wantCapability == "false" {
					if reloaded.cache.Disks["disk"].Readable == nil || *reloaded.cache.Disks["disk"].Readable {
						t.Fatal("negative capability not persisted")
					}
				} else if !reloaded.cache.Disks["disk"].RetryAt.After(now) {
					t.Fatal("retry delay lost on restart")
				}
			}
		})
	}
}

func TestStandbyRetriesRecover(t *testing.T) {
	r := newStandbyReader(filepath.Join(t.TempDir(), "cache"))
	now := time.Unix(1000, 0)
	r.now = func() time.Time { return now }
	unavailable := true
	r.activity = func(string) (string, error) {
		if unavailable {
			return "", fmt.Errorf("busy")
		}
		return "idle", nil
	}
	for i := 0; i < 20; i++ {
		r.read(context.Background(), "disk", Disk{State: "sleeping"})
		entry := r.cache.Disks["disk"]
		delay := entry.RetryAt.Sub(now)
		if delay <= 0 || delay > time.Hour || entry.Readable != nil {
			t.Fatalf("%+v", entry)
		}
		now = entry.RetryAt
	}
	unavailable = false
	r.command = func(_ context.Context, args ...string) ([]byte, int, error) {
		if args[0] == "-n" {
			return []byte(sleepingJSON), 3, nil
		}
		return []byte(`{"temperature":{"current":40}}`), 0, nil
	}
	row := r.read(context.Background(), "disk", Disk{State: "sleeping"})
	if !row.SleepTemperature || r.cache.Disks["disk"].Failures != 0 {
		t.Fatalf("%+v", row)
	}
}

func TestStandbyCacheMigration(t *testing.T) {
	for _, raw := range []string{`null`, `broken`, `{"good":true,"bad":false}`} {
		path := filepath.Join(t.TempDir(), "cache")
		if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		r := newStandbyReader(path)
		if r.cache.Disks == nil || r.cache.Disks["bad"].Readable != nil {
			t.Fatal("invalid negative survived migration")
		}
		if strings.Contains(raw, "good") && r.cache.Disks["good"].Readable == nil {
			t.Fatal("lost positive capability")
		}
	}
}

func TestMixedSleepingCoolingDemand(t *testing.T) {
	for _, tc := range []struct {
		name      string
		disks     []Disk
		cpu, want float64
	}{
		{"known hot plus unreadable", append(readSleep(44), Disk{State: "sleeping"}), 40, .75},
		{"CPU fallback stronger", append(readSleep(37), Disk{State: "sleeping"}), 65, .75},
		{"active cool plus unreadable", []Disk{{State: "active", Temperature: ptr(29)}, {State: "sleeping"}}, 62, .5},
		{"active warm plus unreadable", []Disk{{State: "active", Temperature: ptr(42)}, {State: "sleeping"}}, 40, .75},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := target("balanced", tc.disks, ptr(tc.cpu), false, 0, false, false, false)
			if got != tc.want {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
}

func TestTemperatureDoesNotRefreshSMART(t *testing.T) {
	path := filepath.Join(t.TempDir(), "disk")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	previous := parseDisk(path, []byte(`{"temperature":{"current":35},"smart_status":{"passed":true}}`), 0)
	previous.SmartObservedAt = ptr(100)
	got := cachedDisk(Disk{Path: path, State: "sleeping", Temperature: ptr(40), ObservedAt: ptr(200), SleepTemperature: true}, previous)
	if got.Stale || !got.SmartStale || got.SmartObservedAt == nil || *got.SmartObservedAt != 100 || *got.ObservedAt != 200 || got.Health != "passed" {
		t.Fatalf("%+v", got)
	}
}
