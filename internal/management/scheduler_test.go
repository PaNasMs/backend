package management

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"
)

func TestResourceConflicts(t *testing.T) {
	for _, tc := range []struct {
		a, b     string
		conflict bool
	}{
		{"file.copy", "smart.long", false}, {"user.create", "smart.schedule", false},
		{"file.copy", "disk.eject", true}, {"file.copy", "mount.detach", true},
		{"user.delete", "file.copy", true}, {"raid.delete", "filesystem.resize", true},
		{"updates.install", "smart.long", true}, {"service.restart", "file.copy", true},
		{"future.action", "smart.long", true}, {"smart.long", "smart.abort", true},
	} {
		if got := conflicts(resources(tc.a), resources(tc.b)); got != tc.conflict {
			t.Errorf("%s/%s: %v", tc.a, tc.b, got)
		}
	}
}
func TestSchedulerBypassesIndependentWorkWithoutStarvingWriters(t *testing.T) {
	workFor := func(action string) work { return work{Request: Request{Action: action}} }
	active := map[string][]resource{"file": resources("file.copy")}
	pending := []work{workFor("user.delete"), workFor("smart.long")}
	if runnable(pending, active) != 1 {
		t.Fatal("independent SMART operation blocked")
	}
	pending = []work{workFor("disk.eject"), workFor("smart.long")}
	if runnable(pending, active) != -1 {
		t.Fatal("exclusive operation can be starved")
	}
	if runnable(pending, map[string][]resource{}) != 0 {
		t.Fatal("queued writer not resumed")
	}
}

func TestWorkerRunsIndependentJobsAndRechecksCancelledStatus(t *testing.T) {
	m, err := Open(filepath.Join(t.TempDir(), "jobs.db"))
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan string, 4)
	release := make(chan struct{})
	m.run = func(ctx context.Context, mode, user string, body any) (json.RawMessage, error) {
		req := body.(Request)
		started <- req.ID
		if req.ID == "copy" {
			<-release
		}
		return json.RawMessage(`{}`), nil
	}
	defer func() { close(release); close(m.queue); <-m.finished; m.db.Close() }()
	enqueue := func(id, action, status string) {
		_, err := m.db.Exec("INSERT INTO jobs VALUES(?, 'alice',?,'target',?,'stage','now','now','{}')", id, action, status)
		if err != nil {
			t.Fatal(err)
		}
		m.queue <- work{Job: Job{ID: id, User: "alice", Action: action}, Request: Request{ID: id, Action: action}}
	}
	next := func() string {
		select {
		case id := <-started:
			return id
		case <-time.After(3 * time.Second):
			t.Fatal("worker stalled")
			return ""
		}
	}
	enqueue("copy", "file.copy", "queued")
	if next() != "copy" {
		t.Fatal("copy did not start")
	}
	enqueue("cancelled", "disk.eject", "queued")
	if !m.cancelQueued("cancelled") {
		t.Fatal("queued job not cancelled")
	}
	enqueue("smart", "smart.short", "queued")
	if next() != "smart" {
		t.Fatal("independent work blocked or cancelled job executed")
	}
}

func TestQueuedExclusiveWorkRunsBeforeLaterReaders(t *testing.T) {
	m, err := Open(filepath.Join(t.TempDir(), "jobs.db"))
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan string, 3)
	copyRelease := make(chan struct{})
	m.run = func(ctx context.Context, mode, user string, body any) (json.RawMessage, error) {
		id := body.(Request).ID
		started <- id
		if id == "copy" {
			<-copyRelease
		}
		return json.RawMessage(`{}`), nil
	}
	defer func() { close(m.queue); <-m.finished; m.db.Close() }()
	next := func() string {
		select {
		case id := <-started:
			return id
		case <-time.After(3 * time.Second):
			t.Fatal("worker stalled")
			return ""
		}
	}
	for _, row := range []struct{ id, action string }{{"copy", "file.copy"}, {"eject", "disk.eject"}, {"smart", "smart.short"}} {
		if _, err := m.db.Exec("INSERT INTO jobs VALUES(?,'alice',?,'target','queued','Queued','now','now','{}')", row.id, row.action); err != nil {
			t.Fatal(err)
		}
		m.queue <- work{Job: Job{ID: row.id, User: "alice"}, Request: Request{ID: row.id, Action: row.action}}
		if row.id == "copy" && next() != "copy" {
			t.Fatal("copy missing")
		}
	}
	close(copyRelease)
	if next() != "eject" || next() != "smart" {
		t.Fatal("exclusive queue order lost")
	}
}
