package management

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestLifecycleOwnsMaintenanceWhileOtherJobsKeepSharedBarrier(t *testing.T) {
	path := filepath.Join(t.TempDir(), "maintenance.lock")
	if err := os.WriteFile(path, nil, 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PANASMS_MAINTENANCE_LOCK", path)
	m, err := Open(filepath.Join(t.TempDir(), "jobs.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer m.db.Close()
	defer func() { close(m.queue); <-m.finished }()
	for _, action := range []string{"module.install", "module.enable", "module.disable", "module.remove", "module.recover", "module.catalog-install", "module.source-add", "module.custom", "group.create"} {
		t.Run(action, func(t *testing.T) {
			if _, err := m.db.Exec("INSERT INTO jobs VALUES(?, 'alice', ?, 'target', 'queued', 'Waiting', 'now', 'now', '{}')", action, action); err != nil {
				t.Fatal(err)
			}
			called := false
			m.run = func(context.Context, string, string, any) (json.RawMessage, error) {
				called = true
				file, err := os.Open(path)
				if err != nil {
					t.Fatal(err)
				}
				defer file.Close()
				err = unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
				owns := action == "module.install" || action == "module.enable" || action == "module.disable" || action == "module.remove" || action == "module.recover" || action == "module.catalog-install"
				if owns && err != nil || !owns && !errors.Is(err, unix.EWOULDBLOCK) {
					t.Fatal("wrong maintenance ownership", action, err)
				}
				return json.RawMessage(`{}`), nil
			}
			m.execute(work{Job: Job{ID: action, User: "alice", Action: action}, Request: Request{Action: action}})
			if !called {
				t.Fatal("job never ran")
			}
		})
	}
}

func TestMissingInitializedJobJournalStopsAgent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "jobs.db")
	m, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	close(m.queue)
	<-m.finished
	if err = m.db.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(path + ".initialized"); err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err = Open(path); err == nil || !strings.Contains(err.Error(), "restore the database") {
		t.Fatalf("missing job journal was not rejected: %v", err)
	}
	if _, err = os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("empty job journal was created: %v", err)
	}
}

func TestInterruptedOperationsAreNotReplayed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "jobs.db")
	m, e := Open(path)
	if e != nil {
		t.Fatal(e)
	}
	_, e = m.db.Exec("INSERT INTO jobs VALUES('one','alice','raid.delete','disk','running','work','now','now','{}')")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = m.db.Exec("INSERT INTO jobs VALUES('queued-before-restart','alice','file.copy','file','queued','waiting','now','now','{}')"); e != nil {
		t.Fatal(e)
	}
	close(m.queue)
	<-m.finished
	m.db.Close()
	next, e := Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer next.db.Close()
	defer func() { close(next.queue); <-next.finished }()
	jobs, e := next.List()
	if e != nil || len(jobs) != 2 {
		t.Fatalf("%+v %v", jobs, e)
	}
	for _, j := range jobs {
		if j.ID == "one" && (j.Status != "interrupted" || !j.NeedsReview) {
			t.Fatal(j)
		}
		if j.ID == "queued-before-restart" && (j.Status != "cancelled" || j.NeedsReview) {
			t.Fatal(j)
		}
	}
	if len(next.queue) != 0 {
		t.Fatal("destructive task replayed")
	}
}

func TestClearHistoryKeepsActiveJobsAndIds(t *testing.T) {
	m, err := Open(filepath.Join(t.TempDir(), "jobs.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer m.db.Close()
	defer func() { close(m.queue); <-m.finished }()
	for _, status := range []string{"queued", "running", "succeeded", "failed", "interrupted", "cancelled"} {
		if _, err := m.db.Exec("INSERT INTO jobs VALUES(?, 'alice','mount.attach','disk',?,'stage','now','now','{}')", status, status); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.ClearHistory(); err != nil {
		t.Fatal(err)
	}
	jobs, err := m.List()
	if err != nil || len(jobs) != 5 {
		t.Fatalf("%+v %v", jobs, err)
	}
	for _, j := range jobs {
		if j.Status == "succeeded" {
			t.Fatal("completed task not cleared")
		}
		if j.Status == "failed" && !j.NeedsReview {
			t.Fatal("failed task did not require review")
		}
	}
	for _, id := range []string{"failed", "interrupted", "cancelled"} {
		if err := m.acknowledge(id); err == nil {
			t.Fatal("acknowledged without inspection")
		}
		if _, err := m.db.Exec("INSERT INTO job_recovery VALUES(?,'{}','now')", id); err != nil {
			t.Fatal(err)
		}
		if err := m.acknowledge(id); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.ClearHistory(); err != nil {
		t.Fatal(err)
	}
	jobs, err = m.List()
	if err != nil || len(jobs) != 2 {
		t.Fatalf("%+v %v", jobs, err)
	}
	var count int
	if err := m.db.QueryRow("SELECT count(*) FROM jobs").Scan(&count); err != nil || count != 6 {
		t.Fatal("idempotency records removed", count, err)
	}
	if err := m.ClearHistory(); err != nil {
		t.Fatal(err)
	}
}

func TestJobProgressSurvivesReadingFromJournal(t *testing.T) {
	m, err := Open(filepath.Join(t.TempDir(), "jobs.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { close(m.queue); <-m.finished; m.db.Close() }()
	_, err = m.db.Exec("INSERT INTO jobs VALUES('progress','alice','file.copy','folder','running','work','now','now','{}'); INSERT INTO job_progress VALUES('progress',42.5)")
	if err != nil {
		t.Fatal(err)
	}
	jobs, err := m.list("id=?", "progress")
	if err != nil || len(jobs) != 1 || jobs[0].Percent == nil || *jobs[0].Percent != 42.5 {
		t.Fatalf("jobs=%+v err=%v", jobs, err)
	}
	_, err = m.db.Exec("DELETE FROM job_progress WHERE id='progress'")
	if err != nil {
		t.Fatal(err)
	}
	jobs, err = m.list("id=?", "progress")
	if err != nil || jobs[0].Percent != nil {
		t.Fatal("unknown progress must remain absent", err)
	}
}
