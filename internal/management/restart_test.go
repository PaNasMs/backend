package management

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"os/exec"
	"panasms.local/backend/internal/systemops"
	"path/filepath"
	"testing"
)

func TestJobCrashProcess(t *testing.T) {
	path := os.Getenv("PANASMS_TEST_JOB_DB")
	if path == "" {
		return
	}
	m, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = m.db.Exec("INSERT INTO jobs VALUES('crash','alice','raid.delete','target','queued','Queued','now','now','{}')")
	if err != nil {
		t.Fatal(err)
	}
	m.run = func(context.Context, string, string, any) (json.RawMessage, error) {
		os.Exit(74)
		return nil, nil
	}
	m.execute(work{Job: Job{ID: "crash", User: "alice"}})
	t.Fatal("crash point not reached")
}

func TestProcessDeathDuringOperationRetainsReviewableTask(t *testing.T) {
	path := filepath.Join(t.TempDir(), "jobs.db")
	child := exec.Command(os.Args[0], "-test.run=^TestJobCrashProcess$")
	child.Env = append(os.Environ(), "PANASMS_TEST_JOB_DB="+path)
	if err := child.Run(); err == nil {
		t.Fatal("child did not crash")
	} else if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 74 {
		t.Fatal(err)
	}
	m, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer m.db.Close()
	defer func() { close(m.queue); <-m.finished }()
	if err := m.ClearHistory(); err != nil {
		t.Fatal(err)
	}
	jobs, err := m.List()
	if err != nil || len(jobs) != 1 || jobs[0].Status != "interrupted" || !jobs[0].NeedsReview {
		t.Fatal(jobs, err)
	}
}

func TestLegacyJobsRecoveryNeverReplaysDestructiveWork(t *testing.T) {
	path := filepath.Join(t.TempDir(), "jobs.db")
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(migrations[0].SQL); err != nil {
		t.Fatal(err)
	}
	for _, entry := range []struct{ id, action, status string }{
		{"format", "filesystem.format", "running"},
		{"delete", "raid.delete", "queued"},
		{"done", "user.create", "succeeded"},
	} {
		if _, err = db.Exec("INSERT INTO jobs VALUES(?,'alice',?,'target',?,'stage','now','now','{}')", entry.id, entry.action, entry.status); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()
	for attempt := 0; attempt < 2; attempt++ {
		m, err := Open(path)
		if err != nil {
			t.Fatal(err)
		}
		jobs, err := m.List()
		if err != nil || len(jobs) != 3 {
			t.Fatal(jobs, err)
		}
		for _, j := range jobs {
			switch j.ID {
			case "format":
				if j.Status != "interrupted" || !j.NeedsReview || j.CanCancel {
					t.Fatal(j)
				}
			case "delete":
				if j.Status != "cancelled" || j.NeedsReview {
					t.Fatal(j)
				}
			case "done":
				if j.Status != "succeeded" {
					t.Fatal(j)
				}
			}
		}
		close(m.queue)
		<-m.finished
		m.db.Close()
	}
}

func TestCatalogFailureAfterRepairStaysReviewableAcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "jobs.db")
	m, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, job := range []struct {
		id, stage string
		unchanged bool
	}{
		{"stale", "State has changed. Review a new operation plan.", false},
		{"confirmation", "The exact operation target was not confirmed", false},
		{"clean", "State has changed. Review a new operation plan.", true},
	} {
		if _, err := m.db.Exec("INSERT INTO jobs VALUES(?,'admin','module.catalog-install','fixture','queued','Queued','now','now','{}')", job.id); err != nil {
			t.Fatal(err)
		}
		m.run = func(context.Context, string, string, any) (json.RawMessage, error) {
			return json.Marshal(systemops.Result{Error: job.stage, NoChanges: job.unchanged})
		}
		m.execute(work{Job: Job{ID: job.id, User: "admin"}, Request: Request{Action: "module.catalog-install"}})
	}
	m.Drain()
	m.db.Close()
	m, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer m.db.Close()
	defer m.Drain()
	if err := m.ClearHistory(); err != nil {
		t.Fatal(err)
	}
	jobs, err := m.List()
	if err != nil || len(jobs) != 2 {
		t.Fatal(jobs, err)
	}
	for _, job := range jobs {
		if job.ID == "clean" || job.Status != "failed" || !job.NeedsReview {
			t.Fatal(job)
		}
	}
}
