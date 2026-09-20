package management

import (
	"path/filepath"
	"testing"
)

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
	if e != nil || len(jobs) != 1 || jobs[0].Status != "interrupted" {
		t.Fatalf("%+v %v", jobs, e)
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
	if err != nil || len(jobs) != 2 {
		t.Fatalf("%+v %v", jobs, err)
	}
	for _, j := range jobs {
		if j.Status != "queued" && j.Status != "running" {
			t.Fatal(j)
		}
	}
	var count int
	if err := m.db.QueryRow("SELECT count(*) FROM jobs").Scan(&count); err != nil || count != 6 {
		t.Fatal("idempotency records removed", count, err)
	}
	if err := m.ClearHistory(); err != nil {
		t.Fatal(err)
	}
}
