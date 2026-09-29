package management

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/mattn/go-sqlite3"
)

func TestSQLiteFullAfterMutationSuspendsFurtherWork(t *testing.T) {
	path := filepath.Join(t.TempDir(), "jobs.db")
	m, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = m.db.Exec(`INSERT INTO jobs VALUES('one','alice','raid.delete','disk','queued','Queued','now','now','{}');
 INSERT INTO jobs VALUES('two','alice','filesystem.format','disk','queued','Queued','now','now','{}');`); err != nil {
		t.Fatal(err)
	}
	var pages int
	if err = m.db.QueryRow("PRAGMA page_count").Scan(&pages); err != nil {
		t.Fatal(err)
	}
	if _, err = m.db.Exec("PRAGMA max_page_count=" + strconv.Itoa(pages)); err != nil {
		t.Fatal(err)
	}
	calls := 0
	m.run = func(context.Context, string, string, any) (json.RawMessage, error) {
		calls++
		return json.Marshal(map[string]string{"data": strings.Repeat("x", 1<<20)})
	}
	for _, id := range []string{"one", "two"} {
		m.execute(work{Job: Job{ID: id, User: "alice"}, Request: Request{ID: id}})
	}
	var full sqlite3.Error
	if calls != 1 || !errors.As(m.fault, &full) || full.Code != sqlite3.ErrFull {
		t.Fatalf("expected actual SQLITE_FULL to stop further work: calls=%d fault=%v", calls, m.fault)
	}
	var first, second string
	if err = m.db.QueryRow("SELECT status FROM jobs WHERE id='one'").Scan(&first); err != nil {
		t.Fatal(err)
	}
	if err = m.db.QueryRow("SELECT status FROM jobs WHERE id='two'").Scan(&second); err != nil {
		t.Fatal(err)
	}
	if first != "running" || second != "queued" {
		t.Fatalf("unexpected durable state after SQLITE_FULL: %s, %s", first, second)
	}
	if _, err = m.db.Exec("PRAGMA max_page_count=" + strconv.Itoa(pages+1024)); err != nil {
		t.Fatal(err)
	}
	close(m.queue)
	<-m.finished
	if err = m.db.Close(); err != nil {
		t.Fatal(err)
	}
	recovered, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.db.Close()
	defer func() { close(recovered.queue); <-recovered.finished }()
	jobs, err := recovered.List()
	if err != nil || len(jobs) != 2 {
		t.Fatalf("recovery did not preserve both jobs: %+v %v", jobs, err)
	}
	for _, job := range jobs {
		if job.ID == "one" && (job.Status != "interrupted" || !job.NeedsReview) {
			t.Fatal("completed physical mutation lost its review state", job)
		}
		if job.ID == "two" && job.Status != "cancelled" {
			t.Fatal("queued mutation was replayed after recovery", job)
		}
	}
}

func TestJournalFailureStopsFollowingMutations(t *testing.T) {
	m, err := Open(filepath.Join(t.TempDir(), "jobs.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer m.db.Close()
	defer func() { close(m.queue); <-m.finished }()
	_, err = m.db.Exec(`INSERT INTO jobs VALUES('one','alice','raid.delete','disk','queued','Queued','now','now','{}');
 INSERT INTO jobs VALUES('two','alice','filesystem.format','disk','queued','Queued','now','now','{}');
 CREATE TRIGGER full_journal BEFORE UPDATE ON jobs WHEN NEW.status='succeeded' BEGIN SELECT RAISE(FAIL,'database or disk is full'); END;`)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	m.run = func(context.Context, string, string, any) (json.RawMessage, error) {
		calls++
		return json.RawMessage(`{}`), nil
	}
	for _, id := range []string{"one", "two"} {
		m.execute(work{Job: Job{ID: id, User: "alice"}, Request: Request{ID: id}})
	}
	if calls != 1 || m.fault == nil {
		t.Fatal("unsafe continued execution", calls, m.fault)
	}
	var status string
	if err = m.db.QueryRow("SELECT status FROM jobs WHERE id='one'").Scan(&status); err != nil || status != "running" {
		t.Fatal(status, err)
	}
	if err = m.db.QueryRow("SELECT status FROM jobs WHERE id='two'").Scan(&status); err != nil || status != "queued" {
		t.Fatal(status, err)
	}
}

func TestJournalFailureBeforeStartNeverCallsHelper(t *testing.T) {
	m, err := Open(filepath.Join(t.TempDir(), "jobs.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer m.db.Close()
	defer func() { close(m.queue); <-m.finished }()
	_, err = m.db.Exec(`INSERT INTO jobs VALUES('one','alice','raid.delete','disk','queued','Queued','now','now','{}');
 CREATE TRIGGER broken_journal BEFORE UPDATE ON jobs BEGIN SELECT RAISE(FAIL,'read-only database'); END;`)
	if err != nil {
		t.Fatal(err)
	}
	m.run = func(context.Context, string, string, any) (json.RawMessage, error) {
		t.Fatal("mutation ran without persistent running state")
		return nil, nil
	}
	m.execute(work{Job: Job{ID: "one", User: "alice"}})
	if m.fault == nil {
		t.Fatal("journal failure not latched")
	}
}
