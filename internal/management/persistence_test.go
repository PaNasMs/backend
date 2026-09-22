package management

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
)

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
