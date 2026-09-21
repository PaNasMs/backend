package management

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCancellationIsCooperativeAndIdempotent(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	c := &control{write: w}
	if c.request() == nil {
		t.Fatal("unsafe phase accepted cancellation")
	}
	c.allowed = true
	if err := c.request(); err != nil {
		t.Fatal(err)
	}
	if err := c.request(); err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 8)
	n, err := r.Read(data)
	if err != nil || n != 1 || data[0] != 1 {
		t.Fatalf("%v %v", data[:n], err)
	}
	c.allowed = false
	if c.request() == nil {
		t.Fatal("committing phase accepted cancellation")
	}
}

func TestRecoveryContextContainsNoSecrets(t *testing.T) {
	raw := recoveryContext(Request{Params: map[string]any{"target": "/srv/a", "destination": "/srv/b", "password": "SECRET", "passphrase": "SECRET", "upload": "SECRET", "credentials": map[string]string{"token": "SECRET"}}})
	if strings.Contains(raw, "SECRET") {
		t.Fatal("secret persisted")
	}
	if !strings.Contains(raw, "/srv/b") {
		t.Fatal("destination missing")
	}
}

func TestRecoveryInspectionAndBusyGuard(t *testing.T) {
	m, err := Open(filepath.Join(t.TempDir(), "jobs.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer m.db.Close()
	defer func() { close(m.queue); <-m.finished }()
	_, err = m.db.Exec("INSERT INTO jobs VALUES('broken','alice','file.copy','/srv/a','interrupted','stage','now','now','{}')")
	if err != nil {
		t.Fatal(err)
	}
	called := false
	m.run = func(ctx context.Context, mode, user string, body any) (json.RawMessage, error) {
		called = true
		if mode != "recover" || user != "alice" {
			t.Fatal("wrong helper identity")
		}
		return json.RawMessage(`{"message":"Inspect copies","checks":[],"route":"/files"}`), nil
	}
	if _, err = m.inspect(context.Background(), "broken", "alice"); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("inspection missing")
	}
	jobs, _ := m.List()
	if len(jobs) != 1 || len(jobs[0].Recovery) == 0 || !jobs[0].NeedsReview {
		t.Fatal(jobs)
	}
	if err = m.acknowledge("broken"); err != nil {
		t.Fatal(err)
	}
	jobs, _ = m.List()
	if jobs[0].NeedsReview {
		t.Fatal("acknowledgement not saved")
	}
	if err = m.ClearHistory(); err != nil {
		t.Fatal(err)
	}
	feed, err := m.Monitor([]string{"broken"})
	if err != nil || len(feed) != 1 || feed[0].NeedsReview || len(feed[0].Recovery) != 0 || string(feed[0].Result) != "{}" {
		t.Fatalf("hidden reviewed task lost: %v %v", feed, err)
	}
	_, err = m.db.Exec("INSERT INTO jobs VALUES('active','alice','raid.grow','disk','running','stage','now','now','{}')")
	if err != nil {
		t.Fatal(err)
	}
	called = false
	if _, err = m.inspect(context.Background(), "broken", "alice"); err == nil || called {
		t.Fatal("inspection raced active operation")
	}
}

func TestValidationFailureDoesNotRequireRecovery(t *testing.T) {
	m, err := Open(filepath.Join(t.TempDir(), "jobs.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer m.db.Close()
	defer func() { close(m.queue); <-m.finished }()
	m.run = func(context.Context, string, string, any) (json.RawMessage, error) {
		return json.RawMessage(`{"error":"Rejected before changes","noChanges":true}`), nil
	}
	_, err = m.db.Exec("INSERT INTO jobs VALUES('validation','alice','file.mkdir','/srv/a','queued','stage','now','now','{}')")
	if err != nil {
		t.Fatal(err)
	}
	m.execute(work{Job: Job{ID: "validation", User: "alice"}})
	jobs, err := m.List()
	if err != nil || len(jobs) != 1 || jobs[0].NeedsReview || jobs[0].Status != "failed" {
		t.Fatalf("%+v %v", jobs, err)
	}
	if err = m.ClearHistory(); err != nil {
		t.Fatal(err)
	}
	jobs, _ = m.List()
	if len(jobs) != 0 {
		t.Fatal("validation failure cannot be cleared")
	}
}
