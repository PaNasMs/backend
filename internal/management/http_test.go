package management

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"panasms.local/backend/internal/auth"
)

func httpManager(t *testing.T) *Manager {
	t.Helper()
	m, err := Open(filepath.Join(t.TempDir(), "jobs.db"))
	if err != nil {
		t.Fatal(err)
	}
	close(m.queue)
	<-m.finished
	m.queue = make(chan work, 32)
	t.Cleanup(func() { m.db.Close() })
	return m
}

func call(t *testing.T, m *Manager, user, role, method, view, body string, want int) string {
	t.Helper()
	r := httptest.NewRequest(method, "/manage?view="+view, strings.NewReader(body))
	w := httptest.NewRecorder()
	m.serve(w, r, auth.Identity{Username: user, Role: role})
	if w.Code != want {
		t.Fatalf("%s %s: %d %s", method, view, w.Code, w.Body.String())
	}
	return w.Body.String()
}

func TestSubmissionIsIdempotentAndOwnershipIsEnforced(t *testing.T) {
	m := httpManager(t)
	body := `{"id":"one","action":"file.copy","params":{"target":"/source","destination":"/destination","password":"SECRET"},"fingerprint":"fresh","confirmation":"source"}`
	call(t, m, "alice", "user", "POST", "run", body, 202)
	call(t, m, "alice", "user", "POST", "run", body, 200)
	if len(m.queue) != 1 {
		t.Fatal("duplicate queued")
	}
	call(t, m, "bob", "user", "GET", "job&target=one", "", 404)
	call(t, m, "bob", "user", "POST", "cancel", `{"id":"one"}`, 403)
	call(t, m, "bob", "user", "POST", "run", body, 409)
	var context string
	if err := m.db.QueryRow("SELECT context FROM job_context WHERE id='one'").Scan(&context); err != nil || strings.Contains(context, "SECRET") {
		t.Fatal("unsafe recovery context", err)
	}
	call(t, m, "alice", "user", "POST", "cancel", `{"id":"one"}`, 200)
	call(t, m, "alice", "user", "POST", "clear-history", `{}`, 200)
	if got := call(t, m, "alice", "user", "GET", "jobs", "", 200); strings.TrimSpace(got) != "[]" {
		t.Fatal(got)
	}
	call(t, m, "alice", "user", "POST", "run", body, 200)
	if len(m.queue) != 1 {
		t.Fatal("hidden task replayed")
	}
}

func TestBadModesAndInvalidJSONCannotStartWork(t *testing.T) {
	m := httpManager(t)
	m.run = func(context.Context, string, string, any) (json.RawMessage, error) {
		t.Fatal("unexpected helper")
		return nil, nil
	}
	call(t, m, "alice", "admin", "POST", "typo", `{"id":"one","action":"raid.delete","fingerprint":"x","params":{}}`, 400)
	call(t, m, "alice", "admin", "POST", "run", `{} {}`, 400)
	call(t, m, "alice", "admin", "POST", "run", `{"unexpected":true}`, 400)
	call(t, m, "alice", "user", "POST", "run", `{"action":"raid.delete","params":{}}`, 403)
	if len(m.queue) != 0 {
		t.Fatal("invalid operation queued")
	}
}

func TestSubmissionDatabaseFailureIsNotReportedAsIDConflict(t *testing.T) {
	m := httpManager(t)
	if _, err := m.db.Exec("CREATE TRIGGER full_journal BEFORE INSERT ON jobs BEGIN SELECT RAISE(FAIL,'database or disk is full'); END;"); err != nil {
		t.Fatal(err)
	}
	body := `{"id":"one","action":"file.copy","params":{},"fingerprint":"x"}`
	call(t, m, "alice", "admin", "POST", "run", body, 503)
	call(t, m, "alice", "admin", "POST", "run", body, 503)
	var count int
	if err := m.db.QueryRow("SELECT count(*) FROM jobs").Scan(&count); err != nil || count != 0 || len(m.queue) != 0 {
		t.Fatal("partially queued mutation", count, err)
	}
}
