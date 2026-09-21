package management

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	_ "github.com/mattn/go-sqlite3"
	"io"
	"net/http"
	"os"
	"os/exec"
	"panasms.local/backend/internal/auth"
	"sync"
	"time"
)

type progressKey struct{}
type Request struct {
	Action       string         `json:"action"`
	Params       map[string]any `json:"params"`
	Fingerprint  string         `json:"fingerprint,omitempty"`
	Confirmation string         `json:"confirmation,omitempty"`
	ID           string         `json:"id,omitempty"`
}
type Job struct {
	ID              string          `json:"id"`
	User            string          `json:"user"`
	Action          string          `json:"action"`
	Target          string          `json:"target"`
	Status          string          `json:"status"`
	Stage           string          `json:"stage"`
	Created         string          `json:"created"`
	Updated         string          `json:"updated"`
	Result          json.RawMessage `json:"result"`
	CanCancel       bool            `json:"canCancel"`
	CancelRequested bool            `json:"cancelRequested"`
	NeedsReview     bool            `json:"needsReview"`
	Recovery        json.RawMessage `json:"recovery,omitempty"`
}
type work struct {
	Job     Job
	Request Request
}
type Manager struct {
	db         *sql.DB
	mu         sync.Mutex
	queue      chan work
	finished   chan struct{}
	wake       chan struct{}
	controlsMu sync.Mutex
	controls   map[string]*control
	run        func(context.Context, string, string, any) (json.RawMessage, error)
}

func helper(ctx context.Context, mode, user string, body any) (json.RawMessage, error) {
	raw, e := json.Marshal(body)
	if e != nil {
		return nil, e
	}
	cmd := exec.CommandContext(ctx, "/usr/bin/nsenter", "--mount=/proc/1/ns/mnt", "--", "/usr/bin/python3", "-B", "/usr/lib/panasms/management/main.py", mode, user)
	cmd.Stdin = bytes.NewReader(raw)
	if c, ok := ctx.Value(controlKey{}).(*control); ok {
		read, write, err := os.Pipe()
		if err != nil {
			return nil, err
		}
		defer read.Close()
		defer func() { c.mu.Lock(); c.allowed = false; write.Close(); c.write = nil; c.mu.Unlock() }()
		cmd.ExtraFiles = []*os.File{read}
		cmd.Env = append(os.Environ(), "PANASMS_CONTROL_FD=3")
		c.mu.Lock()
		c.write = write
		c.mu.Unlock()
	}
	// Helpers return bounded, redacted JSON, never subprocess output or credentials.
	var output bytes.Buffer
	cmd.Stdout = &output
	pipe, e := cmd.StderrPipe()
	if e != nil {
		return nil, e
	}
	if e = cmd.Start(); e != nil {
		return nil, e
	}
	scanner := bufio.NewScanner(pipe)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	for scanner.Scan() {
		var update struct {
			Stage       string `json:"stage"`
			Cancellable *bool  `json:"cancellable"`
		}
		if json.Unmarshal(scanner.Bytes(), &update) == nil {
			if update.Cancellable != nil {
				if c, ok := ctx.Value(controlKey{}).(*control); ok {
					c.mu.Lock()
					c.allowed = *update.Cancellable
					c.mu.Unlock()
				}
			}
			if update.Stage != "" && len(update.Stage) < 512 {
				if callback, ok := ctx.Value(progressKey{}).(func(string)); ok {
					callback(update.Stage)
				}
			}
		}
	}
	if scanner.Err() != nil {
		_, _ = io.Copy(io.Discard, pipe)
	}
	e = cmd.Wait()
	out := output.Bytes()
	if e != nil {
		return nil, errors.New("System handler unavailable")
	}
	if len(out) > 4<<20 || !json.Valid(out) {
		return nil, errors.New("Invalid handler response")
	}
	return out, nil
}
func Open(path string) (*Manager, error) {
	db, e := sql.Open("sqlite3", path+"?_journal_mode=WAL&_busy_timeout=5000")
	if e != nil {
		return nil, e
	}
	db.SetMaxOpenConns(1)
	_, e = db.Exec(`CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY, username TEXT NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL, status TEXT NOT NULL, stage TEXT NOT NULL, created TEXT NOT NULL, updated TEXT NOT NULL, result TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS hidden_jobs(id TEXT PRIMARY KEY);
 CREATE TABLE IF NOT EXISTS job_reviews(id TEXT PRIMARY KEY, checked TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS job_context(id TEXT PRIMARY KEY, context TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS job_recovery(id TEXT PRIMARY KEY, report TEXT NOT NULL, checked TEXT NOT NULL);
 UPDATE jobs SET status='cancelled',stage='Cancelled before start',updated=datetime('now') WHERE status='queued';
 UPDATE jobs SET status='interrupted',stage='Process interrupted. Check the actual state before retrying.',updated=datetime('now') WHERE status='running';`)
	if e != nil {
		db.Close()
		return nil, e
	}
	m := &Manager{db: db, queue: make(chan work, 32), finished: make(chan struct{}), wake: make(chan struct{}, 1), run: helper, controls: make(map[string]*control)}
	go m.worker()
	return m, nil
}
func (m *Manager) execute(w work) {
	m.mu.Lock()
	r, e := m.db.Exec("UPDATE jobs SET status='running',stage=?,updated=? WHERE id=? AND status='queued'", "In progress; the result will be checked", time.Now().UTC().Format(time.RFC3339Nano), w.Job.ID)
	n := int64(0)
	if e == nil {
		n, _ = r.RowsAffected()
	}
	m.mu.Unlock()
	if n == 0 {
		return
	}
	c := &control{}
	m.controlsMu.Lock()
	m.controls[w.Job.ID] = c
	m.controlsMu.Unlock()
	defer func() { m.controlsMu.Lock(); delete(m.controls, w.Job.ID); m.controlsMu.Unlock() }()
	ctx := context.WithValue(context.WithValue(context.Background(), controlKey{}, c), progressKey{}, func(stage string) {
		m.db.Exec("UPDATE jobs SET stage=?,updated=? WHERE id=? AND status='running'", stage, time.Now().UTC().Format(time.RFC3339Nano), w.Job.ID)
	})
	result, err := m.run(ctx, "execute", w.Job.User, w.Request)
	status := "succeeded"
	stage := "Done"
	var response struct {
		Error     string `json:"error"`
		Cancelled bool   `json:"cancelled"`
	}
	decodeError := json.Unmarshal(result, &response)
	if err == nil && decodeError != nil {
		err = errors.New("Invalid operation result; inspect the actual state")
	}
	if err != nil {
		status = "failed"
		stage = err.Error()
		result = json.RawMessage(`{}`)
	} else if response.Cancelled {
		status = "cancelled"
		stage = "Cancelled at a safe point; inspect the result before starting another operation"
	} else if response.Error != "" {
		status = "failed"
		stage = response.Error
	}
	m.db.Exec("UPDATE jobs SET status=?,stage=?,updated=?,result=? WHERE id=?", status, stage, time.Now().UTC().Format(time.RFC3339Nano), string(result), w.Job.ID)
}

func (m *Manager) List() ([]Job, error) {
	return m.list("id NOT IN (SELECT id FROM hidden_jobs) ORDER BY created DESC LIMIT 200")
}

func (m *Manager) Monitor(ids []string) ([]Job, error) {
	jobs, err := m.List()
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, j := range jobs {
		seen[j.ID] = true
	}
	for i, id := range ids {
		if i >= 200 {
			break
		}
		if seen[id] {
			continue
		}
		extra, err := m.list("id=?", id)
		if err != nil {
			return nil, err
		}
		jobs = append(jobs, extra...)
		seen[id] = true
	}
	for i := range jobs {
		jobs[i].Recovery = nil
		jobs[i].Result = json.RawMessage(`{}`)
	}
	return jobs, nil
}

func (m *Manager) list(filter string, args ...any) ([]Job, error) {
	rows, e := m.db.Query("SELECT id,username,action,target,status,stage,created,updated,result,(SELECT report FROM job_recovery WHERE job_recovery.id=jobs.id),EXISTS(SELECT 1 FROM job_reviews WHERE job_reviews.id=jobs.id) FROM jobs WHERE "+filter, args...)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	jobs := []Job{}
	for rows.Next() {
		var j Job
		var raw string
		var recovery sql.NullString
		var reviewed bool
		if e = rows.Scan(&j.ID, &j.User, &j.Action, &j.Target, &j.Status, &j.Stage, &j.Created, &j.Updated, &raw, &recovery, &reviewed); e != nil {
			return nil, e
		}
		j.Result = json.RawMessage(raw)
		j.NeedsReview = (j.Status == "failed" || j.Status == "interrupted" || (j.Status == "cancelled" && j.Stage != "Cancelled before start")) && !reviewed
		if recovery.Valid {
			j.Recovery = json.RawMessage(recovery.String)
		}
		j.CanCancel = j.Status == "queued"
		m.controlsMu.Lock()
		c := m.controls[j.ID]
		m.controlsMu.Unlock()
		if c != nil {
			c.mu.Lock()
			j.CanCancel = j.Status == "running" && c.allowed && !c.requested
			j.CancelRequested = c.requested
			c.mu.Unlock()
		}
		jobs = append(jobs, j)
	}
	return jobs, rows.Err()
}
func (m *Manager) ClearHistory() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, err := m.db.Exec("INSERT OR IGNORE INTO hidden_jobs SELECT id FROM jobs WHERE status='succeeded' OR (status='cancelled' AND stage='Cancelled before start') OR (status IN ('failed','interrupted','cancelled') AND id IN (SELECT id FROM job_reviews))")
	return err
}
func reply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
func (m *Manager) Handler(allowed map[string]bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.URL.Query().Get("user")
		if _, e := auth.Lookup(user, allowed); e != nil {
			reply(w, 403, map[string]string{"error": "Access denied"})
			return
		}
		if r.Method == "GET" {
			if r.URL.Query().Get("view") == "jobs" {
				j, e := m.List()
				if e != nil {
					reply(w, 503, map[string]string{"error": "Task log unavailable"})
					return
				}
				reply(w, 200, j)
				return
			}
			ctx, c := context.WithTimeout(r.Context(), 30*time.Second)
			defer c()
			v, e := m.run(ctx, "query", user, map[string]string{"view": r.URL.Query().Get("view"), "target": r.URL.Query().Get("target")})
			if e != nil {
				reply(w, 503, map[string]string{"error": e.Error()})
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write(v)
			return
		}
		if r.Method != "POST" {
			w.WriteHeader(405)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		var req Request
		d := json.NewDecoder(r.Body)
		d.DisallowUnknownFields()
		if d.Decode(&req) != nil || d.Decode(new(any)) != io.EOF {
			reply(w, 400, map[string]string{"error": "Invalid request"})
			return
		}
		if r.URL.Query().Get("view") == "clear-history" {
			if e := m.ClearHistory(); e != nil {
				reply(w, 503, map[string]string{"error": "Could not clear task history"})
				return
			}
			reply(w, 200, map[string]bool{"ok": true})
			return
		}
		if r.URL.Query().Get("view") == "cancel" {
			if err := m.cancel(req.ID); err != nil {
				reply(w, 409, map[string]string{"error": err.Error()})
				return
			}
			reply(w, 200, map[string]bool{"ok": true})
			return
		}
		if r.URL.Query().Get("view") == "acknowledge" {
			if err := m.acknowledge(req.ID); err != nil {
				reply(w, 409, map[string]string{"error": err.Error()})
				return
			}
			reply(w, 200, map[string]bool{"ok": true})
			return
		}
		if r.URL.Query().Get("view") == "recover" {
			ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
			defer cancel()
			result, err := m.inspect(ctx, req.ID, user)
			if err != nil {
				reply(w, 409, map[string]string{"error": err.Error()})
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write(result)
			return
		}
		if r.URL.Query().Get("view") == "plan" {
			ctx, c := context.WithTimeout(r.Context(), 30*time.Second)
			defer c()
			v, e := m.run(ctx, "plan", user, req)
			if e != nil {
				reply(w, 503, map[string]string{"error": e.Error()})
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write(v)
			return
		}
		if req.ID == "" || len(req.ID) > 100 || req.Fingerprint == "" {
			reply(w, 400, map[string]string{"error": "Review the operation plan first"})
			return
		}
		m.mu.Lock()
		defer m.mu.Unlock()
		var existing string
		if m.db.QueryRow("SELECT id FROM jobs WHERE id=? AND username=?", req.ID, user).Scan(&existing) == nil {
			reply(w, 200, map[string]string{"id": existing})
			return
		}
		var pending int
		if err := m.db.QueryRow("SELECT count(*) FROM jobs WHERE status IN ('queued','running')").Scan(&pending); err != nil {
			reply(w, 503, map[string]string{"error": "Queue unavailable"})
			return
		}
		if pending >= 32 || len(m.queue) == cap(m.queue) {
			reply(w, 429, map[string]string{"error": "Queue is full"})
			return
		}
		now := time.Now().UTC().Format(time.RFC3339Nano)
		target, _ := req.Params["target"].(string)
		if target == "" {
			target, _ = req.Params["name"].(string)
		}
		if len(target) > 512 {
			reply(w, 400, map[string]string{"error": "Target is too long"})
			return
		}
		j := Job{ID: req.ID, User: user, Action: req.Action, Target: target, Status: "queued", Stage: "Queued", Created: now, Updated: now, Result: json.RawMessage(`{}`)}
		tx, err := m.db.Begin()
		if err != nil {
			reply(w, 503, map[string]string{"error": "Task log unavailable"})
			return
		}
		_, err = tx.Exec("INSERT INTO jobs VALUES(?,?,?,?,?,?,?,?,?)", j.ID, j.User, j.Action, j.Target, j.Status, j.Stage, j.Created, j.Updated, "{}")
		if err == nil {
			_, err = tx.Exec("INSERT INTO job_context VALUES(?,?)", j.ID, recoveryContext(req))
		}
		if err == nil {
			err = tx.Commit()
		} else {
			tx.Rollback()
		}
		if err != nil {
			reply(w, 409, map[string]string{"error": "Task identifier already in use"})
			return
		}
		m.queue <- work{j, req}
		reply(w, 202, map[string]string{"id": j.ID})
	}
}
