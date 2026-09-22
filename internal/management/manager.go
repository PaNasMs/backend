package management

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/mattn/go-sqlite3"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"panasms.local/backend/internal/auth"
	"panasms.local/backend/internal/database"
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
	fault      error
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
	output := limitedOutput{limit: 4 << 20}
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
	if output.overflow || !json.Valid(out) {
		return nil, errors.New("Invalid handler response")
	}
	return out, nil
}
func Open(path string) (*Manager, error) {
	db, e := sql.Open("sqlite3", path+"?_journal_mode=WAL&_busy_timeout=5000&_synchronous=FULL&_txlock=immediate")
	if e != nil {
		return nil, e
	}
	db.SetMaxOpenConns(1)
	e = database.Migrate(db, "jobs", migrations)
	if e == nil {
		var tx *sql.Tx
		tx, e = db.Begin()
		if e == nil {
			_, e = tx.Exec(`
 INSERT OR IGNORE INTO job_reviews SELECT id,updated FROM jobs WHERE status='failed' AND stage IN ('The exact operation target was not confirmed','State has changed. Review a new operation plan.');
 UPDATE jobs SET status='cancelled',stage='Cancelled before start',updated=datetime('now') WHERE status='queued';
 UPDATE jobs SET status='interrupted',stage='Process interrupted. Check the actual state before retrying.',updated=datetime('now') WHERE status='running';`)
			if e == nil {
				e = tx.Commit()
			}
			tx.Rollback()
		}
	}
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
	if m.fault != nil {
		m.mu.Unlock()
		return
	}
	r, e := m.db.Exec("UPDATE jobs SET status='running',stage=?,updated=? WHERE id=? AND status='queued'", "In progress; the result will be checked", time.Now().UTC().Format(time.RFC3339Nano), w.Job.ID)
	n := int64(0)
	if e == nil {
		n, e = r.RowsAffected()
	}
	if e != nil {
		m.fault = e
		log.Printf("Task journal unavailable: %v", e)
	}
	m.mu.Unlock()
	if e != nil || n == 0 {
		return
	}
	c := &control{}
	m.controlsMu.Lock()
	m.controls[w.Job.ID] = c
	m.controlsMu.Unlock()
	defer func() { m.controlsMu.Lock(); delete(m.controls, w.Job.ID); m.controlsMu.Unlock() }()
	ctx := context.WithValue(context.WithValue(context.Background(), controlKey{}, c), progressKey{}, func(stage string) {
		if _, err := m.db.Exec("UPDATE jobs SET stage=?,updated=? WHERE id=? AND status='running'", stage, time.Now().UTC().Format(time.RFC3339Nano), w.Job.ID); err != nil {
			m.fail(err)
		}
	})
	result, err := m.run(ctx, "execute", w.Job.User, w.Request)
	status := "succeeded"
	stage := "Done"
	var response struct {
		Error     string `json:"error"`
		Cancelled bool   `json:"cancelled"`
		NoChanges bool   `json:"noChanges"`
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
	tx, saveError := m.db.Begin()
	if saveError == nil {
		defer tx.Rollback()
		_, saveError = tx.Exec("UPDATE jobs SET status=?,stage=?,updated=?,result=? WHERE id=?", status, stage, time.Now().UTC().Format(time.RFC3339Nano), string(result), w.Job.ID)
		if saveError == nil && status == "failed" && err == nil && response.NoChanges {
			_, saveError = tx.Exec("INSERT OR IGNORE INTO job_reviews(id,checked) VALUES(?,?)", w.Job.ID, time.Now().UTC().Format(time.RFC3339Nano))
		}
		if saveError == nil {
			saveError = tx.Commit()
		}
		tx.Rollback()
	}
	if saveError != nil {
		m.fail(saveError)
	}
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
func (m *Manager) clearHistoryFor(user string, admin bool) error {
	if admin {
		return m.ClearHistory()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	_, err := m.db.Exec("INSERT OR IGNORE INTO hidden_jobs SELECT id FROM jobs WHERE username=? AND (status='succeeded' OR (status='cancelled' AND stage='Cancelled before start') OR (status IN ('failed','interrupted','cancelled') AND id IN (SELECT id FROM job_reviews)))", user)
	return err
}
func userAction(action string, params map[string]any, user string) bool {
	switch action {
	case "file.mkdir", "file.copy", "file.move", "file.rename", "file.trash", "file.restore", "file.delete":
		return true
	case "user.session.end":
		return params["target"] == user
	}
	return false
}
func reply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
func (m *Manager) Handler(allowed map[string]bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.URL.Query().Get("user")
		id, e := auth.Lookup(user, allowed)
		if e != nil {
			reply(w, 403, map[string]string{"error": "Access denied"})
			return
		}
		m.serve(w, r, id)
	}
}

func (m *Manager) serve(w http.ResponseWriter, r *http.Request, id auth.Identity) {
	user := id.Username
	view := r.URL.Query().Get("view")
	if r.Method == "POST" && view != "plan" && view != "run" && view != "cancel" && view != "recover" && view != "acknowledge" && view != "clear-history" {
		reply(w, 400, map[string]string{"error": "Unknown management operation mode"})
		return
	}
	if r.Method == "GET" {
		if r.URL.Query().Get("view") == "jobs" || r.URL.Query().Get("view") == "job" {
			single := r.URL.Query().Get("view") == "job"
			var j []Job
			var e error
			if single {
				j, e = m.list("id=?", r.URL.Query().Get("target"))
			} else {
				j, e = m.List()
			}
			if e != nil {
				reply(w, 503, map[string]string{"error": "Task log unavailable"})
				return
			}
			if id.Role != "admin" {
				own := []Job{}
				for _, item := range j {
					if ownsJob(id, item.User, item.Created) {
						own = append(own, item)
					}
				}
				j = own
			}
			if single {
				if len(j) == 0 {
					reply(w, 404, map[string]string{"error": "Task not found"})
					return
				}
				reply(w, 200, j[0])
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
		if e := m.clearHistoryFor(user, id.Role == "admin"); e != nil {
			reply(w, 503, map[string]string{"error": "Could not clear task history"})
			return
		}
		reply(w, 200, map[string]bool{"ok": true})
		return
	}
	if id.Role != "admin" {
		view := r.URL.Query().Get("view")
		if view == "cancel" || view == "recover" || view == "acknowledge" {
			var owner, created string
			if m.db.QueryRow("SELECT username,created FROM jobs WHERE id=?", req.ID).Scan(&owner, &created) != nil || !ownsJob(id, owner, created) {
				reply(w, 403, map[string]string{"error": "Access denied"})
				return
			}
		} else if !userAction(req.Action, req.Params, user) {
			reply(w, 403, map[string]string{"error": "Administrator permissions required"})
			return
		}
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
	if m.fault != nil {
		reply(w, 503, map[string]string{"error": "Task journal unavailable. Restore database access and restart the agent; inspect interrupted operations before retrying."})
		return
	}
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
	defer tx.Rollback()
	_, err = tx.Exec("INSERT INTO jobs VALUES(?,?,?,?,?,?,?,?,?)", j.ID, j.User, j.Action, j.Target, j.Status, j.Stage, j.Created, j.Updated, "{}")
	if err == nil {
		_, err = tx.Exec("INSERT INTO job_context VALUES(?,?)", j.ID, recoveryContext(req))
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		var sqliteErr sqlite3.Error
		if errors.As(err, &sqliteErr) && (sqliteErr.ExtendedCode == sqlite3.ErrConstraintPrimaryKey || sqliteErr.ExtendedCode == sqlite3.ErrConstraintUnique) {
			reply(w, 409, map[string]string{"error": "Task identifier already in use"})
		} else {
			m.fault = err
			log.Printf("Task journal unavailable: %v", err)
			reply(w, 503, map[string]string{"error": "Task log unavailable; operation was not started"})
		}
		return
	}
	m.queue <- work{j, req}
	reply(w, 202, map[string]string{"id": j.ID})
}

func ownsJob(id auth.Identity, username, created string) bool {
	if id.Username != username {
		return false
	}
	if id.Created == "" {
		return true
	}
	since, e := time.Parse(time.RFC3339Nano, id.Created)
	if e != nil {
		return false
	}
	when, e := time.Parse(time.RFC3339Nano, created)
	return e == nil && !when.Before(since)
}
