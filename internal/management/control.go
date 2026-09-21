package management

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"sync"
	"time"
)

type controlKey struct{}
type control struct {
	mu        sync.Mutex
	write     *os.File
	allowed   bool
	requested bool
}

func (c *control) request() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.allowed || c.write == nil {
		return errors.New("This operation is past a safe cancellation point. Wait for completion; do not stop the service")
	}
	if c.requested {
		return nil
	}
	if _, err := c.write.Write([]byte{1}); err != nil {
		return errors.New("The operation has already finished")
	}
	c.requested = true
	return nil
}
func (m *Manager) cancel(id string) error {
	if m.cancelQueued(id) {
		return nil
	}
	m.controlsMu.Lock()
	c := m.controls[id]
	m.controlsMu.Unlock()
	if c == nil {
		return errors.New("The task is no longer running")
	}
	if err := c.request(); err != nil {
		return err
	}
	_, err := m.db.Exec("UPDATE jobs SET stage=?,updated=? WHERE id=? AND status='running'", "Cancellation requested; waiting for a safe stop and cleanup", time.Now().UTC().Format(time.RFC3339Nano), id)
	return err
}

// Recovery stores only object references. Passwords, tokens and executable input
// are never persisted or replayed from a job record.
func recoveryContext(req Request) string {
	result := map[string]string{}
	for _, key := range []string{"target", "destination", "point", "name", "interface"} {
		if value, ok := req.Params[key].(string); ok && len(value) <= 1024 {
			result[key] = value
		}
	}
	raw, _ := json.Marshal(result)
	return string(raw)
}
func (m *Manager) inspect(ctx context.Context, id, user string) (json.RawMessage, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var pending int
	if err := m.db.QueryRow("SELECT count(*) FROM jobs WHERE status IN ('queued','running')").Scan(&pending); err != nil {
		return nil, err
	}
	if pending > 0 {
		return nil, errors.New("Wait for active tasks before checking recovery")
	}
	var action, target, status, raw string
	err := m.db.QueryRow("SELECT j.action,j.target,j.status,COALESCE(c.context,'{}') FROM jobs j LEFT JOIN job_context c ON c.id=j.id WHERE j.id=?", id).Scan(&action, &target, &status, &raw)
	if err != nil {
		return nil, errors.New("Task not found")
	}
	if status != "interrupted" && status != "failed" && status != "cancelled" {
		return nil, errors.New("Wait for the running task before checking recovery")
	}
	params := map[string]string{}
	if json.Unmarshal([]byte(raw), &params) != nil {
		return nil, errors.New("Recovery metadata is unreadable")
	}
	if params["target"] == "" {
		params["target"] = target
	}
	result, err := m.run(ctx, "recover", user, map[string]any{"action": action, "params": params})
	if err != nil {
		return nil, err
	}
	var report struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(result, &report) != nil {
		return nil, errors.New("Invalid recovery report")
	}
	if report.Error != "" {
		return nil, errors.New(report.Error)
	}
	_, err = m.db.Exec("INSERT INTO job_recovery(id,report,checked) VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET report=excluded.report,checked=excluded.checked", id, string(result), time.Now().UTC().Format(time.RFC3339Nano))
	return result, err
}

func (m *Manager) acknowledge(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	result, err := m.db.Exec(`INSERT OR REPLACE INTO job_reviews(id,checked)
 SELECT j.id,? FROM jobs j JOIN job_recovery r ON r.id=j.id
 WHERE j.id=? AND j.status IN ('failed','interrupted','cancelled')`, time.Now().UTC().Format(time.RFC3339Nano), id)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return errors.New("Inspect the task before acknowledging its result")
	}
	return nil
}
