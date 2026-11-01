package api

import (
	"io"
	"sync/atomic"
	"time"

	"panasms.local/backend/internal/oled"
)

type transferActivity struct {
	id      uint64
	kind    string
	started time.Time
	total   int64
	loaded  atomic.Int64
}
type transferReader struct {
	io.ReadCloser
	activity *transferActivity
}

func (r *transferReader) Read(p []byte) (int, error) {
	n, e := r.ReadCloser.Read(p)
	r.activity.loaded.Add(int64(n))
	return n, e
}
func (s *Server) startTransfer(kind string, total int64) *transferActivity {
	t := &transferActivity{id: s.transferID.Add(1), kind: kind, total: total, started: time.Now()}
	s.transfers.Store(t.id, t)
	return t
}
func (s *Server) finishTransfer(t *transferActivity, success bool) {
	s.transfers.Delete(t.id)
	if time.Since(t.started) < 10*time.Second {
		return
	}
	message := "Transfer completed"
	if !success {
		message = "Transfer failed"
	}
	s.Store.Inform(transferEventID(t.id)+":"+t.started.UTC().Format(time.RFC3339Nano), message)
}
func (s *Server) transferSnapshot(now time.Time) []oled.Task {
	var tasks []oled.Task
	s.transfers.Range(func(_, v any) bool {
		t := v.(*transferActivity)
		if now.Sub(t.started) < 10*time.Second {
			return true
		}
		var percent *float64
		if t.total > 0 {
			p := min(99, float64(t.loaded.Load())/float64(t.total)*100)
			percent = &p
		}
		tasks = append(tasks, oled.Task{ID: transferEventID(t.id), Kind: t.kind, State: "running", Percent: percent, Started: t.started})
		return true
	})
	return tasks
}
