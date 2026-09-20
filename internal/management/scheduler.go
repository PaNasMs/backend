package management

import (
	"strings"
	"time"
)

type resource struct {
	name      string
	exclusive bool
}

// Unknown actions and service/package changes are exclusive: they may alter
// mount topology or helper binaries. Device aliases must not bypass this lock.
func resources(action string) []resource {
	switch {
	case strings.HasPrefix(action, "smart."):
		return []resource{{"system", false}, {"volumes", false}, {"smart", true}}
	case strings.HasPrefix(action, "file."), strings.HasPrefix(action, "user."), strings.HasPrefix(action, "group."):
		return []resource{{"system", false}, {"volumes", false}, {"data", true}}
	case strings.HasPrefix(action, "raid."), strings.HasPrefix(action, "disk."), strings.HasPrefix(action, "partition."), strings.HasPrefix(action, "filesystem."), strings.HasPrefix(action, "mount."), strings.HasPrefix(action, "luks."), strings.HasPrefix(action, "nfs."), strings.HasPrefix(action, "smb."), action == "folder.permissions":
		return []resource{{"system", false}, {"volumes", true}}
	default:
		return []resource{{"system", true}}
	}
}

func conflicts(a, b []resource) bool {
	for _, x := range a {
		for _, y := range b {
			if x.name == y.name && (x.exclusive || y.exclusive) {
				return true
			}
		}
	}
	return false
}

func runnable(pending []work, active map[string][]resource) int {
	for i, w := range pending {
		claim := resources(w.Request.Action)
		blocked := false
		for _, held := range active {
			if conflicts(claim, held) {
				blocked = true
				break
			}
		}
		// Preserve ordering for conflicting requests; a stream of compatible readers
		// must not starve a queued exclusive operation.
		for j := 0; j < i && !blocked; j++ {
			blocked = conflicts(claim, resources(pending[j].Request.Action))
		}
		if !blocked {
			return i
		}
	}
	return -1
}

func (m *Manager) worker() {
	defer close(m.finished)
	queue := m.queue
	pending := []work{}
	active := map[string][]resource{}
	done := make(chan string, 4)
	for queue != nil || len(pending) > 0 || len(active) > 0 {
		remaining := pending[:0]
		for _, w := range pending {
			var status string
			err := m.db.QueryRow("SELECT status FROM jobs WHERE id=?", w.Job.ID).Scan(&status)
			if err != nil || status == "queued" {
				remaining = append(remaining, w)
			}
		}
		pending = remaining
		for len(active) < 4 {
			i := runnable(pending, active)
			if i < 0 {
				break
			}
			w := pending[i]
			pending = append(pending[:i], pending[i+1:]...)
			active[w.Job.ID] = resources(w.Request.Action)
			go func() { m.execute(w); done <- w.Job.ID }()
		}
		if queue == nil && len(active) == 0 && len(pending) == 0 {
			return
		}
		select {
		case w, ok := <-queue:
			if !ok {
				queue = nil
			} else {
				pending = append(pending, w)
			}
		case <-m.wake:
		case id := <-done:
			delete(active, id)
		}
	}
}

func (m *Manager) cancelQueued(id string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	result, err := m.db.Exec("UPDATE jobs SET status='cancelled',stage='Cancelled before start',updated=? WHERE id=? AND status='queued'", time.Now().UTC().Format(time.RFC3339Nano), id)
	if err != nil {
		return false
	}
	n, err := result.RowsAffected()
	if err != nil || n != 1 {
		return false
	}
	select {
	case m.wake <- struct{}{}:
	default:
	}
	return true
}
