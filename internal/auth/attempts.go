package auth

import (
	"sync"
	"time"
)

type attemptWindow struct {
	at    time.Time
	count int
}
type AttemptLimiter struct {
	mu      sync.Mutex
	windows map[string]attemptWindow
}

func (l *AttemptLimiter) Permit(user string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.windows == nil {
		l.windows = map[string]attemptWindow{}
	}
	for key, w := range l.windows {
		if now.Sub(w.at) >= time.Minute {
			delete(l.windows, key)
		}
	}
	w, exists := l.windows[user]
	if exists && w.count >= 10 {
		return false
	}
	if !exists {
		if len(l.windows) >= 1024 {
			oldest := ""
			for key, v := range l.windows {
				if oldest == "" || v.at.Before(l.windows[oldest].at) {
					oldest = key
				}
			}
			delete(l.windows, oldest)
		}
		w.at = now
	}
	w.count++
	l.windows[user] = w
	return true
}
