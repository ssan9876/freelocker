package httpapi

import (
	"sync"
	"time"
)

const (
	maxFailures = 5
	failWindow  = 15 * time.Minute
)

// loginLimiter is an in-memory sliding-window failure counter. It is
// per-process; a multi-instance deployment would move this to Postgres.
type loginLimiter struct {
	mu    sync.Mutex
	fails map[string][]time.Time
}

func newLoginLimiter() *loginLimiter { return &loginLimiter{fails: map[string][]time.Time{}} }

func (l *loginLimiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	recent := l.fails[key][:0]
	for _, t := range l.fails[key] {
		if now.Sub(t) < failWindow {
			recent = append(recent, t)
		}
	}
	l.fails[key] = recent
	return len(recent) < maxFailures
}

func (l *loginLimiter) fail(key string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.fails[key] = append(l.fails[key], now)
}

func (l *loginLimiter) reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.fails, key)
}
