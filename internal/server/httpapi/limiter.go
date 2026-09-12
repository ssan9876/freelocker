package httpapi

import (
	"context"
	"time"

	"freelocker/internal/server/store"

	"github.com/google/uuid"
)

const (
	maxFailures = 5
	failWindow  = 15 * time.Minute
)

// loginLimiter is a Postgres-backed sliding-window failure counter, so the
// rate limit holds across all server instances rather than per process.
type loginLimiter struct {
	store *store.Store
}

func newLoginLimiter(s *store.Store) *loginLimiter { return &loginLimiter{store: s} }

// allow reports whether another attempt is permitted for the key.
func (l *loginLimiter) allow(ctx context.Context, tenantID uuid.UUID, key string, now time.Time) bool {
	n, err := l.store.CountLoginFailures(ctx, tenantID, key, now.Add(-failWindow))
	if err != nil {
		return true // fail open: never lock out on a transient DB error
	}
	return n < maxFailures
}

func (l *loginLimiter) fail(ctx context.Context, tenantID uuid.UUID, key string, now time.Time) {
	l.store.RecordLoginFailure(ctx, tenantID, key, now)
}

func (l *loginLimiter) reset(ctx context.Context, tenantID uuid.UUID, key string) {
	l.store.ClearLoginFailures(ctx, tenantID, key)
}
