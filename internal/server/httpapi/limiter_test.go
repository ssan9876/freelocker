package httpapi

import (
	"context"
	"testing"
	"time"

	"freelocker/internal/server/store/storetest"
)

func TestLoginLimiter(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	tenant, _ := s.CreateTenant(ctx, "Acme")
	l := newLoginLimiter(s)
	now := time.Now()

	for i := 0; i < maxFailures; i++ {
		if !l.allow(ctx, tenant, "k", now) {
			t.Fatalf("attempt %d blocked early", i)
		}
		l.fail(ctx, tenant, "k", now)
	}
	if l.allow(ctx, tenant, "k", now) {
		t.Fatal("should be blocked after max failures")
	}
	if !l.allow(ctx, tenant, "other", now) {
		t.Fatal("other keys unaffected")
	}
	if !l.allow(ctx, tenant, "k", now.Add(failWindow+time.Second)) {
		t.Fatal("should unblock after the window slides past the failures")
	}
	l.fail(ctx, tenant, "k", now)
	l.reset(ctx, tenant, "k")
	if !l.allow(ctx, tenant, "k", now) {
		t.Fatal("reset should clear failures")
	}
}
