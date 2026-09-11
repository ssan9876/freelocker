package httpapi

import (
	"testing"
	"time"
)

func TestLoginLimiter(t *testing.T) {
	l := newLoginLimiter()
	now := time.Now()
	for i := 0; i < maxFailures; i++ {
		if !l.allow("k", now) {
			t.Fatalf("attempt %d blocked early", i)
		}
		l.fail("k", now)
	}
	if l.allow("k", now) {
		t.Fatal("should be blocked after max failures")
	}
	if !l.allow("other", now) {
		t.Fatal("other keys unaffected")
	}
	if !l.allow("k", now.Add(failWindow+time.Second)) {
		t.Fatal("should unblock after window")
	}
	l.fail("k", now)
	l.reset("k")
	if !l.allow("k", now) {
		t.Fatal("reset should clear failures")
	}
}
