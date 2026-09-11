package sim

import (
	"testing"
	"time"
)

func TestBackoff(t *testing.T) {
	lo := func() float64 { return 0 }
	hi := func() float64 { return 1 }
	if d := Backoff(0, lo); d != 500*time.Millisecond {
		t.Errorf("attempt 0 low = %v", d)
	}
	if d := Backoff(0, hi); d != time.Second {
		t.Errorf("attempt 0 high = %v", d)
	}
	if d := Backoff(3, hi); d != 8*time.Second {
		t.Errorf("attempt 3 high = %v", d)
	}
	if d := Backoff(50, hi); d != 5*time.Minute {
		t.Errorf("attempt 50 high = %v, want cap", d)
	}
	if d := Backoff(50, lo); d != 150*time.Second {
		t.Errorf("attempt 50 low = %v", d)
	}
}
