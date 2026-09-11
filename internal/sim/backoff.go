package sim

import "time"

const (
	backoffBase = time.Second
	backoffCap  = 5 * time.Minute
)

// Backoff returns the delay before reconnect attempt n (0-based) using
// capped exponential backoff with equal jitter.
func Backoff(attempt int, rnd func() float64) time.Duration {
	d := backoffCap
	if attempt < 20 {
		d = min(backoffBase<<attempt, backoffCap)
	}
	half := d / 2
	return half + time.Duration(rnd()*float64(half))
}
