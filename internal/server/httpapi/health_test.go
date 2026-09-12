package httpapi_test

import "testing"

func TestHealthAndReady(t *testing.T) {
	e := newEnv(t)
	c := e.client(t)

	var h struct{ Status string }
	if code := c.do("GET", "/healthz", nil, &h); code != 200 || h.Status != "ok" {
		t.Fatalf("healthz = %d %+v", code, h)
	}

	// Ready before setup: DB reachable, not initialized.
	var r struct {
		Status      string `json:"status"`
		Database    bool   `json:"database"`
		Initialized bool   `json:"initialized"`
	}
	if code := c.do("GET", "/readyz", nil, &r); code != 200 || !r.Database || r.Initialized {
		t.Fatalf("readyz pre-setup = %d %+v", code, r)
	}

	// After setup, initialized is true.
	e.initialized(t)
	c.do("GET", "/readyz", nil, &r)
	if !r.Initialized {
		t.Errorf("readyz should report initialized after setup: %+v", r)
	}
}
