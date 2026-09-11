package httpapi_test

import "testing"

func TestAlertRulesAndAlertsOverHTTP(t *testing.T) {
	e := newEnv(t)
	c := e.initialized(t)

	// create a rule
	var created struct{ ID string }
	body := map[string]any{"name": "High CPU", "metric": "cpu", "op": "gt", "threshold": 90}
	if code := c.do("POST", "/api/alert-rules", body, &created); code != 201 {
		t.Fatalf("create rule = %d", code)
	}
	// bad metric rejected
	if code := c.do("POST", "/api/alert-rules", map[string]any{"name": "x", "metric": "gpu", "op": "gt", "threshold": 5}, nil); code != 400 {
		t.Errorf("bad metric = %d, want 400", code)
	}
	var list []map[string]any
	c.do("GET", "/api/alert-rules", nil, &list)
	if len(list) != 1 || list[0]["metric"] != "cpu" {
		t.Fatalf("rules = %+v", list)
	}
	// alerts list is reachable and empty initially
	var alerts []map[string]any
	if code := c.do("GET", "/api/alerts", nil, &alerts); code != 200 || len(alerts) != 0 {
		t.Fatalf("alerts = %d %+v", code, alerts)
	}
	// delete the rule
	if code := c.do("DELETE", "/api/alert-rules/"+created.ID, nil, nil); code != 204 {
		t.Errorf("delete rule = %d", code)
	}
}

func TestTelemetryRbac(t *testing.T) {
	e := newEnv(t)
	owner := e.initialized(t)
	owner.do("POST", "/api/admins", map[string]string{"email": "ro@example.com", "password": "readonly-password-1", "role": "readonly"}, nil)
	ro := e.client(t)
	ro.loginFull("ro@example.com", "readonly-password-1", "")

	if code := ro.do("GET", "/api/alerts", nil, nil); code != 200 {
		t.Errorf("readonly list alerts = %d", code)
	}
	if code := ro.do("POST", "/api/alert-rules", map[string]any{"name": "x", "metric": "cpu", "op": "gt", "threshold": 5}, nil); code != 403 {
		t.Errorf("readonly create rule = %d, want 403", code)
	}
}
