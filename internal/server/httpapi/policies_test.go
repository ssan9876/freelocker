package httpapi_test

import (
	"strings"
	"testing"
)

func hex64(c string) string { return strings.Repeat(c, 64)[:64] }

func TestPolicyLifecycleOverHTTP(t *testing.T) {
	e := newEnv(t)
	c := e.initialized(t)

	var created struct{ ID string }
	if code := c.do("POST", "/api/policies", map[string]string{"name": "Baseline"}, &created); code != 201 {
		t.Fatalf("create policy = %d", code)
	}
	// add a hash rule
	var ruleResp struct{ ID, Version string }
	body := map[string]string{"kind": "hash", "value": hex64("a"), "description": "notepad"}
	if code := c.do("POST", "/api/policies/"+created.ID+"/rules", body, &ruleResp); code != 201 || ruleResp.Version == "" {
		t.Fatalf("add rule = %d %+v", code, ruleResp)
	}
	// bad rule rejected
	if code := c.do("POST", "/api/policies/"+created.ID+"/rules", map[string]string{"kind": "hash", "value": "short"}, nil); code != 400 {
		t.Errorf("bad rule = %d, want 400", code)
	}
	// mode toggle
	if code := c.do("POST", "/api/policies/"+created.ID+"/mode", map[string]string{"mode": "enforce"}, nil); code != 204 {
		t.Errorf("set mode = %d", code)
	}
	// detail reflects mode + rules + a version
	var detail struct {
		Policy  map[string]any   `json:"policy"`
		Rules   []map[string]any `json:"rules"`
		Version string           `json:"version"`
	}
	c.do("GET", "/api/policies/"+created.ID, nil, &detail)
	if detail.Policy["mode"] != "enforce" || len(detail.Rules) != 1 || detail.Version == "" {
		t.Fatalf("detail = %+v", detail)
	}

	// assign to a group
	var grp struct{ ID string }
	c.do("POST", "/api/groups", map[string]string{"name": "WS"}, &grp)
	if code := c.do("POST", "/api/policies/"+created.ID+"/assign", map[string]string{"group_id": grp.ID}, nil); code != 204 {
		t.Errorf("assign = %d", code)
	}
}

func TestPromoteObservationCreatesRule(t *testing.T) {
	e := newEnv(t)
	c := e.initialized(t)

	var pol struct{ ID string }
	c.do("POST", "/api/policies", map[string]string{"name": "Baseline"}, &pol)
	body := map[string]string{"policy_id": pol.ID, "sha256": hex64("b"), "description": "learned app"}
	if code := c.do("POST", "/api/observations/promote", body, nil); code != 201 {
		t.Fatalf("promote = %d", code)
	}
	var detail struct {
		Rules []map[string]any `json:"rules"`
	}
	c.do("GET", "/api/policies/"+pol.ID, nil, &detail)
	if len(detail.Rules) != 1 || detail.Rules[0]["value"] != strings.ToUpper(hex64("b")) {
		t.Fatalf("promoted rule missing: %+v", detail.Rules)
	}
}

func TestPolicyRbacReadonlyCannotMutate(t *testing.T) {
	e := newEnv(t)
	owner := e.initialized(t)
	owner.do("POST", "/api/admins", map[string]string{"email": "ro@example.com", "password": "readonly-password-1", "role": "readonly"}, nil)
	ro := e.client(t)
	ro.loginFull("ro@example.com", "readonly-password-1", "")

	if code := ro.do("GET", "/api/policies", nil, nil); code != 200 {
		t.Errorf("readonly list policies = %d", code)
	}
	if code := ro.do("POST", "/api/policies", map[string]string{"name": "X"}, nil); code != 403 {
		t.Errorf("readonly create policy = %d, want 403", code)
	}
}
