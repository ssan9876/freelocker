package httpapi_test

import (
	"context"
	"testing"
)

func TestRingfenceAPI(t *testing.T) {
	e := newEnv(t)
	c := e.initialized(t)

	var created struct {
		ID string `json:"id"`
	}
	if code := c.do("POST", "/api/ringfences", map[string]string{"name": "Office"}, &created); code != 201 {
		t.Fatalf("create = %d", code)
	}
	// New ringfences must default to audit — never enforce.
	var list []map[string]any
	c.do("GET", "/api/ringfences", nil, &list)
	if len(list) != 1 || list[0]["mode"] != "audit" {
		t.Fatalf("list = %+v, want one audit-mode ringfence", list)
	}

	if code := c.do("POST", "/api/ringfences/"+created.ID+"/programs",
		map[string]any{"path": `C:\Program Files\App\app.exe`, "network_blocked": true}, nil); code != 201 {
		t.Errorf("add program = %d", code)
	}
	if code := c.do("PUT", "/api/ringfences/"+created.ID+"/protections",
		map[string]string{"asr_rule": "D4F940AB-401B-4EFC-AADC-AD5F3C50688A", "action": "block"}, nil); code != 204 {
		t.Errorf("set protection = %d", code)
	}
	// An ASR GUID outside the curated set is rejected.
	if code := c.do("PUT", "/api/ringfences/"+created.ID+"/protections",
		map[string]string{"asr_rule": "not-a-known-rule", "action": "block"}, nil); code != 400 {
		t.Errorf("unknown ASR rule = %d, want 400", code)
	}
	if code := c.do("POST", "/api/ringfences/"+created.ID+"/mode", map[string]string{"mode": "enforce"}, nil); code != 204 {
		t.Errorf("set mode = %d", code)
	}
	if code := c.do("POST", "/api/ringfences/"+created.ID+"/mode", map[string]string{"mode": "sideways"}, nil); code != 400 {
		t.Errorf("bad mode = %d, want 400", code)
	}

	// Readonly may read but not write.
	c.do("POST", "/api/admins", map[string]string{"email": "ro@example.com", "password": "readonly-password-1", "role": "readonly"}, nil)
	ro := e.client(t)
	ro.loginFull("ro@example.com", "readonly-password-1", "")
	if code := ro.do("GET", "/api/ringfences", nil, nil); code != 200 {
		t.Errorf("readonly list = %d, want 200", code)
	}
	if code := ro.do("POST", "/api/ringfences", map[string]string{"name": "Nope"}, nil); code != 403 {
		t.Errorf("readonly create = %d, want 403", code)
	}

	// Writes are audited.
	tenantID, err := e.store.FirstTenant(context.Background())
	if err != nil {
		t.Fatalf("FirstTenant: %v", err)
	}
	entries, _ := e.store.ListAudit(context.Background(), tenantID, 50, 0)
	seen := map[string]bool{}
	for _, en := range entries {
		seen[en.Action] = true
	}
	for _, want := range []string{"ringfence.create", "ringfence.program", "ringfence.protection", "ringfence.mode"} {
		if !seen[want] {
			t.Errorf("missing audit action %s", want)
		}
	}
}
