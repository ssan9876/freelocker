package httpapi_test

import (
	"context"
	"testing"
)

type idResp struct {
	ID string `json:"id"`
}

func TestGroupRenameMoveDelete(t *testing.T) {
	e := newEnv(t)
	c := e.initialized(t)

	var g1, g2 idResp
	c.do("POST", "/api/groups", map[string]string{"name": "Laptops"}, &g1)
	c.do("POST", "/api/groups", map[string]string{"name": "Servers"}, &g2)

	if code := c.do("PATCH", "/api/groups/"+g1.ID, map[string]string{"name": "Servers"}, nil); code != 409 {
		t.Errorf("rename to duplicate = %d, want 409", code)
	}
	if code := c.do("PATCH", "/api/groups/"+g1.ID, map[string]string{"name": "  "}, nil); code != 400 {
		t.Errorf("rename to blank = %d, want 400", code)
	}
	if code := c.do("PATCH", "/api/groups/"+g1.ID, map[string]string{"name": "Notebooks"}, nil); code != 204 {
		t.Fatalf("rename = %d", code)
	}

	dev := e.fakeDevice(t).String()
	if code := c.do("POST", "/api/devices/"+dev+"/group", map[string]any{"group_id": g1.ID}, nil); code != 204 {
		t.Fatalf("move device = %d", code)
	}
	var d struct {
		Device struct {
			GroupID *string `json:"group_id"`
		} `json:"device"`
	}
	c.do("GET", "/api/devices/"+dev, nil, &d)
	if d.Device.GroupID == nil || *d.Device.GroupID != g1.ID {
		t.Fatalf("device group = %v, want %s", d.Device.GroupID, g1.ID)
	}
	if code := c.do("POST", "/api/devices/"+dev+"/group", map[string]any{"group_id": "00000000-0000-0000-0000-000000000001"}, nil); code != 404 {
		t.Errorf("move to unknown group = %d, want 404", code)
	}

	if code := c.do("DELETE", "/api/groups/"+g1.ID, nil, nil); code != 204 {
		t.Fatalf("delete group = %d", code)
	}
	d.Device.GroupID = nil
	c.do("GET", "/api/devices/"+dev, nil, &d)
	if d.Device.GroupID != nil {
		t.Errorf("device still in deleted group: %v", *d.Device.GroupID)
	}
	if code := c.do("DELETE", "/api/groups/"+g1.ID, nil, nil); code != 404 {
		t.Errorf("delete again = %d, want 404", code)
	}
}

func TestUpdateAlertRule(t *testing.T) {
	e := newEnv(t)
	c := e.initialized(t)
	var r idResp
	c.do("POST", "/api/alert-rules", map[string]any{"name": "cpu", "metric": "cpu", "op": "gt", "threshold": 90}, &r)

	bad := map[string]any{"name": "cpu", "metric": "cpu", "op": "gt", "threshold": 150, "duration_seconds": 0, "enabled": true}
	if code := c.do("PATCH", "/api/alert-rules/"+r.ID, bad, nil); code != 400 {
		t.Errorf("invalid threshold = %d, want 400", code)
	}
	upd := map[string]any{"name": "cpu high", "metric": "cpu", "op": "gt", "threshold": 80, "duration_seconds": 120, "enabled": false}
	if code := c.do("PATCH", "/api/alert-rules/"+r.ID, upd, nil); code != 204 {
		t.Fatalf("update = %d", code)
	}
	var rules []map[string]any
	c.do("GET", "/api/alert-rules", nil, &rules)
	if len(rules) != 1 || rules[0]["name"] != "cpu high" || rules[0]["threshold"] != 80.0 || rules[0]["enabled"] != false {
		t.Errorf("rules = %v", rules)
	}
	if code := c.do("PATCH", "/api/alert-rules/00000000-0000-0000-0000-000000000001", upd, nil); code != 404 {
		t.Errorf("update missing = %d, want 404", code)
	}
}

func TestAdminEnableAndRole(t *testing.T) {
	e := newEnv(t)
	c := e.initialized(t)
	var me idResp
	c.do("GET", "/api/me", nil, &me)

	var other idResp
	c.do("POST", "/api/admins", map[string]string{"email": "ops@example.com", "password": "ops-password-1234", "role": "admin"}, &other)

	// Changing your own role is refused, which (with owner-only access) means
	// at least one active owner always remains.
	if code := c.do("POST", "/api/admins/"+me.ID+"/role", map[string]string{"role": "admin"}, nil); code != 400 {
		t.Errorf("change own role = %d, want 400", code)
	}
	if code := c.do("POST", "/api/admins/"+other.ID+"/role", map[string]string{"role": "god"}, nil); code != 400 {
		t.Errorf("invalid role = %d, want 400", code)
	}
	if code := c.do("POST", "/api/admins/"+other.ID+"/role", map[string]string{"role": "owner"}, nil); code != 204 {
		t.Fatalf("promote = %d", code)
	}
	// Now two owners: demoting the other is fine, and leaves one again.
	if code := c.do("POST", "/api/admins/"+other.ID+"/role", map[string]string{"role": "readonly"}, nil); code != 204 {
		t.Fatalf("demote = %d", code)
	}

	c.do("POST", "/api/admins/"+other.ID+"/disable", nil, nil)
	if code := c.do("POST", "/api/admins/"+other.ID+"/enable", nil, nil); code != 204 {
		t.Fatalf("enable = %d", code)
	}
	var list []struct {
		ID       string
		Role     string
		Disabled bool
	}
	c.do("GET", "/api/admins", nil, &list)
	for _, a := range list {
		if a.ID == other.ID && (a.Disabled || a.Role != "readonly") {
			t.Errorf("other admin = %+v", a)
		}
	}
}

func TestProviderSuspendsTenant(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	prov := e.initialized(t)
	const betaOwner, betaPass = "owner@beta.example.com", "beta-password-1234"
	var cr struct {
		TenantID string `json:"tenant_id"`
	}
	prov.do("POST", "/api/provider/tenants", map[string]string{"org_name": "Beta", "owner_email": betaOwner, "owner_password": betaPass}, &cr)

	beta := e.client(t)
	secret := beta.loginFull(betaOwner, betaPass, "")

	defTenant, _ := e.store.FirstTenant(ctx)
	if code := prov.do("PATCH", "/api/provider/tenants/"+defTenant.String(), map[string]any{"suspended": true}, nil); code != 400 {
		t.Errorf("suspend own tenant = %d, want 400", code)
	}
	if code := prov.do("PATCH", "/api/provider/tenants/"+cr.TenantID, map[string]any{"name": "Beta Ltd", "suspended": true}, nil); code != 204 {
		t.Fatalf("suspend = %d", code)
	}
	var list []struct {
		ID        string
		Name      string
		Suspended bool
	}
	prov.do("GET", "/api/provider/tenants", nil, &list)
	if len(list) != 2 || list[1].Name != "Beta Ltd" || !list[1].Suspended {
		t.Errorf("tenants = %+v", list)
	}

	// Beta's live session is gone and it cannot log in again.
	if code := beta.do("GET", "/api/me", nil, nil); code != 401 {
		t.Errorf("suspended session /api/me = %d, want 401", code)
	}
	if code := e.client(t).do("POST", "/api/login", map[string]string{"email": betaOwner, "password": betaPass}, nil); code != 401 {
		t.Errorf("suspended login = %d, want 401", code)
	}

	if code := prov.do("PATCH", "/api/provider/tenants/"+cr.TenantID, map[string]any{"suspended": false}, nil); code != 204 {
		t.Fatalf("unsuspend = %d", code)
	}
	e.client(t).loginFull(betaOwner, betaPass, secret)
}
