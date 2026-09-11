package httpapi_test

import (
	"context"
	"testing"
	"time"

	"freelocker/internal/server/store"

	"github.com/google/uuid"
)

// fakeDevice inserts an enrolled device directly through the store.
func (e *env) fakeDevice(t *testing.T) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	k := e.rt().Keys
	id := uuid.New()
	hash := []byte("fake-" + id.String())
	if _, err := e.store.CreateInstallToken(ctx, k.TenantID, store.InstallToken{Name: "fake"}, hash); err != nil {
		t.Fatal(err)
	}
	_, err := e.store.EnrollDevice(ctx, hash, time.Now(), func(uuid.UUID) (store.NewDevice, error) {
		return store.NewDevice{ID: id, Hostname: "pc-9", CertSerial: "s", CertExpiresAt: time.Now().Add(time.Hour)}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestTokensDevicesCommandsRevokeAudit(t *testing.T) {
	e := newEnv(t)
	c := e.initialized(t)

	var grp struct{ ID string }
	if code := c.do("POST", "/api/groups", map[string]string{"name": "Laptops"}, &grp); code != 201 {
		t.Fatalf("create group = %d", code)
	}
	if code := c.do("POST", "/api/groups", map[string]string{"name": "Laptops"}, nil); code != 409 {
		t.Errorf("duplicate group = %d, want 409", code)
	}
	var tok struct{ ID, Token string }
	if code := c.do("POST", "/api/tokens", map[string]any{"name": "HQ", "group_id": grp.ID, "expires_in_hours": 24, "max_uses": 10}, &tok); code != 201 || tok.Token == "" {
		t.Fatalf("create token = %d %+v", code, tok)
	}
	var toks []map[string]any
	c.do("GET", "/api/tokens", nil, &toks)
	if len(toks) != 1 || toks[0]["name"] != "HQ" || toks[0]["token"] != nil {
		t.Errorf("token list = %+v (must not include the secret)", toks)
	}

	dev := e.fakeDevice(t)
	var devs []map[string]any
	c.do("GET", "/api/devices?status=never_seen", nil, &devs)
	if len(devs) != 1 || devs[0]["hostname"] != "pc-9" {
		t.Fatalf("devices = %+v", devs)
	}
	var detail struct {
		Device        map[string]any `json:"device"`
		UninstallCode string         `json:"uninstall_code"`
	}
	c.do("GET", "/api/devices/"+dev.String(), nil, &detail)
	if detail.UninstallCode != e.rt().Keys.UninstallCode(dev) {
		t.Errorf("uninstall code = %q", detail.UninstallCode)
	}

	if code := c.do("POST", "/api/devices/"+dev.String()+"/commands", map[string]string{"type": "format_c"}, nil); code != 400 {
		t.Errorf("bad command type = %d, want 400", code)
	}
	var cmd struct{ ID string }
	if code := c.do("POST", "/api/devices/"+dev.String()+"/commands", map[string]string{"type": "ping"}, &cmd); code != 201 {
		t.Fatalf("issue command = %d", code)
	}
	var cmds []map[string]any
	c.do("GET", "/api/devices/"+dev.String()+"/commands", nil, &cmds)
	if len(cmds) != 1 || cmds[0]["id"] != cmd.ID || cmds[0]["state"] != "pending" {
		t.Errorf("commands = %+v", cmds)
	}

	if code := c.do("POST", "/api/devices/"+dev.String()+"/revoke", nil, nil); code != 204 {
		t.Fatalf("revoke = %d", code)
	}
	c.do("GET", "/api/devices/"+dev.String(), nil, &detail)
	if detail.Device["status"] != "revoked" {
		t.Errorf("status after revoke = %v", detail.Device["status"])
	}
	if code := c.do("POST", "/api/devices/"+dev.String()+"/commands", map[string]string{"type": "ping"}, nil); code != 409 {
		t.Errorf("command to revoked device = %d, want 409", code)
	}
	if code := c.do("GET", "/api/devices/"+uuid.NewString(), nil, nil); code != 404 {
		t.Errorf("unknown device = %d, want 404", code)
	}

	var audit []struct{ Action string }
	c.do("GET", "/api/audit?limit=50", nil, &audit)
	seen := map[string]bool{}
	for _, a := range audit {
		seen[a.Action] = true
	}
	for _, want := range []string{"group.create", "token.create", "command.issue", "device.revoke", "admin.login"} {
		if !seen[want] {
			t.Errorf("audit missing %s (have %v)", want, seen)
		}
	}
}

func TestRolesAndAdminManagement(t *testing.T) {
	e := newEnv(t)
	owner := e.initialized(t)

	var created struct{ ID string }
	body := map[string]string{"email": "ro@example.com", "password": "readonly-password-1", "role": "readonly"}
	if code := owner.do("POST", "/api/admins", body, &created); code != 201 {
		t.Fatalf("create admin = %d", code)
	}
	if code := owner.do("POST", "/api/admins", body, nil); code != 409 {
		t.Errorf("duplicate admin = %d, want 409", code)
	}
	if code := owner.do("POST", "/api/admins", map[string]string{"email": "x@example.com", "password": "some-password-12", "role": "god"}, nil); code != 400 {
		t.Errorf("bad role = %d, want 400", code)
	}

	dev := e.fakeDevice(t)
	ro := e.client(t)
	ro.loginFull("ro@example.com", "readonly-password-1", "")
	if code := ro.do("GET", "/api/devices", nil, nil); code != 200 {
		t.Errorf("readonly list devices = %d", code)
	}
	var detail map[string]any
	ro.do("GET", "/api/devices/"+dev.String(), nil, &detail)
	if _, ok := detail["uninstall_code"]; ok {
		t.Error("readonly must not see uninstall code")
	}
	for _, path := range []string{"/api/tokens", "/api/groups", "/api/devices/" + dev.String() + "/revoke"} {
		if code := ro.do("POST", path, map[string]string{"name": "x"}, nil); code != 403 {
			t.Errorf("readonly POST %s = %d, want 403", path, code)
		}
	}
	if code := ro.do("GET", "/api/admins", nil, nil); code != 403 {
		t.Errorf("readonly list admins = %d, want 403", code)
	}

	var me struct{ ID string }
	owner.do("GET", "/api/me", nil, &me)
	if code := owner.do("POST", "/api/admins/"+me.ID+"/disable", nil, nil); code != 400 {
		t.Errorf("self-disable = %d, want 400", code)
	}
	if code := owner.do("POST", "/api/admins/"+created.ID+"/disable", nil, nil); code != 204 {
		t.Fatalf("disable = %d", code)
	}
	if code := ro.do("GET", "/api/me", nil, nil); code != 401 {
		t.Errorf("disabled admin /api/me = %d, want 401", code)
	}
}
