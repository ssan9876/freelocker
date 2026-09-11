package httpapi_test

import (
	"testing"
)

func TestSetupOnlyOnce(t *testing.T) {
	e := newEnv(t)
	c := e.client(t)
	var st struct{ Initialized bool }
	c.do("GET", "/api/setup/status", nil, &st)
	if st.Initialized {
		t.Fatal("fresh server must be uninitialized")
	}
	if code := c.do("POST", "/api/login", map[string]string{"email": "x@y.z", "password": "whatever-long"}, nil); code != 503 {
		t.Errorf("login before setup = %d, want 503", code)
	}
	if code := c.do("POST", "/api/setup", map[string]string{"org_name": "Acme", "email": ownerEmail, "password": "short"}, nil); code != 400 {
		t.Errorf("weak password setup = %d, want 400", code)
	}
	if code := c.do("POST", "/api/setup", map[string]string{"org_name": "Acme", "email": ownerEmail, "password": ownerPass}, nil); code != 201 {
		t.Fatalf("setup = %d", code)
	}
	if code := c.do("POST", "/api/setup", map[string]string{"org_name": "Evil", "email": "e@x.com", "password": ownerPass}, nil); code != 409 {
		t.Errorf("second setup = %d, want 409", code)
	}
}

func TestLoginRequiresPasswordThenMFA(t *testing.T) {
	e := newEnv(t)
	e.initialized(t)

	c := e.client(t)
	if code := c.do("POST", "/api/login", map[string]string{"email": ownerEmail, "password": "wrong-password-xx"}, nil); code != 401 {
		t.Errorf("bad password = %d", code)
	}
	var lr struct {
		CSRF string `json:"csrf_token"`
	}
	c.do("POST", "/api/login", map[string]string{"email": ownerEmail, "password": ownerPass}, &lr)
	c.csrf = lr.CSRF
	if code := c.do("GET", "/api/me", nil, nil); code != 403 {
		t.Errorf("/api/me before MFA = %d, want 403", code)
	}
	if code := c.do("POST", "/api/mfa/verify", map[string]string{"code": "000000"}, nil); code != 401 {
		t.Errorf("wrong TOTP = %d, want 401", code)
	}
}

func TestFullLoginMeCSRFAndLogout(t *testing.T) {
	e := newEnv(t)
	c := e.initialized(t)

	var me struct{ Email, Role string }
	if code := c.do("GET", "/api/me", nil, &me); code != 200 || me.Email != ownerEmail || me.Role != "owner" {
		t.Fatalf("/api/me = %d %+v", code, me)
	}
	good := c.csrf
	c.csrf = "forged"
	if code := c.do("POST", "/api/logout", nil, nil); code != 403 {
		t.Errorf("logout with bad CSRF = %d, want 403", code)
	}
	c.csrf = good
	if code := c.do("POST", "/api/logout", nil, nil); code != 204 {
		t.Errorf("logout = %d", code)
	}
	if code := c.do("GET", "/api/me", nil, nil); code != 401 {
		t.Errorf("/api/me after logout = %d, want 401", code)
	}
}

func TestLoginRateLimited(t *testing.T) {
	e := newEnv(t)
	e.initialized(t)
	c := e.client(t)
	codes := []int{}
	for i := 0; i < 6; i++ {
		codes = append(codes, c.do("POST", "/api/login", map[string]string{"email": ownerEmail, "password": "wrong-password-xx"}, nil))
	}
	if codes[4] != 401 || codes[5] != 429 {
		t.Errorf("codes = %v, want 5x401 then 429", codes)
	}
}
