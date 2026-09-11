package httpapi_test

import "testing"

func TestGroupControlsOverHTTP(t *testing.T) {
	e := newEnv(t)
	c := e.initialized(t)

	var grp struct{ ID string }
	c.do("POST", "/api/groups", map[string]string{"name": "WS"}, &grp)

	// Default: not blocked.
	var got struct {
		USBStorageBlocked bool `json:"usb_storage_blocked"`
	}
	c.do("GET", "/api/groups/"+grp.ID+"/controls", nil, &got)
	if got.USBStorageBlocked {
		t.Error("default should be allow")
	}
	// Block it.
	if code := c.do("POST", "/api/groups/"+grp.ID+"/controls", map[string]bool{"usb_storage_blocked": true}, nil); code != 204 {
		t.Fatalf("set controls = %d", code)
	}
	c.do("GET", "/api/groups/"+grp.ID+"/controls", nil, &got)
	if !got.USBStorageBlocked {
		t.Error("controls should reflect the block")
	}
}

func TestControlsRbac(t *testing.T) {
	e := newEnv(t)
	owner := e.initialized(t)
	var grp struct{ ID string }
	owner.do("POST", "/api/groups", map[string]string{"name": "WS"}, &grp)
	owner.do("POST", "/api/admins", map[string]string{"email": "ro@example.com", "password": "readonly-password-1", "role": "readonly"}, nil)
	ro := e.client(t)
	ro.loginFull("ro@example.com", "readonly-password-1", "")

	if code := ro.do("GET", "/api/groups/"+grp.ID+"/controls", nil, nil); code != 200 {
		t.Errorf("readonly get controls = %d", code)
	}
	if code := ro.do("POST", "/api/groups/"+grp.ID+"/controls", map[string]bool{"usb_storage_blocked": true}, nil); code != 403 {
		t.Errorf("readonly set controls = %d, want 403", code)
	}
}
