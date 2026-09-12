package httpapi_test

import "testing"

type controlsView struct {
	Overrides map[string]*bool `json:"overrides"`
	Group     map[string]bool  `json:"group"`
	Effective map[string]bool  `json:"effective"`
}

func TestDeviceControlOverridesOverHTTP(t *testing.T) {
	e := newEnv(t)
	c := e.initialized(t)
	var g idResp
	c.do("POST", "/api/groups", map[string]string{"name": "Kiosks"}, &g)
	c.do("POST", "/api/groups/"+g.ID+"/controls", map[string]bool{"usb_storage_blocked": true}, nil)
	dev := e.fakeDevice(t).String()
	c.do("POST", "/api/devices/"+dev+"/group", map[string]any{"group_id": g.ID}, nil)

	var v controlsView
	if code := c.do("GET", "/api/devices/"+dev+"/controls", nil, &v); code != 200 {
		t.Fatalf("get = %d", code)
	}
	if v.Overrides["usb_storage_blocked"] != nil || !v.Group["usb_storage_blocked"] || !v.Effective["usb_storage_blocked"] {
		t.Fatalf("initial view = %+v", v)
	}

	body := map[string]any{"usb_storage_blocked": false, "network_blocked": true, "elevation_blocked": nil}
	if code := c.do("POST", "/api/devices/"+dev+"/controls", body, nil); code != 204 {
		t.Fatalf("set = %d", code)
	}
	v = controlsView{}
	c.do("GET", "/api/devices/"+dev+"/controls", nil, &v)
	usb, net := v.Overrides["usb_storage_blocked"], v.Overrides["network_blocked"]
	if usb == nil || *usb || net == nil || !*net || v.Overrides["elevation_blocked"] != nil {
		t.Errorf("overrides = %+v", v.Overrides)
	}
	if v.Effective["usb_storage_blocked"] || !v.Effective["network_blocked"] || v.Effective["elevation_blocked"] || !v.Group["usb_storage_blocked"] {
		t.Errorf("effective = %+v group = %+v", v.Effective, v.Group)
	}

	unknown := "00000000-0000-0000-0000-000000000001"
	if code := c.do("GET", "/api/devices/"+unknown+"/controls", nil, nil); code != 404 {
		t.Errorf("unknown device get = %d, want 404", code)
	}
	if code := c.do("POST", "/api/devices/"+unknown+"/controls", body, nil); code != 404 {
		t.Errorf("unknown device set = %d, want 404", code)
	}
}

func TestDeviceControlOverridesRbac(t *testing.T) {
	e := newEnv(t)
	owner := e.initialized(t)
	dev := e.fakeDevice(t).String()
	owner.do("POST", "/api/admins", map[string]string{"email": "ro@example.com", "password": "readonly-password-1", "role": "readonly"}, nil)
	ro := e.client(t)
	ro.loginFull("ro@example.com", "readonly-password-1", "")

	if code := ro.do("GET", "/api/devices/"+dev+"/controls", nil, nil); code != 200 {
		t.Errorf("readonly get = %d, want 200", code)
	}
	if code := ro.do("POST", "/api/devices/"+dev+"/controls", map[string]any{"network_blocked": true}, nil); code != 403 {
		t.Errorf("readonly set = %d, want 403", code)
	}
}
