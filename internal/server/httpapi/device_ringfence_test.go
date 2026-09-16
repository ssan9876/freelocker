package httpapi_test

import "testing"

type deviceRingfenceView struct {
	Ringfence *struct {
		ID   string `json:"id"`
		Name string `json:"name"`
		Mode string `json:"mode"`
	} `json:"ringfence"`
	Programs []struct {
		Path           string `json:"path"`
		NetworkBlocked bool   `json:"network_blocked"`
	} `json:"programs"`
	Protections []struct {
		ASRRule string `json:"asr_rule"`
		Action  string `json:"action"`
	} `json:"protections"`
}

// The device page has to answer "what is contained on this machine". Until
// now the console rendered an apology in its place because no read endpoint
// existed.
func TestDeviceRingfenceOverHTTP(t *testing.T) {
	e := newEnv(t)
	c := e.initialized(t)

	var g idResp
	c.do("POST", "/api/groups", map[string]string{"name": "WS"}, &g)
	dev := e.fakeDevice(t).String()
	c.do("POST", "/api/devices/"+dev+"/group", map[string]any{"group_id": g.ID}, nil)

	// A device with no ringfence is not an error — it is a 200 saying "none".
	// A 404 here would be indistinguishable from "device does not exist".
	var v deviceRingfenceView
	if code := c.do("GET", "/api/devices/"+dev+"/ringfence", nil, &v); code != 200 {
		t.Fatalf("unassigned device = %d, want 200", code)
	}
	if v.Ringfence != nil {
		t.Fatalf("unassigned device reported ringfence %+v, want null", v.Ringfence)
	}

	var rf idResp
	c.do("POST", "/api/ringfences", map[string]string{"name": "Office"}, &rf)
	c.do("POST", "/api/ringfences/"+rf.ID+"/programs",
		map[string]any{"path": `C:\Program Files\App\app.exe`, "network_blocked": true}, nil)
	c.do("PUT", "/api/ringfences/"+rf.ID+"/protections",
		map[string]string{"asr_rule": "D4F940AB-401B-4EFC-AADC-AD5F3C50688A", "action": "audit"}, nil)
	c.do("POST", "/api/ringfences/"+rf.ID+"/assign", map[string]string{"group_id": g.ID}, nil)

	v = deviceRingfenceView{}
	if code := c.do("GET", "/api/devices/"+dev+"/ringfence", nil, &v); code != 200 {
		t.Fatalf("assigned device = %d, want 200", code)
	}
	if v.Ringfence == nil || v.Ringfence.Name != "Office" || v.Ringfence.ID != rf.ID {
		t.Fatalf("ringfence = %+v, want Office/%s", v.Ringfence, rf.ID)
	}
	if v.Ringfence.Mode != "audit" {
		t.Errorf("mode = %q, want audit (the schema default)", v.Ringfence.Mode)
	}
	// The contained programs are the substance of the answer, not decoration:
	// naming the ringfence without saying what it contains sends the admin to
	// another page to learn anything useful.
	if len(v.Programs) != 1 || !v.Programs[0].NetworkBlocked {
		t.Fatalf("programs = %+v, want the one network-blocked entry", v.Programs)
	}
	if len(v.Protections) != 1 || v.Protections[0].Action != "audit" {
		t.Fatalf("protections = %+v, want one audit-mode ASR rule", v.Protections)
	}

	// A device that does not exist is still a 404.
	if code := c.do("GET", "/api/devices/00000000-0000-0000-0000-000000000001/ringfence", nil, nil); code != 404 {
		t.Errorf("unknown device = %d, want 404", code)
	}
}

// Reads are allowed for any role, matching every other ringfence read.
func TestDeviceRingfenceReadableByReadOnlyRole(t *testing.T) {
	e := newEnv(t)
	c := e.initialized(t)
	dev := e.fakeDevice(t).String()

	c.do("POST", "/api/admins", map[string]string{"email": "ro@example.com", "password": "readonly-password-1", "role": "readonly"}, nil)
	ro := e.client(t)
	ro.loginFull("ro@example.com", "readonly-password-1", "")

	if code := ro.do("GET", "/api/devices/"+dev+"/ringfence", nil, nil); code != 200 {
		t.Errorf("read-only GET = %d, want 200", code)
	}
}
