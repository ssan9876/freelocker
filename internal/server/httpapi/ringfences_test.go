package httpapi_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
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

// TestAddRingfenceProgramDefaultsNetworkBlockedTrue covers FINDING 5: the
// schema's DEFAULT true and the console must agree. Omitting the field
// entirely (not sending false) must default to true, matching the schema.
func TestAddRingfenceProgramDefaultsNetworkBlockedTrue(t *testing.T) {
	e := newEnv(t)
	c := e.initialized(t)

	var rf struct {
		ID string `json:"id"`
	}
	c.do("POST", "/api/ringfences", map[string]string{"name": "Office"}, &rf)
	if code := c.do("POST", "/api/ringfences/"+rf.ID+"/programs",
		map[string]any{"path": `C:\a.exe`}, nil); code != 201 {
		t.Fatalf("add program = %d", code)
	}

	var detail struct {
		Programs []struct {
			NetworkBlocked bool `json:"network_blocked"`
		} `json:"programs"`
	}
	c.do("GET", "/api/ringfences/"+rf.ID, nil, &detail)
	if len(detail.Programs) != 1 || !detail.Programs[0].NetworkBlocked {
		t.Fatalf("programs = %+v, want network_blocked defaulted to true", detail.Programs)
	}
}

// TestUnassignRingfenceRequiresMatchingRingfenceID covers FINDING 3: an
// admin viewing ringfence A must not be able to detach ringfence B from a
// group that is actually assigned to B, by unassigning through A's page. The
// server is authoritative on what is currently assigned, not the client.
func TestUnassignRingfenceRequiresMatchingRingfenceID(t *testing.T) {
	e := newEnv(t)
	c := e.initialized(t)

	var rfA, rfB struct {
		ID string `json:"id"`
	}
	c.do("POST", "/api/ringfences", map[string]string{"name": "A"}, &rfA)
	c.do("POST", "/api/ringfences", map[string]string{"name": "B"}, &rfB)

	var grp struct {
		ID string `json:"id"`
	}
	c.do("POST", "/api/groups", map[string]string{"name": "WS"}, &grp)

	// Group is actually assigned to B.
	if code := c.do("POST", "/api/ringfences/"+rfB.ID+"/assign", map[string]string{"group_id": grp.ID}, nil); code != 204 {
		t.Fatalf("assign B = %d", code)
	}

	// No ringfence_id at all: rejected outright, not a silent detach.
	if code := c.do("DELETE", "/api/groups/"+grp.ID+"/ringfence", nil, nil); code != 400 {
		t.Errorf("unassign without ringfence_id = %d, want 400", code)
	}

	// Caller believes (wrongly) that A is assigned: must be refused with 409,
	// and B must remain assigned afterward.
	if code := c.do("DELETE", "/api/groups/"+grp.ID+"/ringfence?ringfence_id="+rfA.ID, nil, nil); code != 409 {
		t.Errorf("unassign with mismatched ringfence_id = %d, want 409", code)
	}

	// The correct ringfence_id (B) succeeds.
	if code := c.do("DELETE", "/api/groups/"+grp.ID+"/ringfence?ringfence_id="+rfB.ID, nil, nil); code != 204 {
		t.Errorf("unassign with matching ringfence_id = %d, want 204", code)
	}
}

// TestListRingfenceEventsDeviceIDFilter covers FINDING 4's HTTP surface: a
// bad device_id is a 400, and a well-formed one is accepted and passed
// through (the filtering logic itself is covered store-side in
// TestRingfenceEventsFilterByDevice).
func TestListRingfenceEventsDeviceIDFilter(t *testing.T) {
	e := newEnv(t)
	c := e.initialized(t)

	if code := c.do("GET", "/api/ringfence-events?device_id=not-a-uuid", nil, nil); code != 400 {
		t.Errorf("bad device_id = %d, want 400", code)
	}
	if code := c.do("GET", "/api/ringfence-events?device_id="+uuid.NewString(), nil, nil); code != 200 {
		t.Errorf("well-formed device_id = %d, want 200", code)
	}
}
