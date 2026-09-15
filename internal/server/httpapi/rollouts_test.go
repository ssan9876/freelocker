package httpapi_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

func mustUUID(t *testing.T, s string) uuid.UUID {
	t.Helper()
	id, err := uuid.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

type rolloutJSON struct {
	ID          string   `json:"id"`
	Version     string   `json:"version"`
	GroupIDs    []string `json:"group_ids"`
	BatchSize   int      `json:"batch_size"`
	MaxFailures int      `json:"max_failures"`
	State       string   `json:"state"`
	CreatedBy   string   `json:"created_by"`
	Summary     struct {
		Targeted, AlreadyCurrent, Issued, Updated, Failed, Remaining int
	} `json:"summary"`
	Devices []struct {
		DeviceID string `json:"device_id"`
		Hostname string `json:"hostname"`
		State    string `json:"state"`
	} `json:"devices"`
}

func TestRolloutLifecycleOverHTTP(t *testing.T) {
	e := newEnv(t)
	c := e.initialized(t)
	c.uploadRelease(t, "1.0.0")
	c.uploadRelease(t, "1.0.1")
	var g idResp
	c.do("POST", "/api/groups", map[string]string{"name": "Pilot"}, &g)
	dev := e.fakeDevice(t)
	c.do("POST", "/api/devices/"+dev.String()+"/group", map[string]any{"group_id": g.ID}, nil)

	// Validation.
	if code := c.do("POST", "/api/rollouts", map[string]any{"version": "nope"}, nil); code != 404 {
		t.Errorf("unknown version = %d, want 404", code)
	}
	if code := c.do("POST", "/api/rollouts", map[string]any{"version": "1.0.1", "batch_size": 0}, nil); code != 400 {
		t.Errorf("batch_size 0 = %d, want 400", code)
	}
	if code := c.do("POST", "/api/rollouts", map[string]any{"version": "1.0.1", "max_failures": -1}, nil); code != 400 {
		t.Errorf("negative max_failures = %d, want 400", code)
	}

	var created idResp
	if code := c.do("POST", "/api/rollouts", map[string]any{"version": "1.0.1", "group_ids": []string{g.ID}, "batch_size": 5}, &created); code != 201 {
		t.Fatalf("create = %d", code)
	}
	if code := c.do("POST", "/api/rollouts", map[string]any{"version": "1.0.0"}, nil); code != 409 {
		t.Errorf("second open rollout = %d, want 409", code)
	}

	var got rolloutJSON
	if code := c.do("GET", "/api/rollouts/"+created.ID, nil, &got); code != 200 {
		t.Fatalf("get = %d", code)
	}
	if got.Version != "1.0.1" || got.State != "active" || got.BatchSize != 5 || got.MaxFailures != 3 || len(got.GroupIDs) != 1 || got.GroupIDs[0] != g.ID || got.CreatedBy != "admin:"+ownerEmail {
		t.Errorf("rollout = %+v", got)
	}
	if got.Summary.Targeted != 1 || got.Summary.Remaining != 1 {
		t.Errorf("summary = %+v", got.Summary)
	}

	// The device is offline in this test, so a reconcile pass issues nothing
	// and the rollout stays active with the device remaining.
	k := e.rt().Keys
	r, _ := e.store.GetRollout(context.Background(), k.TenantID, mustUUID(t, created.ID))
	if err := e.rt().Rollouts.Reconcile(context.Background(), k.TenantID, r); err != nil {
		t.Fatal(err)
	}
	c.do("GET", "/api/rollouts/"+created.ID, nil, &got)
	if got.State != "active" || got.Summary.Issued != 0 {
		t.Errorf("after reconcile (offline device) = %+v", got)
	}

	var list []rolloutJSON
	if code := c.do("GET", "/api/rollouts", nil, &list); code != 200 || len(list) != 1 || list[0].ID != created.ID {
		t.Fatalf("list = %d %+v", code, list)
	}

	// Transitions.
	if code := c.do("POST", "/api/rollouts/"+created.ID+"/resume", nil, nil); code != 409 {
		t.Errorf("resume active = %d, want 409", code)
	}
	if code := c.do("POST", "/api/rollouts/"+created.ID+"/pause", nil, nil); code != 204 {
		t.Errorf("pause = %d", code)
	}
	if code := c.do("POST", "/api/rollouts/"+created.ID+"/resume", nil, nil); code != 204 {
		t.Errorf("resume = %d", code)
	}
	if code := c.do("POST", "/api/rollouts/"+created.ID+"/cancel", nil, nil); code != 204 {
		t.Errorf("cancel = %d", code)
	}
	c.do("GET", "/api/rollouts/"+created.ID, nil, &got)
	if got.State != "cancelled" {
		t.Errorf("after cancel state = %s", got.State)
	}
	if code := c.do("POST", "/api/rollouts/"+created.ID+"/pause", nil, nil); code != 409 {
		t.Errorf("pause cancelled = %d, want 409", code)
	}

	// Rollback from a terminal rollout creates a new one with the same targets.
	var rb idResp
	if code := c.do("POST", "/api/rollouts/"+created.ID+"/rollback", map[string]string{"version": "1.0.0"}, &rb); code != 201 {
		t.Fatalf("rollback = %d", code)
	}
	c.do("GET", "/api/rollouts/"+rb.ID, nil, &got)
	if got.Version != "1.0.0" || got.State != "active" || len(got.GroupIDs) != 1 || got.BatchSize != 5 {
		t.Errorf("rollback rollout = %+v", got)
	}
	// Rollback from an open rollout cancels it first.
	var rb2 idResp
	if code := c.do("POST", "/api/rollouts/"+rb.ID+"/rollback", map[string]string{"version": "1.0.1"}, &rb2); code != 201 {
		t.Fatalf("rollback of open = %d", code)
	}
	c.do("GET", "/api/rollouts/"+rb.ID, nil, &got)
	if got.State != "cancelled" {
		t.Errorf("rolled-back rollout state = %s, want cancelled", got.State)
	}
	// Rolling back to the rollout's own version is rejected.
	if code := c.do("POST", "/api/rollouts/"+rb2.ID+"/rollback", map[string]string{"version": "1.0.1"}, nil); code != 400 {
		t.Errorf("rollback to same version = %d, want 400", code)
	}

	// Audit trail.
	entries, _ := e.store.ListAudit(context.Background(), k.TenantID, 100, 0)
	seen := map[string]bool{}
	for _, en := range entries {
		seen[en.Action] = true
	}
	for _, a := range []string{"rollout.create", "rollout.pause", "rollout.resume", "rollout.cancel", "rollout.rollback"} {
		if !seen[a] {
			t.Errorf("missing audit action %s", a)
		}
	}
}

func TestRolloutRbac(t *testing.T) {
	e := newEnv(t)
	owner := e.initialized(t)
	owner.uploadRelease(t, "1.0.0")
	owner.do("POST", "/api/admins", map[string]string{"email": "ro@example.com", "password": "readonly-password-1", "role": "readonly"}, nil)
	ro := e.client(t)
	ro.loginFull("ro@example.com", "readonly-password-1", "")
	if code := ro.do("GET", "/api/rollouts", nil, nil); code != 200 {
		t.Errorf("readonly list = %d, want 200", code)
	}
	if code := ro.do("POST", "/api/rollouts", map[string]any{"version": "1.0.0"}, nil); code != 403 {
		t.Errorf("readonly create = %d, want 403", code)
	}
}
