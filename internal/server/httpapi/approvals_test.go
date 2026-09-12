package httpapi_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"freelocker/internal/server/store"

	"github.com/google/uuid"
)

// seedApproval creates a pending approval request for sha on policyID.
func (e *env) seedApproval(t *testing.T, policyID, sha string) string {
	t.Helper()
	ctx := context.Background()
	tenant := e.rt().Keys.TenantID
	dev := e.fakeDevice(t)
	if err := e.store.UpsertApprovalRequests(ctx, tenant, uuid.MustParse(policyID), dev, []store.BlockEvent{
		{SHA256: sha, Path: `C:\new.exe`, At: time.Now()},
	}); err != nil {
		t.Fatal(err)
	}
	list, _ := e.store.ListApprovalRequests(ctx, tenant, "", 100)
	for _, r := range list {
		if r.SHA256 == sha {
			return r.ID.String()
		}
	}
	t.Fatalf("seeded request %s not found", sha)
	return ""
}

func TestApproveAndDenyOverHTTP(t *testing.T) {
	e := newEnv(t)
	c := e.initialized(t)

	var pol struct{ ID string }
	c.do("POST", "/api/policies", map[string]string{"name": "Baseline"}, &pol)
	shaApprove, shaDeny := strings.ToUpper(hex64("c")), strings.ToUpper(hex64("d"))
	approveID := e.seedApproval(t, pol.ID, shaApprove)
	denyID := e.seedApproval(t, pol.ID, shaDeny)

	var count struct{ Pending int }
	if code := c.do("GET", "/api/approvals/count", nil, &count); code != 200 || count.Pending != 2 {
		t.Fatalf("count = %d %+v", code, count)
	}
	var pending []map[string]any
	c.do("GET", "/api/approvals?status=pending", nil, &pending)
	if len(pending) != 2 || pending[0]["policy_name"] != "Baseline" || pending[0]["decided_at"] != nil {
		t.Fatalf("pending = %+v", pending)
	}

	type detail struct {
		Rules   []map[string]any `json:"rules"`
		Version string           `json:"version"`
	}
	var before detail
	c.do("GET", "/api/policies/"+pol.ID, nil, &before)

	if code := c.do("POST", "/api/approvals/"+approveID+"/approve", nil, nil); code != 204 {
		t.Fatalf("approve = %d", code)
	}
	var after detail
	c.do("GET", "/api/policies/"+pol.ID, nil, &after)
	if len(after.Rules) != 1 || after.Rules[0]["value"] != shaApprove || after.Version == before.Version {
		t.Fatalf("after approve: rules %+v version %q (before %q)", after.Rules, after.Version, before.Version)
	}

	var errResp struct{ Error string }
	if code := c.do("POST", "/api/approvals/"+approveID+"/approve", nil, &errResp); code != 409 || errResp.Error != "request already decided" {
		t.Errorf("second approve = %d %+v, want 409", code, errResp)
	}

	if code := c.do("POST", "/api/approvals/"+denyID+"/deny", nil, nil); code != 204 {
		t.Fatalf("deny = %d", code)
	}
	c.do("GET", "/api/policies/"+pol.ID, nil, &after)
	if len(after.Rules) != 1 {
		t.Errorf("deny must not add a rule: %+v", after.Rules)
	}

	var approved, denied []map[string]any
	c.do("GET", "/api/approvals?status=approved", nil, &approved)
	c.do("GET", "/api/approvals?status=denied", nil, &denied)
	if len(approved) != 1 || len(denied) != 1 || approved[0]["decided_at"] == nil {
		t.Errorf("approved %+v denied %+v", approved, denied)
	}
	c.do("GET", "/api/approvals/count", nil, &count)
	if count.Pending != 0 {
		t.Errorf("pending after decisions = %d", count.Pending)
	}

	if code := c.do("POST", "/api/approvals/"+uuid.NewString()+"/deny", nil, nil); code != 404 {
		t.Errorf("unknown id = %d, want 404", code)
	}
	if code := c.do("GET", "/api/approvals?status=bogus", nil, nil); code != 400 {
		t.Errorf("bad status = %d, want 400", code)
	}
}

func TestApprovalsReadonlyCannotDecide(t *testing.T) {
	e := newEnv(t)
	owner := e.initialized(t)
	var pol struct{ ID string }
	owner.do("POST", "/api/policies", map[string]string{"name": "Baseline"}, &pol)
	id := e.seedApproval(t, pol.ID, strings.ToUpper(hex64("e")))
	owner.do("POST", "/api/admins", map[string]string{"email": "ro@example.com", "password": "readonly-password-1", "role": "readonly"}, nil)
	ro := e.client(t)
	ro.loginFull("ro@example.com", "readonly-password-1", "")

	if code := ro.do("GET", "/api/approvals", nil, nil); code != 200 {
		t.Errorf("readonly list = %d", code)
	}
	if code := ro.do("POST", "/api/approvals/"+id+"/approve", nil, nil); code != 403 {
		t.Errorf("readonly approve = %d, want 403", code)
	}
}

func TestApproveAsPath(t *testing.T) {
	e := newEnv(t)
	c := e.initialized(t)

	var pol struct{ ID string }
	c.do("POST", "/api/policies", map[string]string{"name": "Baseline"}, &pol)
	id := e.seedApproval(t, pol.ID, strings.ToUpper(hex64("e")))

	// Approve as a path rule (the seeded request has path C:\new.exe).
	if code := c.do("POST", "/api/approvals/"+id+"/approve", map[string]string{"kind": "path"}, nil); code != 204 {
		t.Fatalf("approve as path = %d", code)
	}
	var detail struct {
		Rules []map[string]any `json:"rules"`
	}
	c.do("GET", "/api/policies/"+pol.ID, nil, &detail)
	if len(detail.Rules) != 1 || detail.Rules[0]["kind"] != "path" || detail.Rules[0]["value"] != `C:\new.exe` {
		t.Fatalf("expected a path rule, got %+v", detail.Rules)
	}
}
