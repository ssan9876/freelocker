package httpapi_test

import (
	"context"
	"testing"
	"time"

	"freelocker/internal/server/store"

	"github.com/google/uuid"
)

func mustParseUUID(t *testing.T, s string) uuid.UUID {
	t.Helper()
	id, err := uuid.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// seedObservation records one observation for a device, as the agent would.
func seedObservation(t *testing.T, e *env, dev string, o store.Observation) {
	t.Helper()
	ctx := context.Background()
	tenant, _ := e.store.FirstTenant(ctx)
	if err := e.store.RecordObservation(ctx, tenant, mustParseUUID(t, dev), o, time.Now()); err != nil {
		t.Fatal(err)
	}
}

const testTBS = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"

func TestPromoteObservationAsPublisher(t *testing.T) {
	e := newEnv(t)
	c := e.initialized(t)
	dev := e.fakeDevice(t).String()
	var pol idResp
	c.do("POST", "/api/policies", map[string]string{"name": "Workstations", "mode": "audit"}, &pol)

	seedObservation(t, e, dev, store.Observation{
		SHA256: "AA11", Path: `C:\app.exe`, Signer: "Contoso Ltd", SignerTBS: testTBS, SignerVerified: true,
	})
	seedObservation(t, e, dev, store.Observation{SHA256: "BB22", Path: `C:\unsigned.exe`})

	// A verified observation becomes a publisher rule whose value is the TBS hash.
	body := map[string]string{"policy_id": pol.ID, "sha256": "AA11", "kind": "publisher", "description": "Contoso apps"}
	if code := c.do("POST", "/api/observations/promote", body, nil); code != 201 {
		t.Fatalf("promote publisher = %d", code)
	}
	var detail struct {
		Rules []struct {
			Kind          string `json:"kind"`
			Value         string `json:"value"`
			PublisherName string `json:"publisher_name"`
		} `json:"rules"`
	}
	c.do("GET", "/api/policies/"+pol.ID, nil, &detail)
	found := false
	for _, r := range detail.Rules {
		if r.Kind == "publisher" {
			found = true
			if r.Value != testTBS || r.PublisherName != "Contoso Ltd" {
				t.Errorf("publisher rule = %+v", r)
			}
		}
	}
	if !found {
		t.Fatalf("no publisher rule on policy: %+v", detail.Rules)
	}

	// Unsigned/unverified observations are refused.
	bad := map[string]string{"policy_id": pol.ID, "sha256": "BB22", "kind": "publisher"}
	if code := c.do("POST", "/api/observations/promote", bad, nil); code != 400 {
		t.Errorf("unverified promote = %d, want 400", code)
	}
	missing := map[string]string{"policy_id": pol.ID, "sha256": "NOPE", "kind": "publisher"}
	if code := c.do("POST", "/api/observations/promote", missing, nil); code != 404 {
		t.Errorf("unknown observation promote = %d, want 404", code)
	}
	// The client cannot smuggle its own TBS value.
	spoof := map[string]string{"policy_id": pol.ID, "sha256": "BB22", "kind": "publisher", "signer_tbs": testTBS}
	if code := c.do("POST", "/api/observations/promote", spoof, nil); code != 400 {
		t.Errorf("client-supplied TBS = %d, want 400", code)
	}
}

func TestObservationsListExposesPublisher(t *testing.T) {
	e := newEnv(t)
	c := e.initialized(t)
	dev := e.fakeDevice(t).String()
	seedObservation(t, e, dev, store.Observation{
		SHA256: "AA11", Path: `C:\app.exe`, Signer: "Contoso Ltd", SignerTBS: testTBS, SignerVerified: true,
	})

	var obs []struct {
		SHA256         string `json:"sha256"`
		Signer         string `json:"signer"`
		SignerTBS      string `json:"signer_tbs"`
		SignerVerified bool   `json:"signer_verified"`
	}
	if code := c.do("GET", "/api/devices/"+dev+"/observations", nil, &obs); code != 200 || len(obs) != 1 {
		t.Fatalf("observations = %d, %+v", code, obs)
	}
	if obs[0].SignerTBS != testTBS || !obs[0].SignerVerified || obs[0].Signer != "Contoso Ltd" {
		t.Errorf("observation JSON = %+v", obs[0])
	}
}

func TestApproveAsPublisher(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	c := e.initialized(t)
	dev := e.fakeDevice(t)
	tenant, _ := e.store.FirstTenant(ctx)
	var grp, pol idResp
	c.do("POST", "/api/groups", map[string]string{"name": "WS"}, &grp)
	c.do("POST", "/api/policies", map[string]string{"name": "P", "mode": "audit"}, &pol)
	c.do("POST", "/api/policies/"+pol.ID+"/assign", map[string]string{"group_id": grp.ID}, nil)
	c.do("POST", "/api/devices/"+dev.String()+"/group", map[string]any{"group_id": grp.ID}, nil)

	if _, err := e.store.UpsertApprovalRequests(ctx, tenant, mustParseUUID(t, pol.ID), dev, []store.BlockEvent{{
		SHA256: "CC33", Path: `C:\blocked.exe`, Signer: "Contoso Ltd", SignerTBS: testTBS, SignerVerified: true, At: time.Now(),
	}}); err != nil {
		t.Fatal(err)
	}
	var reqs []struct {
		ID             string `json:"id"`
		SignerTBS      string `json:"signer_tbs"`
		SignerVerified bool   `json:"signer_verified"`
	}
	c.do("GET", "/api/approvals?status=pending", nil, &reqs)
	if len(reqs) != 1 || reqs[0].SignerTBS != testTBS || !reqs[0].SignerVerified {
		t.Fatalf("approvals = %+v", reqs)
	}
	if code := c.do("POST", "/api/approvals/"+reqs[0].ID+"/approve", map[string]string{"kind": "publisher"}, nil); code != 204 {
		t.Fatalf("approve publisher = %d", code)
	}
	var detail struct {
		Rules []struct {
			Kind  string `json:"kind"`
			Value string `json:"value"`
		} `json:"rules"`
	}
	c.do("GET", "/api/policies/"+pol.ID, nil, &detail)
	for _, r := range detail.Rules {
		if r.Kind == "publisher" && r.Value == testTBS {
			return
		}
	}
	t.Errorf("no publisher rule after approval: %+v", detail.Rules)
}
