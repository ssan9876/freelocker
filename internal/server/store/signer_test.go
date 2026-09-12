package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"freelocker/internal/server/store"
)

func TestObservationPublisherRoundTrip(t *testing.T) {
	ctx := context.Background()
	s, tenant, _, dev := overrideEnv(t) // tenant + grouped device
	now := time.Now()

	for _, o := range []store.Observation{
		{SHA256: "AA11", Path: `C:\app.exe`, Signer: "Contoso Ltd", SignerTBS: "BEEF", SignerVerified: true},
		{SHA256: "BB22", Path: `C:\other.exe`, Signer: "Nobody"},
	} {
		if err := s.RecordObservation(ctx, tenant, dev, o, now); err != nil {
			t.Fatal(err)
		}
	}

	obs, err := s.ListObservations(ctx, tenant, dev, 10)
	if err != nil || len(obs) != 2 {
		t.Fatalf("observations = %d, %v", len(obs), err)
	}
	byHash := map[string]store.Observation{}
	for _, o := range obs {
		byHash[o.SHA256] = o
	}
	if o := byHash["AA11"]; o.SignerTBS != "BEEF" || !o.SignerVerified {
		t.Errorf("verified observation = %+v", o)
	}
	if o := byHash["BB22"]; o.SignerTBS != "" || o.SignerVerified {
		t.Errorf("unsigned observation = %+v", o)
	}

	tbs, name, verified, err := s.ObservationPublisher(ctx, tenant, "AA11")
	if err != nil || tbs != "BEEF" || name != "Contoso Ltd" || !verified {
		t.Fatalf("ObservationPublisher = %q %q %v, %v", tbs, name, verified, err)
	}
	if _, _, _, err := s.ObservationPublisher(ctx, tenant, "NOPE"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("unknown hash err = %v", err)
	}
	other, _ := s.CreateTenant(ctx, "Other")
	if _, _, _, err := s.ObservationPublisher(ctx, other, "AA11"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("cross-tenant err = %v", err)
	}
}

func TestBlockEventsAndApprovalsCarryPublisher(t *testing.T) {
	ctx := context.Background()
	s, tenant, gid, dev := overrideEnv(t)
	pid, err := s.CreatePolicy(ctx, tenant, "P", "audit")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AssignPolicy(ctx, tenant, gid, pid); err != nil {
		t.Fatal(err)
	}
	evs := []store.BlockEvent{{
		SHA256: "CC33", Path: `C:\blocked.exe`, Signer: "Contoso Ltd",
		SignerTBS: "FEED", SignerVerified: true, Blocked: false, At: time.Now(),
	}}
	if err := s.RecordBlockEvents(ctx, tenant, dev, evs); err != nil {
		t.Fatal(err)
	}
	list, err := s.ListBlockEvents(ctx, tenant, 10)
	if err != nil || len(list) != 1 || list[0].SignerTBS != "FEED" || !list[0].SignerVerified {
		t.Fatalf("block events = %+v, %v", list, err)
	}
	if err := s.UpsertApprovalRequests(ctx, tenant, pid, dev, evs); err != nil {
		t.Fatal(err)
	}
	reqs, err := s.ListApprovalRequests(ctx, tenant, "pending", 10)
	if err != nil || len(reqs) != 1 {
		t.Fatalf("approval requests = %+v, %v", reqs, err)
	}
	if reqs[0].SignerTBS != "FEED" || !reqs[0].SignerVerified {
		t.Errorf("approval request publisher = %+v", reqs[0])
	}
	got, err := s.GetApprovalRequest(ctx, tenant, reqs[0].ID)
	if err != nil || got.SignerTBS != "FEED" || !got.SignerVerified {
		t.Errorf("GetApprovalRequest publisher = %+v, %v", got, err)
	}
}
