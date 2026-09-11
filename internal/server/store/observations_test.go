package store_test

import (
	"context"
	"testing"
	"time"

	"freelocker/internal/server/store"
	"freelocker/internal/server/store/storetest"

	"github.com/google/uuid"
)

func seedDevice(t *testing.T, s *store.Store, tenant uuid.UUID) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	h := []byte("h-" + uuid.NewString())
	s.CreateInstallToken(ctx, tenant, store.InstallToken{Name: "t"}, h)
	dev := uuid.New()
	if _, err := s.EnrollDevice(ctx, h, time.Now(), func(uuid.UUID) (store.NewDevice, error) {
		return store.NewDevice{ID: dev, Hostname: "pc", CertSerial: "s", CertExpiresAt: time.Now().Add(time.Hour)}, nil
	}); err != nil {
		t.Fatal(err)
	}
	return dev
}

func TestObservationUpsert(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	tenant, _ := s.CreateTenant(ctx, "Acme")
	dev := seedDevice(t, s, tenant)

	now := time.Now()
	o := store.Observation{SHA256: "ABC", Path: `C:\app.exe`, Signer: ""}
	if err := s.RecordObservation(ctx, tenant, dev, o, now); err != nil {
		t.Fatal(err)
	}
	o.Signer = "Acme Corp"
	if err := s.RecordObservation(ctx, tenant, dev, o, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	list, _ := s.ListObservations(ctx, tenant, dev, 10)
	if len(list) != 1 || list[0].Count != 2 {
		t.Fatalf("expected 1 observation with count 2, got %+v", list)
	}
	if list[0].Signer != "Acme Corp" {
		t.Errorf("signer should fill in on later report: %q", list[0].Signer)
	}
	if !list[0].LastSeen.After(list[0].FirstSeen) {
		t.Error("last_seen should advance")
	}
}

func TestBlockEvents(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	tenant, _ := s.CreateTenant(ctx, "Acme")
	dev := seedDevice(t, s, tenant)

	err := s.RecordBlockEvents(ctx, tenant, dev, []store.BlockEvent{
		{SHA256: "AA", Path: `C:\bad1.exe`, Blocked: true, At: time.Now().Add(-time.Minute)},
		{SHA256: "BB", Path: `C:\bad2.exe`, Blocked: false, At: time.Now()},
	})
	if err != nil {
		t.Fatal(err)
	}
	list, err := s.ListBlockEvents(ctx, tenant, 10)
	if err != nil || len(list) != 2 || list[0].Path != `C:\bad2.exe` {
		t.Fatalf("block events = %+v, %v (newest first)", list, err)
	}
	if err := s.RecordBlockEvents(ctx, tenant, dev, nil); err != nil {
		t.Errorf("empty batch should be a no-op: %v", err)
	}
}
