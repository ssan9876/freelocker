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

// Provenance is nullable on purpose: "no agent has reported whether this was
// downloaded" is a different fact from "the agent looked and found no mark".
// An older agent reports neither, and rendering that as "not downloaded"
// would be an assertion nothing actually made.
func TestObservationProvenance(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	tenant, _ := s.CreateTenant(ctx, "Acme")
	dev := enrollTestDevice(t, s, tenant, nil, "pc1", "1.0.0")
	now := time.Now()

	// An agent that reports nothing leaves provenance unknown.
	legacy := store.Observation{SHA256: "AAAA", Path: `C:\Windows\System32\notepad.exe`}
	if err := s.RecordObservation(ctx, tenant, dev, legacy, now); err != nil {
		t.Fatal(err)
	}

	yes := true
	downloaded := store.Observation{
		SHA256: "BBBB", Path: `C:\Users\u\Downloads\setup.exe`,
		Downloaded: &yes, DownloadSource: "https://example.com/setup.exe",
	}
	if err := s.RecordObservation(ctx, tenant, dev, downloaded, now); err != nil {
		t.Fatal(err)
	}

	no := false
	installed := store.Observation{SHA256: "CCCC", Path: `C:\Program Files\App\app.exe`, Downloaded: &no}
	if err := s.RecordObservation(ctx, tenant, dev, installed, now); err != nil {
		t.Fatal(err)
	}

	got, err := s.ListObservations(ctx, tenant, dev, 10)
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]store.Observation{}
	for _, o := range got {
		by[o.SHA256] = o
	}
	if by["AAAA"].Downloaded != nil {
		t.Errorf("legacy observation = %v, want nil (unknown)", *by["AAAA"].Downloaded)
	}
	if by["BBBB"].Downloaded == nil || !*by["BBBB"].Downloaded {
		t.Errorf("downloaded observation = %v, want true", by["BBBB"].Downloaded)
	}
	if by["BBBB"].DownloadSource != "https://example.com/setup.exe" {
		t.Errorf("source = %q", by["BBBB"].DownloadSource)
	}
	if by["CCCC"].Downloaded == nil || *by["CCCC"].Downloaded {
		t.Errorf("installed observation = %v, want false", by["CCCC"].Downloaded)
	}
}

// Re-reporting must not lose a mark already recorded. The agent rescans
// constantly and a single read failure (a locked file, a permission blip)
// would otherwise erase provenance the console had already shown.
func TestObservationProvenanceSurvivesUnknownRescan(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	tenant, _ := s.CreateTenant(ctx, "Acme")
	dev := enrollTestDevice(t, s, tenant, nil, "pc1", "1.0.0")
	now := time.Now()

	yes := true
	o := store.Observation{SHA256: "BBBB", Path: `C:\Users\u\Downloads\setup.exe`,
		Downloaded: &yes, DownloadSource: "https://example.com/setup.exe"}
	if err := s.RecordObservation(ctx, tenant, dev, o, now); err != nil {
		t.Fatal(err)
	}

	// Same binary, this time the agent could not read the mark.
	o.Downloaded, o.DownloadSource = nil, ""
	if err := s.RecordObservation(ctx, tenant, dev, o, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}

	got, _ := s.ListObservations(ctx, tenant, dev, 10)
	if len(got) != 1 {
		t.Fatalf("got %d observations, want 1", len(got))
	}
	if got[0].Downloaded == nil || !*got[0].Downloaded {
		t.Errorf("provenance = %v, want the previously recorded true to survive", got[0].Downloaded)
	}
	if got[0].DownloadSource != "https://example.com/setup.exe" {
		t.Errorf("source = %q, want the recorded origin to survive", got[0].DownloadSource)
	}
}
