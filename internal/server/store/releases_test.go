package store_test

import (
	"context"
	"errors"
	"testing"

	"freelocker/internal/server/store"
	"freelocker/internal/server/store/storetest"
)

func TestReleases(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	tenant, _ := s.CreateTenant(ctx, "Acme")

	if _, err := s.LatestRelease(ctx, tenant); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("empty latest err = %v", err)
	}
	for _, v := range []string{"1.0.0", "1.2.0"} {
		if err := s.PutRelease(ctx, tenant, store.Release{Version: v, SHA256: []byte("h" + v), Signature: []byte("s")}); err != nil {
			t.Fatal(err)
		}
	}
	r, err := s.GetRelease(ctx, tenant, "1.0.0")
	if err != nil || string(r.SHA256) != "h1.0.0" {
		t.Fatalf("get = %+v, %v", r, err)
	}
	latest, err := s.LatestRelease(ctx, tenant)
	if err != nil || latest.Version != "1.2.0" {
		t.Fatalf("latest = %+v, %v", latest, err)
	}
	if err := s.PutRelease(ctx, tenant, store.Release{Version: "1.0.0", SHA256: []byte("new"), Signature: []byte("s2")}); err != nil {
		t.Fatal(err)
	}
	r, _ = s.GetRelease(ctx, tenant, "1.0.0")
	if string(r.SHA256) != "new" {
		t.Errorf("upsert failed: %s", r.SHA256)
	}
}
