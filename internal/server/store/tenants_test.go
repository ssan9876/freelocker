package store_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"freelocker/internal/server/store"
	"freelocker/internal/server/store/storetest"
)

func TestTenantsAndServerKeys(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)

	if _, err := s.FirstTenant(ctx); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("FirstTenant on empty db err = %v, want ErrNotFound", err)
	}
	id, err := s.CreateTenant(ctx, "Acme")
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.FirstTenant(ctx)
	if err != nil || got != id {
		t.Fatalf("FirstTenant = %v, %v; want %v", got, err, id)
	}

	if err := s.PutServerKey(ctx, id, "ca", []byte("pub"), []byte("priv")); err != nil {
		t.Fatal(err)
	}
	pub, priv, err := s.GetServerKey(ctx, id, "ca")
	if err != nil || !bytes.Equal(pub, []byte("pub")) || !bytes.Equal(priv, []byte("priv")) {
		t.Fatalf("GetServerKey = %q %q %v", pub, priv, err)
	}
	if _, _, err := s.GetServerKey(ctx, id, "missing"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing key err = %v", err)
	}
	// Migrate must be idempotent.
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
}
