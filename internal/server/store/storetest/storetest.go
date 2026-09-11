// Package storetest provides an isolated, migrated store per test.
package storetest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"freelocker/internal/server/store"

	"github.com/jackc/pgx/v5"
)

const defaultURL = "postgres://freelocker:freelocker@localhost:55432/freelocker?sslmode=disable"

func New(t *testing.T) *store.Store {
	s, _ := NewWithSQL(t)
	return s
}

// NewWithSQL also returns a function that executes raw SQL inside the
// test's schema, for asserting database-level guarantees.
func NewWithSQL(t *testing.T) (*store.Store, func(sql string, args ...any) error) {
	t.Helper()
	ctx := context.Background()
	url := os.Getenv("FREELOCKER_TEST_DATABASE_URL")
	if url == "" {
		url = defaultURL
	}
	conn, err := pgx.Connect(ctx, url)
	if err != nil {
		t.Fatalf("connect test db (start it: docker compose -f deploy/docker-compose.dev.yml up -d): %v", err)
	}
	b := make([]byte, 8)
	rand.Read(b)
	schema := "t_" + hex.EncodeToString(b)
	if _, err := conn.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, "SET search_path TO "+schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		conn.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
		conn.Close(context.Background())
	})

	sep := "?"
	if strings.Contains(url, "?") {
		sep = "&"
	}
	s, err := store.Open(ctx, url+sep+"search_path="+schema)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	exec := func(sql string, args ...any) error {
		_, err := conn.Exec(ctx, sql, args...)
		return err
	}
	return s, exec
}
