package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"freelocker/internal/server/store"
	"freelocker/internal/server/store/storetest"

	"github.com/google/uuid"
)

func TestCommandLifecycle(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	tenant, _ := s.CreateTenant(ctx, "Acme")
	s.CreateInstallToken(ctx, tenant, store.InstallToken{Name: "t"}, []byte("h"))
	dev := uuid.New()
	s.EnrollDevice(ctx, []byte("h"), time.Now(), func(uuid.UUID) (store.NewDevice, error) { return newDev(dev), nil })

	now := time.Now().Truncate(time.Microsecond)
	live := store.Command{ID: uuid.New(), DeviceID: dev, Type: "ping", IssuedAt: now, ExpiresAt: now.Add(time.Hour)}
	stale := store.Command{ID: uuid.New(), DeviceID: dev, Type: "ping", IssuedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Hour)}
	for _, c := range []store.Command{live, stale} {
		if err := s.CreateCommand(ctx, tenant, c); err != nil {
			t.Fatal(err)
		}
	}

	open, err := s.OpenCommands(ctx, tenant, dev, now)
	if err != nil || len(open) != 1 || open[0].ID != live.ID || open[0].State != "pending" {
		t.Fatalf("open = %+v, %v", open, err)
	}
	if err := s.MarkCommandSent(ctx, tenant, live.ID); err != nil {
		t.Fatal(err)
	}
	if open, _ := s.OpenCommands(ctx, tenant, dev, now); len(open) != 1 || open[0].State != "sent" {
		t.Fatalf("sent command must stay open for redelivery: %+v", open)
	}

	if err := s.CompleteCommand(ctx, tenant, uuid.New(), live.ID, true, "pong", now); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("completion by another device err = %v", err)
	}
	if err := s.CompleteCommand(ctx, tenant, dev, live.ID, true, "pong", now); err != nil {
		t.Fatal(err)
	}
	if err := s.CompleteCommand(ctx, tenant, dev, live.ID, true, "again", now); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("double completion err = %v", err)
	}

	n, err := s.ExpireCommands(ctx, now)
	if err != nil || n != 1 {
		t.Fatalf("expired = %d, %v", n, err)
	}
	hist, _ := s.ListDeviceCommands(ctx, tenant, dev, 10)
	states := map[uuid.UUID]string{}
	for _, c := range hist {
		states[c.ID] = c.State
	}
	if states[live.ID] != "succeeded" || states[stale.ID] != "expired" {
		t.Errorf("states = %v", states)
	}
	if hist[0].ID != live.ID || hist[0].Result != "pong" || hist[0].CompletedAt == nil {
		t.Errorf("newest = %+v", hist[0])
	}
}
