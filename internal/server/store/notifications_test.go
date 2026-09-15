package store_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"freelocker/internal/server/store"
	"freelocker/internal/server/store/storetest"

	"github.com/google/uuid"
)

func TestValidateChannel(t *testing.T) {
	cases := []struct {
		name string
		c    store.NotificationChannel
		ok   bool
	}{
		{"webhook ok", store.NotificationChannel{Kind: "webhook", Name: "Slack", Events: []string{"alert.raised"}, URL: "https://h.example/x"}, true},
		{"email ok", store.NotificationChannel{Kind: "email", Name: "Ops", Events: []string{"approval.new"}, Recipients: []string{"ops@example.com"}}, true},
		{"no name", store.NotificationChannel{Kind: "webhook", Events: []string{"alert.raised"}, URL: "https://h"}, false},
		{"no events", store.NotificationChannel{Kind: "webhook", Name: "x", URL: "https://h"}, false},
		{"unknown event", store.NotificationChannel{Kind: "webhook", Name: "x", Events: []string{"nope"}, URL: "https://h"}, false},
		{"bad scheme", store.NotificationChannel{Kind: "webhook", Name: "x", Events: []string{"alert.raised"}, URL: "ftp://h"}, false},
		{"email no recipients", store.NotificationChannel{Kind: "email", Name: "x", Events: []string{"alert.raised"}}, false},
		{"email bad address", store.NotificationChannel{Kind: "email", Name: "x", Events: []string{"alert.raised"}, Recipients: []string{"nope"}}, false},
		{"bad kind", store.NotificationChannel{Kind: "sms", Name: "x", Events: []string{"alert.raised"}}, false},
	}
	for _, tc := range cases {
		err := store.ValidateChannel(tc.c)
		if (err == nil) != tc.ok {
			t.Errorf("%s: err = %v, want ok=%v", tc.name, err, tc.ok)
		}
		var ve *store.ValidationError
		if err != nil && !errors.As(err, &ve) {
			t.Errorf("%s: error must be *ValidationError, got %T", tc.name, err)
		}
	}
}

func TestChannelCRUDAndForEvent(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	tenant, _ := s.CreateTenant(ctx, "Acme")
	other, _ := s.CreateTenant(ctx, "Beta")

	c := store.NotificationChannel{ID: uuid.New(), Kind: "webhook", Name: "Slack", Events: []string{"alert.raised", "rollout.auto_paused"}, Enabled: true, URL: "https://h.example/x", Secret: []byte("sealed")}
	if err := s.CreateChannel(ctx, tenant, c); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateChannel(ctx, tenant, store.NotificationChannel{ID: uuid.New(), Kind: "email", Name: "Slack", Events: []string{"alert.raised"}, Recipients: []string{"a@b.c"}}); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("dup name err = %v", err)
	}
	got, err := s.GetChannel(ctx, tenant, c.ID)
	if err != nil || got.Name != "Slack" || len(got.Events) != 2 || string(got.Secret) != "sealed" || !got.Enabled || got.Recipients == nil {
		t.Fatalf("get = %+v, %v (Recipients must be non-nil)", got, err)
	}
	if _, err := s.GetChannel(ctx, other, c.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("cross-tenant get err = %v", err)
	}

	// ForEvent: subscribed + enabled only.
	chs, _ := s.ChannelsForEvent(ctx, tenant, "alert.raised")
	if len(chs) != 1 || chs[0].ID != c.ID {
		t.Fatalf("for alert.raised = %+v", chs)
	}
	if chs, _ = s.ChannelsForEvent(ctx, tenant, "approval.new"); len(chs) != 0 {
		t.Errorf("unsubscribed kind returned %+v", chs)
	}
	got.Enabled = false
	got.Name = "Slack ops"
	if err := s.UpdateChannel(ctx, tenant, got); err != nil {
		t.Fatal(err)
	}
	if chs, _ = s.ChannelsForEvent(ctx, tenant, "alert.raised"); len(chs) != 0 {
		t.Errorf("disabled channel returned %+v", chs)
	}
	list, _ := s.ListChannels(ctx, tenant)
	if len(list) != 1 || list[0].Name != "Slack ops" {
		t.Errorf("list = %+v", list)
	}
	// Suspended tenant → nothing.
	got.Enabled = true
	s.UpdateChannel(ctx, tenant, got)
	s.SetTenantSuspended(ctx, tenant, true)
	if chs, _ = s.ChannelsForEvent(ctx, tenant, "alert.raised"); len(chs) != 0 {
		t.Errorf("suspended tenant returned %+v", chs)
	}
	s.SetTenantSuspended(ctx, tenant, false)

	if err := s.DeleteChannel(ctx, other, c.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("cross-tenant delete err = %v", err)
	}
	if err := s.DeleteChannel(ctx, tenant, c.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetChannel(ctx, tenant, c.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("after delete err = %v", err)
	}
}

func mkChannel(t *testing.T, s *store.Store, tenant uuid.UUID, name string) uuid.UUID {
	t.Helper()
	c := store.NotificationChannel{ID: uuid.New(), Kind: "webhook", Name: name, Events: []string{"alert.raised"}, Enabled: true, URL: "https://h.example/" + name}
	if err := s.CreateChannel(context.Background(), tenant, c); err != nil {
		t.Fatal(err)
	}
	return c.ID
}

func TestDeliveryOutbox(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	tenant, _ := s.CreateTenant(ctx, "Acme")
	a := mkChannel(t, s, tenant, "a")
	b := mkChannel(t, s, tenant, "b")
	now := time.Now().Truncate(time.Second)

	if err := s.EnqueueDeliveries(ctx, tenant, []uuid.UUID{a, b}, "alert.raised", []byte(`{"kind":"alert.raised"}`), now); err != nil {
		t.Fatal(err)
	}
	if err := s.EnqueueDeliveries(ctx, tenant, nil, "alert.raised", []byte(`{}`), now); err != nil {
		t.Fatalf("empty channel list must be a no-op: %v", err)
	}

	// Not due yet.
	if got, _ := s.ClaimDeliveries(ctx, now.Add(-time.Second), 2*time.Minute, 50); len(got) != 0 {
		t.Fatalf("claimed before due: %+v", got)
	}
	got, err := s.ClaimDeliveries(ctx, now, 2*time.Minute, 50)
	if err != nil || len(got) != 2 {
		t.Fatalf("claim = %+v, %v", got, err)
	}
	if got[0].Attempts != 1 || got[0].TenantID != tenant || got[0].ChannelName == "" || !got[0].NextAttemptAt.Equal(now.Add(2*time.Minute)) || string(got[0].Payload) == "" {
		t.Errorf("claimed row = %+v", got[0])
	}
	// Leased: a second claim now returns nothing.
	if again, _ := s.ClaimDeliveries(ctx, now, 2*time.Minute, 50); len(again) != 0 {
		t.Errorf("double claim = %+v", again)
	}
	// Lease expiry brings it back.
	if again, _ := s.ClaimDeliveries(ctx, now.Add(3*time.Minute), 2*time.Minute, 1); len(again) != 1 || again[0].Attempts != 2 {
		t.Errorf("after lease = %+v", again)
	}

	if err := s.FinishDelivery(ctx, got[0].ID, "sent", "", time.Time{}, now); err != nil {
		t.Fatal(err)
	}
	if err := s.FinishDelivery(ctx, got[1].ID, "pending", "500 boom", now.Add(time.Minute), now); err != nil {
		t.Fatal(err)
	}
	list, _ := s.ListDeliveries(ctx, tenant, 10)
	if len(list) != 2 {
		t.Fatalf("list = %+v", list)
	}
	states := map[int64]store.Delivery{}
	for _, d := range list {
		states[d.ID] = d
	}
	if d := states[got[0].ID]; d.State != "sent" || d.SentAt == nil {
		t.Errorf("sent row = %+v", d)
	}
	if d := states[got[1].ID]; d.State != "pending" || d.LastError != "500 boom" || !d.NextAttemptAt.Equal(now.Add(time.Minute)) {
		t.Errorf("retry row = %+v", d)
	}
	// Failed terminal.
	s.FinishDelivery(ctx, got[1].ID, "failed", "gave up", time.Time{}, now)
	if c, _ := s.ClaimDeliveries(ctx, now.Add(time.Hour), time.Minute, 50); len(c) != 0 {
		t.Errorf("failed row claimed: %+v", c)
	}
	// Deleting the channel cascades.
	s.DeleteChannel(ctx, tenant, a)
	list, _ = s.ListDeliveries(ctx, tenant, 10)
	if len(list) != 1 {
		t.Errorf("after cascade = %+v", list)
	}
}

// A last_error longer than the 500-byte cap must not be cut mid-rune:
// Postgres rejects an invalid UTF-8 parameter, which would leave the row
// stuck in pending and re-claimed forever.
func TestFinishDeliveryTruncatesInvalidUTF8(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	tenant, _ := s.CreateTenant(ctx, "Acme")
	ch := mkChannel(t, s, tenant, "a")
	now := time.Now().Truncate(time.Second)
	if err := s.EnqueueDeliveries(ctx, tenant, []uuid.UUID{ch}, "alert.raised", []byte(`{}`), now); err != nil {
		t.Fatal(err)
	}
	got, err := s.ClaimDeliveries(ctx, now, time.Minute, 1)
	if err != nil || len(got) != 1 {
		t.Fatalf("claim = %+v, %v", got, err)
	}
	// Byte 499 is the first byte of the two-byte "é", so a plain [:500]
	// slice splits it.
	msg := strings.Repeat("a", 499) + "é…"
	if len(msg) <= 500 || utf8.ValidString(msg[:500]) {
		t.Fatalf("test fixture does not split a rune at byte 500 (len %d)", len(msg))
	}
	if err := s.FinishDelivery(ctx, got[0].ID, "pending", msg, now.Add(time.Minute), now); err != nil {
		t.Fatalf("FinishDelivery with mid-rune truncation: %v", err)
	}
	list, err := s.ListDeliveries(ctx, tenant, 10)
	if err != nil || len(list) != 1 {
		t.Fatalf("list = %+v, %v", list, err)
	}
	stored := list[0].LastError
	if len(stored) > 500 {
		t.Errorf("stored last_error is %d bytes, want <= 500", len(stored))
	}
	if !utf8.ValidString(stored) {
		t.Errorf("stored last_error is not valid UTF-8: %q", stored)
	}
	if !strings.HasPrefix(stored, strings.Repeat("a", 100)) {
		t.Errorf("stored last_error lost its prefix: %q", stored)
	}
}

func TestClaimDeliveriesConcurrent(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	tenant, _ := s.CreateTenant(ctx, "Acme")
	ch := mkChannel(t, s, tenant, "a")
	now := time.Now()
	for i := 0; i < 20; i++ {
		s.EnqueueDeliveries(ctx, tenant, []uuid.UUID{ch}, "alert.raised", []byte(`{}`), now)
	}
	var mu sync.Mutex
	seen := map[int64]int{}
	var wg sync.WaitGroup
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := s.ClaimDeliveries(ctx, now, time.Minute, 10)
			if err != nil {
				t.Error(err)
				return
			}
			mu.Lock()
			for _, d := range got {
				seen[d.ID]++
			}
			mu.Unlock()
		}()
	}
	wg.Wait()
	if len(seen) != 20 {
		t.Fatalf("claimed %d distinct rows, want 20", len(seen))
	}
	for id, n := range seen {
		if n != 1 {
			t.Errorf("row %d claimed %d times", id, n)
		}
	}
}
