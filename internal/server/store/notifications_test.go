package store_test

import (
	"context"
	"errors"
	"testing"

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
