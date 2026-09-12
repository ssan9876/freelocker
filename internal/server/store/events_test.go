package store_test

import (
	"context"
	"testing"
	"time"

	"freelocker/internal/server/store"
	"freelocker/internal/server/store/storetest"
)

func TestDeviceEvents(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	tenant, _ := s.CreateTenant(ctx, "Acme")
	dev := seedDevice(t, s, tenant)

	err := s.RecordDeviceEvents(ctx, tenant, dev, []store.DeviceEvent{
		{Kind: "process_launch", Summary: "bob launched cmd.exe", At: time.Now().Add(-time.Minute)},
		{Kind: "logon", Summary: "alice logged on", At: time.Now()},
	})
	if err != nil {
		t.Fatal(err)
	}
	all, err := s.ListDeviceEvents(ctx, tenant, "", 10)
	if err != nil || len(all) != 2 || all[0].Kind != "logon" {
		t.Fatalf("events = %+v, %v (newest first)", all, err)
	}
	only, _ := s.ListDeviceEvents(ctx, tenant, "process_launch", 10)
	if len(only) != 1 || only[0].Kind != "process_launch" {
		t.Errorf("filtered = %+v", only)
	}
	if err := s.RecordDeviceEvents(ctx, tenant, dev, nil); err != nil {
		t.Errorf("empty batch should be a no-op: %v", err)
	}
}
