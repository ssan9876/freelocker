package agentapi_test

import (
	"context"
	"testing"
	"time"

	flv1 "freelocker/gen/freelocker/v1"
	"freelocker/internal/sim"
)

func TestReportEvents(t *testing.T) {
	ctx := context.Background()
	ts := startServer(t)
	id, err := sim.Enroll(ctx, ts.Addr, ts.Token, hw)
	if err != nil {
		t.Fatal(err)
	}
	client := agentClient(t, ts, id)

	if _, err := client.ReportEvents(ctx, &flv1.EventsRequest{Events: []*flv1.DeviceEvent{
		{Kind: "process_launch", Summary: "bob launched cmd.exe", AtUnix: time.Now().Unix()},
		{Kind: "", Summary: "skipped (no kind)"},
	}}); err != nil {
		t.Fatal(err)
	}
	evs, _ := ts.Deps.Store.ListDeviceEvents(ctx, ts.Deps.Keys.TenantID, "", 10)
	if len(evs) != 1 || evs[0].Kind != "process_launch" {
		t.Fatalf("events = %+v (empty-kind event must be skipped)", evs)
	}
}
