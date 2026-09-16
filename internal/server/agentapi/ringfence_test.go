package agentapi_test

import (
	"context"
	"testing"
	"time"

	flv1 "freelocker/gen/freelocker/v1"
	"freelocker/internal/server/store"
	"freelocker/internal/server/tokens"
	"freelocker/internal/sim"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// TestRingfenceOverTheWire enrolls a device, assigns a ringfence to its
// group, and checks the agent receives it and can report a violation back.
func TestRingfenceOverTheWire(t *testing.T) {
	ctx := context.Background()
	ts := startServer(t)
	s, tenant := ts.Deps.Store, ts.Deps.Keys.TenantID

	gid, err := s.CreateDeviceGroup(ctx, tenant, "Kiosks")
	if err != nil {
		t.Fatal(err)
	}

	rfID := uuid.New()
	if err := s.CreateRingfence(ctx, tenant, store.Ringfence{ID: rfID, Name: "Lockdown", Mode: "enforce"}); err != nil {
		t.Fatal(err)
	}
	const path = `C:\Program Files\App\app.exe`
	if err := s.AddRingfenceProgram(ctx, tenant, rfID, store.RingfenceProgram{ID: uuid.New(), Path: path, NetworkBlocked: true}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetRingfenceProtection(ctx, tenant, rfID, "block-office-child-process", "block"); err != nil {
		t.Fatal(err)
	}
	if err := s.AssignRingfence(ctx, tenant, gid, rfID); err != nil {
		t.Fatal(err)
	}

	full, hash, _ := tokens.Generate(ts.Deps.Keys.CA.Pin())
	if _, err := s.CreateInstallToken(ctx, tenant, store.InstallToken{Name: "k", GroupID: &gid}, hash); err != nil {
		t.Fatal(err)
	}
	id, err := sim.Enroll(ctx, ts.Addr, full, hw)
	if err != nil {
		t.Fatal(err)
	}

	resp := getRingfence(t, ts.Addr, id)
	if resp.GetMode() != "enforce" {
		t.Errorf("Mode = %q, want %q", resp.GetMode(), "enforce")
	}
	if len(resp.GetPrograms()) != 1 || resp.GetPrograms()[0].GetPath() != path {
		t.Errorf("Programs = %+v, want one program with path %q", resp.GetPrograms(), path)
	}
	if len(resp.GetProtections()) != 1 {
		t.Errorf("Protections = %+v, want one protection", resp.GetProtections())
	}
	if resp.GetVersion() == "" {
		t.Error("Version should not be empty for an assigned ringfence")
	}

	// A device with no group (so no ringfence assignment) gets an empty
	// Version and no error: the contract the agent relies on to clear any
	// rules it previously set.
	unassignedToken, unassignedHash, _ := tokens.Generate(ts.Deps.Keys.CA.Pin())
	if _, err := s.CreateInstallToken(ctx, tenant, store.InstallToken{Name: "u"}, unassignedHash); err != nil {
		t.Fatal(err)
	}
	unassigned, err := sim.Enroll(ctx, ts.Addr, unassignedToken, hw)
	if err != nil {
		t.Fatal(err)
	}
	uResp := getRingfence(t, ts.Addr, unassigned)
	if uResp.GetVersion() != "" {
		t.Errorf("unassigned device Version = %q, want empty", uResp.GetVersion())
	}

	// Report one network event plus one event of an unknown kind; only the
	// network event should be recorded.
	cfg, err := id.TLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	conn, err := grpc.NewClient(ts.Addr, grpc.WithTransportCredentials(credentials.NewTLS(cfg)))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	cctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := flv1.NewAgentClient(conn).ReportRingfenceEvents(cctx, &flv1.ReportRingfenceEventsRequest{
		Events: []*flv1.RingfenceEvent{
			{Kind: "network", Program: path, Detail: "blocked outbound to 10.0.0.1:443", Enforced: true},
			{Kind: "bogus", Program: path, Detail: "should be skipped"},
		},
		AsrAvailable: false,
	}); err != nil {
		t.Fatal(err)
	}

	evs, err := s.ListRingfenceEvents(ctx, tenant, 10, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 1 {
		t.Fatalf("ListRingfenceEvents returned %d events, want 1: %+v", len(evs), evs)
	}
	if evs[0].DeviceID != uuid.MustParse(id.DeviceID) {
		t.Errorf("event DeviceID = %s, want %s", evs[0].DeviceID, id.DeviceID)
	}
	if evs[0].Kind != "network" || evs[0].Program != path {
		t.Errorf("event = %+v, want kind network program %q", evs[0], path)
	}

	// The device's reported ASR availability must be persisted for the
	// calling device (identified by its mTLS cert, never a request field),
	// even though the request also included violations.
	dev, err := s.GetDevice(ctx, tenant, uuid.MustParse(id.DeviceID))
	if err != nil {
		t.Fatal(err)
	}
	if dev.ASRAvailable == nil || *dev.ASRAvailable != false {
		t.Fatalf("device ASRAvailable = %+v, want false", dev.ASRAvailable)
	}

	// A second report with AsrAvailable true updates it (ASR toggled on,
	// e.g. Defender came back into real-time mode).
	if _, err := flv1.NewAgentClient(conn).ReportRingfenceEvents(cctx, &flv1.ReportRingfenceEventsRequest{
		AsrAvailable: true,
	}); err != nil {
		t.Fatal(err)
	}
	dev, err = s.GetDevice(ctx, tenant, uuid.MustParse(id.DeviceID))
	if err != nil {
		t.Fatal(err)
	}
	if dev.ASRAvailable == nil || *dev.ASRAvailable != true {
		t.Fatalf("device ASRAvailable after second report = %+v, want true", dev.ASRAvailable)
	}
}

func getRingfence(t *testing.T, addr string, id *sim.Identity) *flv1.GetRingfenceResponse {
	t.Helper()
	cfg, err := id.TLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(credentials.NewTLS(cfg)))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	cctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := flv1.NewAgentClient(conn).GetRingfence(cctx, &flv1.GetRingfenceRequest{})
	if err != nil {
		t.Fatal(err)
	}
	return resp
}
