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

// TestGetControlsHonoursDeviceOverride proves an override that loosens the
// group's USB block reaches the agent through the unchanged GetControls RPC.
func TestGetControlsHonoursDeviceOverride(t *testing.T) {
	ctx := context.Background()
	ts := startServer(t)
	s, tenant := ts.Deps.Store, ts.Deps.Keys.TenantID
	gid, _ := s.CreateDeviceGroup(ctx, tenant, "Kiosks")
	s.SetControls(ctx, tenant, gid, store.DeviceControls{USBStorageBlocked: true})
	full, hash, _ := tokens.Generate(ts.Deps.Keys.CA.Pin())
	s.CreateInstallToken(ctx, tenant, store.InstallToken{Name: "k", GroupID: &gid}, hash)
	id, err := sim.Enroll(ctx, ts.Addr, full, hw)
	if err != nil {
		t.Fatal(err)
	}

	if !getControls(t, ts.Addr, id).GetUsbStorageBlocked() {
		t.Fatal("group block should apply before any override")
	}
	allow := false
	if err := s.SetDeviceOverrides(ctx, tenant, uuid.MustParse(id.DeviceID), store.DeviceControlOverrides{USBStorageBlocked: &allow}); err != nil {
		t.Fatal(err)
	}
	if getControls(t, ts.Addr, id).GetUsbStorageBlocked() {
		t.Error("device override Allow should lift the group's USB block")
	}
}

func getControls(t *testing.T, addr string, id *sim.Identity) *flv1.ControlsResponse {
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
	resp, err := flv1.NewAgentClient(conn).GetControls(cctx, &flv1.GetControlsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	return resp
}
