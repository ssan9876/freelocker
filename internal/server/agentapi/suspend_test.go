package agentapi_test

import (
	"context"
	"testing"
	"time"

	flv1 "freelocker/gen/freelocker/v1"
	"freelocker/internal/sim"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

// TestSuspendedTenantDeviceRefused proves a suspended tenant's agents are
// refused with PermissionDenied (nothing changes on the endpoint; the agent
// just retries) and are served again once the tenant is unsuspended.
func TestSuspendedTenantDeviceRefused(t *testing.T) {
	ctx := context.Background()
	ts := startServer(t)
	id, err := sim.Enroll(ctx, ts.Addr, ts.Token, hw)
	if err != nil {
		t.Fatal(err)
	}
	tenant := ts.Deps.Keys.TenantID

	if code := getPolicyCode(t, ts.Addr, id); code != codes.OK {
		t.Fatalf("before suspend: %v", code)
	}
	if err := ts.Deps.Store.SetTenantSuspended(ctx, tenant, true); err != nil {
		t.Fatal(err)
	}
	if code := getPolicyCode(t, ts.Addr, id); code != codes.PermissionDenied {
		t.Errorf("suspended: code = %v, want PermissionDenied", code)
	}
	if _, err := sim.Enroll(ctx, ts.Addr, ts.Token, hw); status.Code(err) != codes.PermissionDenied {
		t.Errorf("enroll into suspended tenant: %v, want PermissionDenied", err)
	}

	ts.Deps.Store.SetTenantSuspended(ctx, tenant, false)
	if code := getPolicyCode(t, ts.Addr, id); code != codes.OK {
		t.Errorf("after unsuspend: %v", code)
	}
}

func getPolicyCode(t *testing.T, addr string, id *sim.Identity) codes.Code {
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
	_, err = flv1.NewAgentClient(conn).GetPolicy(cctx, &flv1.GetPolicyRequest{})
	return status.Code(err)
}
