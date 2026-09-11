package agentapi_test

import (
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	flv1 "freelocker/gen/freelocker/v1"
	"freelocker/internal/server/policysvc"
	"freelocker/internal/server/store"
	"freelocker/internal/server/tokens"
	"freelocker/internal/sim"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func agentClient(t *testing.T, ts *testServer, id *sim.Identity) flv1.AgentClient {
	t.Helper()
	cfg, err := id.TLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	conn, err := grpc.NewClient(ts.Addr, grpc.WithTransportCredentials(credentials.NewTLS(cfg)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return flv1.NewAgentClient(conn)
}

func TestGetPolicyObserveAndReportBlocks(t *testing.T) {
	ctx := context.Background()
	ts := startServer(t)
	tenant := ts.Deps.Keys.TenantID
	svc := &policysvc.Service{Store: ts.Deps.Store, Keys: ts.Deps.Keys}

	// Build a policy, assign it to a group, and enroll a device into that
	// group via a group-scoped install token.
	gid, _ := ts.Deps.Store.CreateDeviceGroup(ctx, tenant, "WS")
	pid, _ := ts.Deps.Store.CreatePolicy(ctx, tenant, "Baseline", "audit")
	hash64 := ""
	for i := 0; i < 64; i++ {
		hash64 += "A"
	}
	ts.Deps.Store.AddRule(ctx, tenant, pid, store.PolicyRule{Kind: "hash", Value: hash64}, nil)
	version, err := svc.Recompile(ctx, tenant, pid)
	if err != nil {
		t.Fatal(err)
	}
	ts.Deps.Store.AssignPolicy(ctx, tenant, gid, pid)

	full, hash, _ := tokens.Generate(ts.Deps.Keys.CA.Pin())
	ts.Deps.Store.CreateInstallToken(ctx, tenant, store.InstallToken{Name: "ws", GroupID: &gid}, hash)
	id, err := sim.Enroll(ctx, ts.Addr, full, hw)
	if err != nil {
		t.Fatal(err)
	}
	devID := uuid.MustParse(id.DeviceID)

	client := agentClient(t, ts, id)
	resp, err := client.GetPolicy(ctx, &flv1.GetPolicyRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetVersion() != version || resp.GetMode() != "audit" || len(resp.GetXml()) == 0 {
		t.Fatalf("policy = %q %q len=%d", resp.GetVersion(), resp.GetMode(), len(resp.GetXml()))
	}
	if !ed25519.Verify(id.UpdatePub, []byte(resp.GetVersion()), resp.GetSignature()) {
		t.Error("policy signature must verify with the update key")
	}

	if _, err := client.Observe(ctx, &flv1.ObserveRequest{Apps: []*flv1.ObservedApp{
		{Sha256: "AA", Path: `C:\app.exe`, Signer: "Acme"},
	}}); err != nil {
		t.Fatal(err)
	}
	obs, _ := ts.Deps.Store.ListObservations(ctx, tenant, devID, 10)
	if len(obs) != 1 || obs[0].SHA256 != "AA" {
		t.Fatalf("observations = %+v", obs)
	}

	if _, err := client.ReportBlocks(ctx, &flv1.ReportBlocksRequest{Events: []*flv1.BlockEvent{
		{Sha256: "BB", Path: `C:\bad.exe`, Blocked: false, AtUnix: time.Now().Unix()},
	}}); err != nil {
		t.Fatal(err)
	}
	blocks, _ := ts.Deps.Store.ListBlockEvents(ctx, tenant, 10)
	if len(blocks) != 1 || blocks[0].Path != `C:\bad.exe` {
		t.Fatalf("block events = %+v", blocks)
	}
}
