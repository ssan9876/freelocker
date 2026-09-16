package agentapi_test

import (
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	flv1 "freelocker/gen/freelocker/v1"
	"freelocker/internal/server/agentapi"
	"freelocker/internal/server/notify"
	"freelocker/internal/server/policysvc"
	"freelocker/internal/server/store"
	"freelocker/internal/server/tokens"
	"freelocker/internal/sim"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type recEmitter struct{ events []notify.Event }

func (r *recEmitter) Emit(_ context.Context, e notify.Event) { r.events = append(r.events, e) }

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
	// An agent that sends no provenance field at all leaves it unknown, not
	// false — this is the wire behaviour that lets an older agent coexist
	// with the console's "unknown" state.
	if obs[0].Downloaded != nil {
		t.Errorf("absent provenance became %v, want nil", *obs[0].Downloaded)
	}

	// A newer agent reports the mark, and it survives the round trip.
	yes := true
	if _, err := client.Observe(ctx, &flv1.ObserveRequest{Apps: []*flv1.ObservedApp{
		{Sha256: "CC", Path: `C:\Users\u\Downloads\setup.exe`, Downloaded: &yes,
			DownloadSource: "https://example.com/setup.exe"},
	}}); err != nil {
		t.Fatal(err)
	}
	obs, _ = ts.Deps.Store.ListObservations(ctx, tenant, devID, 10)
	var downloaded *store.Observation
	for i := range obs {
		if obs[i].SHA256 == "CC" {
			downloaded = &obs[i]
		}
	}
	if downloaded == nil {
		t.Fatalf("downloaded observation missing from %+v", obs)
	}
	if downloaded.Downloaded == nil || !*downloaded.Downloaded {
		t.Errorf("provenance = %v, want true over the wire", downloaded.Downloaded)
	}
	if downloaded.DownloadSource != "https://example.com/setup.exe" {
		t.Errorf("source = %q", downloaded.DownloadSource)
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

	reqs, err := ts.Deps.Store.ListApprovalRequests(ctx, tenant, "pending", 10)
	if err != nil || len(reqs) != 1 || reqs[0].SHA256 != "BB" || reqs[0].PolicyID != pid || reqs[0].DeviceCount != 1 {
		t.Fatalf("approval requests = %+v, %v", reqs, err)
	}
}

func TestReportBlocksEmitsApprovalNew(t *testing.T) {
	ctx := context.Background()
	rec := &recEmitter{}
	ts := startServer(t, func(d *agentapi.Deps) { d.Notify = rec })
	tenant := ts.Deps.Keys.TenantID
	svc := &policysvc.Service{Store: ts.Deps.Store, Keys: ts.Deps.Keys}

	gid, _ := ts.Deps.Store.CreateDeviceGroup(ctx, tenant, "WS")
	pid, _ := ts.Deps.Store.CreatePolicy(ctx, tenant, "Baseline", "audit")
	hash64 := ""
	for i := 0; i < 64; i++ {
		hash64 += "A"
	}
	ts.Deps.Store.AddRule(ctx, tenant, pid, store.PolicyRule{Kind: "hash", Value: hash64}, nil)
	if _, err := svc.Recompile(ctx, tenant, pid); err != nil {
		t.Fatal(err)
	}
	ts.Deps.Store.AssignPolicy(ctx, tenant, gid, pid)

	full, hash, _ := tokens.Generate(ts.Deps.Keys.CA.Pin())
	ts.Deps.Store.CreateInstallToken(ctx, tenant, store.InstallToken{Name: "ws", GroupID: &gid}, hash)
	id, err := sim.Enroll(ctx, ts.Addr, full, hw)
	if err != nil {
		t.Fatal(err)
	}
	client := agentClient(t, ts, id)

	if _, err := client.ReportBlocks(ctx, &flv1.ReportBlocksRequest{Events: []*flv1.BlockEvent{
		{Sha256: "BB", Path: `C:\bad.exe`, Blocked: false, AtUnix: time.Now().Unix()},
	}}); err != nil {
		t.Fatal(err)
	}
	if len(rec.events) != 1 || rec.events[0].Kind != "approval.new" {
		t.Fatalf("events after first report = %+v", rec.events)
	}

	// A repeat of the same hash must not emit again.
	if _, err := client.ReportBlocks(ctx, &flv1.ReportBlocksRequest{Events: []*flv1.BlockEvent{
		{Sha256: "BB", Path: `C:\bad.exe`, Blocked: false, AtUnix: time.Now().Unix()},
	}}); err != nil {
		t.Fatal(err)
	}
	if len(rec.events) != 1 {
		t.Fatalf("events after repeat report = %+v, want still 1", rec.events)
	}
}

func TestReportBlocksWithoutPolicyCreatesNoApproval(t *testing.T) {
	ctx := context.Background()
	ts := startServer(t)
	tenant := ts.Deps.Keys.TenantID

	full, hash, _ := tokens.Generate(ts.Deps.Keys.CA.Pin())
	ts.Deps.Store.CreateInstallToken(ctx, tenant, store.InstallToken{Name: "nogroup"}, hash)
	id, err := sim.Enroll(ctx, ts.Addr, full, hw)
	if err != nil {
		t.Fatal(err)
	}
	client := agentClient(t, ts, id)
	if _, err := client.ReportBlocks(ctx, &flv1.ReportBlocksRequest{Events: []*flv1.BlockEvent{
		{Sha256: "CC", Path: `C:\x.exe`, AtUnix: time.Now().Unix()},
	}}); err != nil {
		t.Fatalf("report must still ack without a policy: %v", err)
	}
	if blocks, _ := ts.Deps.Store.ListBlockEvents(ctx, tenant, 10); len(blocks) != 1 {
		t.Fatalf("block events = %+v", blocks)
	}
	if reqs, _ := ts.Deps.Store.ListApprovalRequests(ctx, tenant, "", 10); len(reqs) != 0 {
		t.Fatalf("approval requests = %+v, want none", reqs)
	}
}
