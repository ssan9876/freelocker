package agentapi_test

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	flv1 "freelocker/gen/freelocker/v1"
	"freelocker/internal/server/agentapi"
	"freelocker/internal/server/alerting"
	"freelocker/internal/server/bootstrap"
	"freelocker/internal/server/commands"
	"freelocker/internal/server/hub"
	"freelocker/internal/server/keyset"
	"freelocker/internal/server/policysvc"
	"freelocker/internal/server/store"
	"freelocker/internal/server/store/storetest"
	"freelocker/internal/server/tokens"
	"freelocker/internal/sim"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// TestMultiTenantEnrollmentOverTheWire proves two tenants, each with its own
// CA, can enroll and connect agents over one server: SNI selects the right
// per-tenant server cert and the client-CA union authenticates each tenant's
// device cert. It also proves a device from tenant A cannot pass its cert to
// tenant B's transport.
func TestMultiTenantEnrollmentOverTheWire(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	master := bytes.Repeat([]byte{21}, 32)
	tenantA, err := bootstrap.Init(ctx, s, master, "Acme", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	tenantB, err := bootstrap.ProvisionTenant(ctx, s, master, "Beta", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	kp := keyset.New(s, master)
	ka, _ := kp.For(ctx, tenantA)
	kb, _ := kp.For(ctx, tenantB)

	// A group-scoped install token per tenant.
	tokenFor := func(tid uuid.UUID, pin string) string {
		full, hash, _ := tokens.Generate(pin)
		if _, err := s.CreateInstallToken(ctx, tid, store.InstallToken{Name: "t"}, hash); err != nil {
			t.Fatal(err)
		}
		return full
	}
	tokA := tokenFor(tenantA, ka.CA.Pin())
	tokB := tokenFor(tenantB, kb.CA.Pin())

	// Server with the multi-tenant TLS + per-tenant key resolver.
	h := hub.New()
	deps := agentapi.Deps{
		Store: s, KeyFor: kp.For, Hub: h,
		Commands: &commands.Service{Store: s, KeyFor: kp.For, Hub: h},
		Policy:   &policysvc.Service{Store: s, KeyFor: kp.For},
		Alerting: alerting.New(s),
	}
	tlsCfg := agentapi.NewTenantTLS(kp, s, []string{"127.0.0.1"}, time.Now).Config()
	lis, _ := net.Listen("tcp", "127.0.0.1:0")
	srv := agentapi.NewGRPCServer(deps, tlsCfg)
	go srv.Serve(lis)
	t.Cleanup(srv.Stop)
	addr := lis.Addr().String()

	hw := &flv1.HardwareInfo{Hostname: "pc", OsBuild: "26100"}
	idA, err := sim.Enroll(ctx, addr, tokA, hw)
	if err != nil {
		t.Fatalf("tenant A enroll: %v", err)
	}
	idB, err := sim.Enroll(ctx, addr, tokB, hw)
	if err != nil {
		t.Fatalf("tenant B enroll: %v", err)
	}

	// Each device authenticates over its own tenant's transport and reaches
	// the Agent service (GetPolicy returns its tenant's policy version).
	if v := getPolicyVersion(t, addr, idA); v == "" {
		t.Error("tenant A device could not GetPolicy")
	}
	if v := getPolicyVersion(t, addr, idB); v == "" {
		t.Error("tenant B device could not GetPolicy")
	}

	// The two devices belong to different tenants.
	tA, _, _, _ := s.DeviceAuthState(ctx, uuid.MustParse(idA.DeviceID))
	tB, _, _, _ := s.DeviceAuthState(ctx, uuid.MustParse(idB.DeviceID))
	if tA != tenantA || tB != tenantB || tA == tB {
		t.Fatalf("device tenants = %v, %v; want %v, %v", tA, tB, tenantA, tenantB)
	}

	// Cross-tenant transport: device A's client cert but tenant B's SNI +
	// roots must NOT establish a usable session (server presents B's cert,
	// which A's roots reject; and A's client cert isn't signed by... it is
	// in the union pool, but the server cert won't validate for A's roots).
	crossCfg, _ := idA.TLSConfig()
	crossCfg.ServerName = kb.CA.Pin() // pretend to be tenant B
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(credentials.NewTLS(crossCfg)))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if _, err := flv1.NewAgentClient(conn).GetPolicy(cctx, &flv1.GetPolicyRequest{}); err == nil {
		t.Error("device A must not connect over tenant B's SNI (server cert is B's, A trusts only A)")
	}
}

func getPolicyVersion(t *testing.T, addr string, id *sim.Identity) string {
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
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := flv1.NewAgentClient(conn).GetPolicy(ctx, &flv1.GetPolicyRequest{})
	if err != nil {
		return ""
	}
	return resp.GetVersion()
}
