package agentapi_test

import (
	"context"
	"crypto/tls"
	"testing"
	"time"

	flv1 "freelocker/gen/freelocker/v1"
	"freelocker/internal/server/agentapi"
	"freelocker/internal/sim"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func waitDone(t *testing.T, s *sim.Session) error {
	t.Helper()
	select {
	case err := <-s.Done():
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("stream did not end")
		return nil
	}
}

func enrollAndConnect(t *testing.T, ts *testServer) (*sim.Identity, *sim.Session) {
	t.Helper()
	id, err := sim.Enroll(context.Background(), ts.Addr, ts.Token, hw)
	if err != nil {
		t.Fatal(err)
	}
	sess, err := sim.Connect(context.Background(), ts.Addr, id)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sess.Close() })
	return id, sess
}

func TestHeartbeatUpdatesInventoryAndGoodbyeMarksCleanShutdown(t *testing.T) {
	ctx := context.Background()
	ts := startServer(t)
	id, sess := enrollAndConnect(t, ts)
	devID := uuid.MustParse(id.DeviceID)

	if err := sess.Heartbeat(&flv1.Inventory{Hostname: "pc-01", IpAddresses: []string{"10.1.1.1"}, AgentVersion: "0.1.0"}); err != nil {
		t.Fatal(err)
	}
	eventually(t, "device online", func() bool {
		d, _ := ts.Deps.Store.GetDevice(ctx, ts.Deps.Keys.TenantID, devID)
		return d.Status(time.Now()) == "online" && d.AgentVersion == "0.1.0"
	})
	if !ts.Deps.Hub.Connected(devID) {
		t.Error("hub should report connected")
	}

	sess.Goodbye("service stopping")
	eventually(t, "clean shutdown", func() bool {
		d, _ := ts.Deps.Store.GetDevice(ctx, ts.Deps.Keys.TenantID, devID)
		return d.CleanShutdown
	})
	eventually(t, "hub unregistered", func() bool { return !ts.Deps.Hub.Connected(devID) })
}

func TestAgentServiceRequiresClientCert(t *testing.T) {
	ts := startServer(t)
	conn, err := grpc.NewClient(ts.Addr, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{InsecureSkipVerify: true})))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, err = flv1.NewAgentClient(conn).RenewCertificate(context.Background(), &flv1.RenewRequest{})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("err = %v, want Unauthenticated", err)
	}
}

func TestRevokeDisconnectsAndBlocksReconnect(t *testing.T) {
	ctx := context.Background()
	ts := startServer(t)
	id, sess := enrollAndConnect(t, ts)
	devID := uuid.MustParse(id.DeviceID)
	eventually(t, "connected", func() bool { return ts.Deps.Hub.Connected(devID) })

	if err := ts.Deps.Store.RevokeDevice(ctx, ts.Deps.Keys.TenantID, devID); err != nil {
		t.Fatal(err)
	}
	ts.Deps.Hub.Disconnect(devID, agentapi.RevokedError())
	if err := waitDone(t, sess); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("live stream ended with %v, want Unauthenticated", err)
	}

	again, err := sim.Connect(ctx, ts.Addr, id)
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	if err := waitDone(t, again); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("reconnect ended with %v, want Unauthenticated", err)
	}
}

func TestRenewSupersedesOldCertificate(t *testing.T) {
	ctx := context.Background()
	ts := startServer(t)
	id, sess := enrollAndConnect(t, ts)
	sess.Close()

	renewed, err := sim.Renew(ctx, ts.Addr, id)
	if err != nil {
		t.Fatal(err)
	}
	good, err := sim.Connect(ctx, ts.Addr, renewed)
	if err != nil {
		t.Fatal(err)
	}
	defer good.Close()
	devID := uuid.MustParse(id.DeviceID)
	eventually(t, "renewed cert connects", func() bool { return ts.Deps.Hub.Connected(devID) })

	old, _ := sim.Connect(ctx, ts.Addr, id)
	defer old.Close()
	if err := waitDone(t, old); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("old cert: %v, want Unauthenticated", err)
	}
	entries, _ := ts.Deps.Store.ListAudit(ctx, ts.Deps.Keys.TenantID, 1, 0)
	if entries[0].Action != "device.cert_renew" {
		t.Errorf("latest audit = %s", entries[0].Action)
	}
}

func TestSecondConnectionReplacesFirst(t *testing.T) {
	ts := startServer(t)
	id, first := enrollAndConnect(t, ts)
	eventually(t, "first connected", func() bool { return ts.Deps.Hub.Connected(uuid.MustParse(id.DeviceID)) })
	second, err := sim.Connect(context.Background(), ts.Addr, id)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if err := waitDone(t, first); status.Code(err) != codes.Aborted {
		t.Fatalf("first stream ended with %v, want Aborted", err)
	}
}
