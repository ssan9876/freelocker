package agentapi_test

import (
	"context"
	"testing"
	"time"

	flv1 "freelocker/gen/freelocker/v1"
	"freelocker/internal/server/commands"
	"freelocker/internal/sim"

	"github.com/google/uuid"
)

func recvCommand(t *testing.T, s *sim.Session) *flv1.SignedCommand {
	t.Helper()
	select {
	case c := <-s.Commands():
		return c
	case <-time.After(5 * time.Second):
		t.Fatal("no command received")
		return nil
	}
}

func TestLiveCommandDeliveredSignedAndResultRecorded(t *testing.T) {
	ctx := context.Background()
	ts := startServer(t)
	id, sess := enrollAndConnect(t, ts)
	devID := uuid.MustParse(id.DeviceID)
	eventually(t, "connected", func() bool { return ts.Deps.Hub.Connected(devID) })
	svc := ts.Deps.Commands.(*commands.Service)

	cmdID, err := svc.Issue(ctx, ts.Deps.Keys.TenantID, devID, flv1.CommandType_COMMAND_TYPE_PING, nil, nil, "admin:test@example.com")
	if err != nil {
		t.Fatal(err)
	}
	cmd, err := commands.Verify(id.CommandPub, recvCommand(t, sess), id.DeviceID, time.Now())
	if err != nil || cmd.GetId() != cmdID.String() || cmd.GetType() != flv1.CommandType_COMMAND_TYPE_PING {
		t.Fatalf("verify = %+v, %v", cmd, err)
	}

	sess.SendResult(&flv1.CommandResult{CommandId: cmd.GetId(), Success: true, Message: "pong"})
	eventually(t, "command succeeded", func() bool {
		hist, _ := ts.Deps.Store.ListDeviceCommands(ctx, ts.Deps.Keys.TenantID, devID, 1)
		return len(hist) == 1 && hist[0].State == "succeeded" && hist[0].Result == "pong"
	})
}

func TestCommandQueuedWhileOfflineDeliveredOnConnect(t *testing.T) {
	ctx := context.Background()
	ts := startServer(t)
	id, err := sim.Enroll(ctx, ts.Addr, ts.Token, hw)
	if err != nil {
		t.Fatal(err)
	}
	devID := uuid.MustParse(id.DeviceID)
	svc := ts.Deps.Commands.(*commands.Service)
	cmdID, _ := svc.Issue(ctx, ts.Deps.Keys.TenantID, devID, flv1.CommandType_COMMAND_TYPE_REFRESH_INVENTORY, nil, nil, "system")

	sess, err := sim.Connect(ctx, ts.Addr, id)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	cmd, err := commands.Verify(id.CommandPub, recvCommand(t, sess), id.DeviceID, time.Now())
	if err != nil || cmd.GetId() != cmdID.String() {
		t.Fatalf("queued command = %+v, %v", cmd, err)
	}
}
