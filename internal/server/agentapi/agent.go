package agentapi

import (
	"context"
	"errors"
	"io"
	"time"

	flv1 "freelocker/gen/freelocker/v1"
	"freelocker/internal/server/hub"
	"freelocker/internal/server/store"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const clockSkew = 5 * time.Minute

type CommandSink interface {
	DeliverPending(ctx context.Context, tenantID, deviceID uuid.UUID) error
	Complete(ctx context.Context, tenantID, deviceID uuid.UUID, r *flv1.CommandResult) error
}

type agentService struct {
	flv1.UnimplementedAgentServer
	d Deps
}

func (s *agentService) Connect(stream flv1.Agent_ConnectServer) error {
	dev := deviceFrom(stream.Context())
	ctx, cancel := context.WithCancelCause(stream.Context())
	defer cancel(nil)
	c := s.d.Hub.Register(dev.ID, cancel)
	defer s.d.Hub.Unregister(dev.ID, c)
	s.d.Log.Info("agent connected", "device", dev.ID)

	if s.d.Commands != nil {
		if err := s.d.Commands.DeliverPending(ctx, dev.TenantID, dev.ID); err != nil {
			s.d.Log.Error("deliver pending commands", "device", dev.ID, "err", err)
		}
	}

	recvErr := make(chan error, 1)
	go func() {
		for {
			m, err := stream.Recv()
			if err != nil {
				recvErr <- err
				return
			}
			s.handle(ctx, dev, m)
		}
	}()

	for {
		select {
		case <-ctx.Done():
			cause := context.Cause(ctx)
			if errors.Is(cause, hub.ErrReplaced) {
				return status.Error(codes.Aborted, cause.Error())
			}
			if st, ok := status.FromError(cause); ok {
				return st.Err()
			}
			return status.FromContextError(cause).Err()
		case err := <-recvErr:
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		case m := <-c.Send:
			if err := stream.Send(m); err != nil {
				return err
			}
		}
	}
}

func (s *agentService) handle(ctx context.Context, dev device, m *flv1.AgentMessage) {
	now := s.d.Now()
	switch b := m.GetBody().(type) {
	case *flv1.AgentMessage_Heartbeat:
		if skew := now.Sub(time.Unix(b.Heartbeat.GetSentAtUnix(), 0)); skew > clockSkew || skew < -clockSkew {
			s.d.Log.Warn("agent clock skew", "device", dev.ID, "skew", skew)
		}
		inv := b.Heartbeat.GetInventory()
		err := s.d.Store.RecordHeartbeat(ctx, dev.TenantID, dev.ID, store.Inventory{
			Hostname: inv.GetHostname(), OSBuild: inv.GetOsBuild(), IPs: inv.GetIpAddresses(),
			LoggedOnUser: inv.GetLoggedOnUser(), AgentVersion: inv.GetAgentVersion(), UptimeSeconds: inv.GetUptimeSeconds(),
		}, now)
		if err != nil {
			s.d.Log.Error("record heartbeat", "device", dev.ID, "err", err)
		}
	case *flv1.AgentMessage_CommandResult:
		if s.d.Commands == nil {
			return
		}
		if err := s.d.Commands.Complete(ctx, dev.TenantID, dev.ID, b.CommandResult); err != nil {
			s.d.Log.Warn("command result rejected", "device", dev.ID, "command", b.CommandResult.GetCommandId(), "err", err)
		}
	case *flv1.AgentMessage_Goodbye:
		if err := s.d.Store.MarkCleanShutdown(ctx, dev.TenantID, dev.ID); err != nil {
			s.d.Log.Error("mark clean shutdown", "device", dev.ID, "err", err)
		}
	}
}

func (s *agentService) RenewCertificate(ctx context.Context, req *flv1.RenewRequest) (*flv1.RenewResponse, error) {
	dev := deviceFrom(ctx)
	now := s.d.Now()
	der, serial, notAfter, err := s.d.Keys.CA.SignDevice(req.GetCsrDer(), dev.ID, now)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if err := s.d.Store.UpdateDeviceCert(ctx, dev.TenantID, dev.ID, serial, notAfter); err != nil {
		return nil, status.Error(codes.Internal, "store certificate")
	}
	if err := s.d.Store.AppendAudit(ctx, dev.TenantID, store.AuditEntry{
		Actor: "device:" + dev.ID.String(), Action: "device.cert_renew", TargetType: "device",
		TargetID: dev.ID.String(), Detail: map[string]any{"serial": serial}, Result: "success",
	}); err != nil {
		s.d.Log.Error("audit write failed", "err", err)
	}
	return &flv1.RenewResponse{CertDer: der}, nil
}
