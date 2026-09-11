// Package commands issues signed commands to agents and records results.
package commands

import (
	"context"
	"log/slog"
	"time"

	flv1 "freelocker/gen/freelocker/v1"
	"freelocker/internal/server/bootstrap"
	"freelocker/internal/server/hub"
	"freelocker/internal/server/store"

	"github.com/google/uuid"
)

const DefaultTTL = 24 * time.Hour

type Service struct {
	Store *store.Store
	Keys  *bootstrap.Keys
	Hub   *hub.Hub
	Now   func() time.Time
	Log   *slog.Logger
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Service) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

func (s *Service) Issue(ctx context.Context, tenantID, deviceID uuid.UUID, typ flv1.CommandType, payload []byte, issuedBy *uuid.UUID, actor string) (uuid.UUID, error) {
	now := s.now()
	c := store.Command{
		ID: uuid.New(), DeviceID: deviceID, Type: TypeName(typ), Payload: payload, IssuedBy: issuedBy,
		IssuedAt: now, ExpiresAt: now.Add(DefaultTTL),
	}
	if err := s.Store.CreateCommand(ctx, tenantID, c); err != nil {
		return uuid.Nil, err
	}
	if err := s.Store.AppendAudit(ctx, tenantID, store.AuditEntry{
		Actor: actor, Action: "command.issue", TargetType: "device", TargetID: deviceID.String(),
		Detail: map[string]any{"command_id": c.ID.String(), "type": c.Type}, Result: "success",
	}); err != nil {
		s.log().Error("audit write failed", "err", err)
	}
	s.deliver(ctx, tenantID, c)
	return c.ID, nil
}

// DeliverPending pushes every open command; called when an agent connects.
func (s *Service) DeliverPending(ctx context.Context, tenantID, deviceID uuid.UUID) error {
	open, err := s.Store.OpenCommands(ctx, tenantID, deviceID, s.now())
	if err != nil {
		return err
	}
	for _, c := range open {
		s.deliver(ctx, tenantID, c)
	}
	return nil
}

func (s *Service) deliver(ctx context.Context, tenantID uuid.UUID, c store.Command) {
	typ, err := ParseType(c.Type)
	if err != nil {
		s.log().Error("stored command has unknown type", "command", c.ID, "type", c.Type)
		return
	}
	sc, err := Sign(s.Keys.CommandKey, &flv1.Command{
		Id: c.ID.String(), Type: typ, DeviceId: c.DeviceID.String(),
		IssuedAtUnix: c.IssuedAt.Unix(), ExpiresAtUnix: c.ExpiresAt.Unix(), Payload: c.Payload,
	})
	if err != nil {
		s.log().Error("sign command", "command", c.ID, "err", err)
		return
	}
	if !s.Hub.Send(c.DeviceID, &flv1.ServerMessage{Body: &flv1.ServerMessage_Command{Command: sc}}) {
		return // stays pending; delivered on next connect
	}
	if c.State == "" || c.State == "pending" {
		if err := s.Store.MarkCommandSent(ctx, tenantID, c.ID); err != nil {
			s.log().Warn("mark command sent", "command", c.ID, "err", err)
		}
	}
}

func (s *Service) Complete(ctx context.Context, tenantID, deviceID uuid.UUID, r *flv1.CommandResult) error {
	id, err := uuid.Parse(r.GetCommandId())
	if err != nil {
		return err
	}
	if err := s.Store.CompleteCommand(ctx, tenantID, deviceID, id, r.GetSuccess(), r.GetMessage(), s.now()); err != nil {
		return err
	}
	result := "failure"
	if r.GetSuccess() {
		result = "success"
	}
	return s.Store.AppendAudit(ctx, tenantID, store.AuditEntry{
		Actor: "device:" + deviceID.String(), Action: "command.result", TargetType: "command", TargetID: id.String(),
		Detail: map[string]any{"message": r.GetMessage()}, Result: result,
	})
}

func (s *Service) ExpireStale(ctx context.Context) (int64, error) {
	return s.Store.ExpireCommands(ctx, s.now())
}
