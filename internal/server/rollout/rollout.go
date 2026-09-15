// Package rollout drives staged agent updates: each tick issues signed
// update commands to a batch of targeted devices and resolves progress from
// command results and the version each device reports.
package rollout

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"freelocker/internal/server/commands"
	"freelocker/internal/server/notify"
	"freelocker/internal/server/store"

	"github.com/google/uuid"
)

const DefaultConfirmTimeout = 10 * time.Minute

type Service struct {
	Store    *store.Store
	Commands *commands.Service
	// Online reports whether a device currently holds a stream to the hub.
	Online func(deviceID uuid.UUID) bool
	// ReleaseURL builds the download URL for a version.
	ReleaseURL func(version string) string
	Now        func() time.Time
	// ConfirmTimeout is how long after a successful update command a device
	// may keep reporting the old version before it counts as failed.
	ConfirmTimeout time.Duration
	Log            *slog.Logger
	Notify         notify.Emitter
}

func (s *Service) emit(ctx context.Context, e notify.Event) {
	if s.Notify != nil {
		s.Notify.Emit(ctx, e)
	}
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

func (s *Service) timeout() time.Duration {
	if s.ConfirmTimeout > 0 {
		return s.ConfirmTimeout
	}
	return DefaultConfirmTimeout
}

// Tick reconciles every active rollout of every non-suspended tenant. An
// error in one rollout is logged and does not stop the others.
func (s *Service) Tick(ctx context.Context) error {
	open, err := s.Store.OpenRollouts(ctx)
	if err != nil {
		return err
	}
	for _, o := range open {
		if err := s.Reconcile(ctx, o.TenantID, o.Rollout); err != nil {
			s.log().Error("rollout reconcile", "rollout", o.ID, "err", err)
		}
	}
	return nil
}

// Reconcile runs one pass over an active rollout: resolve in-flight rows,
// auto-pause on failures, issue the next batch, and complete when nothing
// is left.
func (s *Service) Reconcile(ctx context.Context, tenantID uuid.UUID, r store.Rollout) error {
	if r.State != "active" {
		return nil
	}
	now := s.now()

	// 1. Resolve in-flight devices first so freed batch slots are reused.
	_, newlyFailed, err := s.Store.ResolveRolloutDevices(ctx, tenantID, r.ID, now, s.timeout())
	if err != nil {
		return fmt.Errorf("resolve: %w", err)
	}
	sum, err := s.Store.RolloutSummary(ctx, tenantID, r.ID)
	if err != nil {
		return err
	}

	// 2. Auto-pause when failures reach the threshold. Only a tick that
	// resolved a new failure may pause: the failure count is cumulative, so
	// gating on it alone would re-pause the rollout on the first tick after
	// an operator resumed it, leaving resume a dead end.
	if r.MaxFailures > 0 && newlyFailed > 0 && sum.Failed >= r.MaxFailures {
		if err := s.Store.SetRolloutState(ctx, tenantID, r.ID, []string{"active"}, "paused", now); err != nil {
			return fmt.Errorf("auto-pause: %w", err)
		}
		if err := s.Store.AppendAudit(ctx, tenantID, store.AuditEntry{
			Actor: "system", Action: "rollout.auto_pause", TargetType: "rollout", TargetID: r.ID.String(),
			Detail: map[string]any{"version": r.Version, "failed": sum.Failed, "max_failures": r.MaxFailures}, Result: "success",
		}); err != nil {
			s.log().Error("rollout audit", "rollout", r.ID, "action", "rollout.auto_pause", "err", err)
		}
		s.log().Warn("rollout auto-paused", "rollout", r.ID, "failed", sum.Failed)
		s.emit(ctx, notify.Event{Kind: "rollout.auto_paused", TenantID: tenantID, At: now,
			Title:  fmt.Sprintf("Rollout of %s auto-paused after %d failures", r.Version, sum.Failed),
			Body:   fmt.Sprintf("The rollout of agent %s was paused automatically: %d devices failed to update (threshold %d). Review the failures in the console, then resume or roll back.", r.Version, sum.Failed, r.MaxFailures),
			Detail: map[string]any{"rollout_id": r.ID.String(), "version": r.Version, "failed": sum.Failed, "max_failures": r.MaxFailures}})
		return nil
	}

	// 3. Issue the next batch to online candidates.
	if slots := r.BatchSize - sum.Issued; slots > 0 {
		rel, err := s.Store.GetRelease(ctx, tenantID, r.Version)
		if err != nil {
			return fmt.Errorf("release %s: %w", r.Version, err)
		}
		payload := commands.UpdatePayload{Version: rel.Version, URL: s.ReleaseURL(rel.Version), SHA256: rel.SHA256, Signature: rel.Signature}
		cands, err := s.Store.RolloutCandidates(ctx, tenantID, r.ID)
		if err != nil {
			return fmt.Errorf("candidates: %w", err)
		}
		for _, c := range cands {
			if slots == 0 {
				break
			}
			if s.Online != nil && !s.Online(c.DeviceID) {
				continue
			}
			cmdID, err := s.Commands.IssueUpdate(ctx, tenantID, c.DeviceID, payload, "rollout:"+r.ID.String())
			if err != nil {
				s.log().Error("rollout issue update", "rollout", r.ID, "device", c.DeviceID, "err", err)
				continue
			}
			if err := s.Store.AddRolloutDevice(ctx, r.ID, c.DeviceID, cmdID, now); err != nil {
				s.log().Error("rollout record device", "rollout", r.ID, "device", c.DeviceID, "err", err)
				continue
			}
			sum.Issued++
			sum.Remaining--
			slots--
		}
	}

	// 4. Complete when nothing is in flight and nothing is left to issue.
	if sum.Issued == 0 && sum.Remaining == 0 {
		if err := s.Store.SetRolloutState(ctx, tenantID, r.ID, []string{"active"}, "completed", now); err != nil {
			return fmt.Errorf("complete: %w", err)
		}
		s.log().Info("rollout completed", "rollout", r.ID, "version", r.Version, "updated", sum.Updated, "failed", sum.Failed)
		s.emit(ctx, notify.Event{Kind: "rollout.completed", TenantID: tenantID, At: now,
			Title:  fmt.Sprintf("Rollout of %s completed", r.Version),
			Body:   fmt.Sprintf("Agent %s reached every targeted device: %d updated, %d failed.", r.Version, sum.Updated, sum.Failed),
			Detail: map[string]any{"rollout_id": r.ID.String(), "version": r.Version, "updated": sum.Updated, "failed": sum.Failed}})
	}
	return nil
}
