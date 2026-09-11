package agentapi

import (
	"context"
	"errors"
	"time"

	flv1 "freelocker/gen/freelocker/v1"
	"freelocker/internal/server/store"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *agentService) GetPolicy(ctx context.Context, _ *flv1.GetPolicyRequest) (*flv1.GetPolicyResponse, error) {
	dev := deviceFrom(ctx)
	if s.d.Policy == nil {
		return nil, status.Error(codes.Unavailable, "application control not enabled")
	}
	eff, err := s.d.Policy.Effective(ctx, dev.TenantID, dev.ID)
	if err != nil {
		s.d.Log.Error("resolve policy", "device", dev.ID, "err", err)
		return nil, status.Error(codes.Internal, "could not resolve policy")
	}
	return &flv1.GetPolicyResponse{Version: eff.Version, Mode: eff.Mode, Xml: eff.XML, Signature: eff.Signature}, nil
}

func (s *agentService) Observe(ctx context.Context, req *flv1.ObserveRequest) (*flv1.Ack, error) {
	dev := deviceFrom(ctx)
	now := s.d.Now()
	for _, a := range req.GetApps() {
		if a.GetSha256() == "" || a.GetPath() == "" {
			continue
		}
		err := s.d.Store.RecordObservation(ctx, dev.TenantID, dev.ID, store.Observation{
			SHA256: a.GetSha256(), Path: a.GetPath(), Signer: a.GetSigner(),
		}, now)
		if err != nil {
			s.d.Log.Error("record observation", "device", dev.ID, "err", err)
			return nil, status.Error(codes.Internal, "could not record observations")
		}
	}
	return &flv1.Ack{}, nil
}

func (s *agentService) ReportBlocks(ctx context.Context, req *flv1.ReportBlocksRequest) (*flv1.Ack, error) {
	dev := deviceFrom(ctx)
	events := make([]store.BlockEvent, 0, len(req.GetEvents()))
	for _, e := range req.GetEvents() {
		at := time.Unix(e.GetAtUnix(), 0)
		if e.GetAtUnix() == 0 {
			at = s.d.Now()
		}
		events = append(events, store.BlockEvent{
			SHA256: e.GetSha256(), Path: e.GetPath(), Signer: e.GetSigner(), Blocked: e.GetBlocked(), At: at,
		})
	}
	if err := s.d.Store.RecordBlockEvents(ctx, dev.TenantID, dev.ID, events); err != nil {
		s.d.Log.Error("record block events", "device", dev.ID, "err", err)
		return nil, status.Error(codes.Internal, "could not record block events")
	}
	s.queueApprovals(ctx, dev.TenantID, dev.ID, events)
	return &flv1.Ack{}, nil
}

// queueApprovals turns block events into approval requests against the
// device's effective policy. Failures are logged only: the block events are
// already recorded and are the source of truth.
func (s *agentService) queueApprovals(ctx context.Context, tenantID, deviceID uuid.UUID, events []store.BlockEvent) {
	pv, err := s.d.Store.EffectivePolicyForDevice(ctx, tenantID, deviceID)
	if errors.Is(err, store.ErrNotFound) {
		return
	}
	if err != nil {
		s.d.Log.Error("resolve policy for approvals", "device", deviceID, "err", err)
		return
	}
	if err := s.d.Store.UpsertApprovalRequests(ctx, tenantID, pv.PolicyID, deviceID, events); err != nil {
		s.d.Log.Error("queue approval requests", "device", deviceID, "err", err)
	}
}

func (s *agentService) GetControls(ctx context.Context, _ *flv1.GetControlsRequest) (*flv1.ControlsResponse, error) {
	dev := deviceFrom(ctx)
	c, err := s.d.Store.EffectiveControlsForDevice(ctx, dev.TenantID, dev.ID)
	if err == store.ErrNotFound {
		return &flv1.ControlsResponse{}, nil // default allow
	}
	if err != nil {
		s.d.Log.Error("resolve controls", "device", dev.ID, "err", err)
		return nil, status.Error(codes.Internal, "could not resolve controls")
	}
	return &flv1.ControlsResponse{UsbStorageBlocked: c.USBStorageBlocked}, nil
}

func (s *agentService) ReportMetrics(ctx context.Context, req *flv1.MetricsRequest) (*flv1.Ack, error) {
	dev := deviceFrom(ctx)
	now := s.d.Now()
	sample := store.MetricSample{CPUPct: req.GetCpuPct(), MemPct: req.GetMemPct(), DiskPct: req.GetDiskPct(), At: now}
	if err := s.d.Store.RecordMetrics(ctx, dev.TenantID, dev.ID, sample, now); err != nil {
		s.d.Log.Error("record metrics", "device", dev.ID, "err", err)
		return nil, status.Error(codes.Internal, "could not record metrics")
	}
	if s.d.Alerting != nil {
		if err := s.d.Alerting.Evaluate(ctx, dev.TenantID, dev.ID, sample, now); err != nil {
			s.d.Log.Error("evaluate alerts", "device", dev.ID, "err", err)
		}
	}
	return &flv1.Ack{}, nil
}
