package agentapi

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	flv1 "freelocker/gen/freelocker/v1"
	"freelocker/internal/server/notify"
	"freelocker/internal/server/store"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// baseName returns the final path component, splitting on both '\' and '/'
// so a Windows path is handled correctly even when running on Linux (where
// filepath.Base would not split on '\').
func baseName(p string) string {
	if i := strings.LastIndexAny(p, `\/`); i >= 0 {
		return p[i+1:]
	}
	return p
}

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
			SignerTBS: a.GetSignerTbs(), SignerVerified: a.GetSignerVerified(),
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
			SignerTBS: e.GetSignerTbs(), SignerVerified: e.GetSignerVerified(),
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
	newIDs, err := s.d.Store.UpsertApprovalRequests(ctx, tenantID, pv.PolicyID, deviceID, events)
	if err != nil {
		s.d.Log.Error("queue approval requests", "device", deviceID, "err", err)
		return
	}
	if s.d.Notify == nil || len(newIDs) == 0 {
		return
	}
	host := deviceID.String()
	if d, err := s.d.Store.GetDevice(ctx, tenantID, deviceID); err == nil && d.Hostname != "" {
		host = d.Hostname
	}
	for _, id := range newIDs {
		req, err := s.d.Store.GetApprovalRequest(ctx, tenantID, id)
		if err != nil {
			s.d.Log.Error("load approval request for notification", "request", id, "err", err)
			continue
		}
		s.d.Notify.Emit(ctx, notify.Event{Kind: "approval.new", TenantID: tenantID, At: req.FirstSeen,
			Title:  fmt.Sprintf("Approval requested: %s on %s", baseName(req.Path), host),
			Body:   fmt.Sprintf("%s was blocked on %s by policy %s and is waiting for approval.\nPath: %s\nSigner: %s", baseName(req.Path), host, req.PolicyName, req.Path, req.Signer),
			Detail: map[string]any{"request_id": id.String(), "policy_id": req.PolicyID.String(), "policy_name": req.PolicyName, "sha256": req.SHA256, "path": req.Path, "signer": req.Signer, "device_id": deviceID.String(), "hostname": host}})
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
	return &flv1.ControlsResponse{
		UsbStorageBlocked: c.USBStorageBlocked,
		NetworkBlocked:    c.NetworkBlocked,
		ElevationBlocked:  c.ElevationBlocked,
	}, nil
}

func (s *agentService) ReportEvents(ctx context.Context, req *flv1.EventsRequest) (*flv1.Ack, error) {
	dev := deviceFrom(ctx)
	evs := make([]store.DeviceEvent, 0, len(req.GetEvents()))
	for _, e := range req.GetEvents() {
		if e.GetKind() == "" {
			continue
		}
		at := time.Unix(e.GetAtUnix(), 0)
		if e.GetAtUnix() == 0 {
			at = s.d.Now()
		}
		evs = append(evs, store.DeviceEvent{Kind: e.GetKind(), Summary: e.GetSummary(), At: at})
	}
	if err := s.d.Store.RecordDeviceEvents(ctx, dev.TenantID, dev.ID, evs); err != nil {
		s.d.Log.Error("record device events", "device", dev.ID, "err", err)
		return nil, status.Error(codes.Internal, "could not record events")
	}
	return &flv1.Ack{}, nil
}

func (s *agentService) GetRingfence(ctx context.Context, _ *flv1.GetRingfenceRequest) (*flv1.GetRingfenceResponse, error) {
	dev := deviceFrom(ctx)
	rf, err := s.d.Store.RingfenceForDevice(ctx, dev.TenantID, dev.ID)
	if err == store.ErrNotFound {
		return &flv1.GetRingfenceResponse{}, nil // nothing assigned; agent clears any rules it set
	}
	if err != nil {
		s.d.Log.Error("resolve ringfence", "device", dev.ID, "err", err)
		return nil, status.Error(codes.Internal, "could not resolve ringfence")
	}
	out := &flv1.GetRingfenceResponse{Version: rf.Version, Mode: rf.Mode}
	for _, p := range rf.Programs {
		out.Programs = append(out.Programs, &flv1.RingfenceProgram{Path: p.Path, NetworkBlocked: p.NetworkBlocked})
	}
	for _, p := range rf.Protections {
		out.Protections = append(out.Protections, &flv1.RingfenceProtection{AsrRule: p.ASRRule, Action: p.Action})
	}
	return out, nil
}

func (s *agentService) ReportRingfenceEvents(ctx context.Context, req *flv1.ReportRingfenceEventsRequest) (*flv1.Ack, error) {
	dev := deviceFrom(ctx)
	evs := make([]store.RingfenceEvent, 0, len(req.GetEvents()))
	for _, e := range req.GetEvents() {
		if e.GetKind() != "network" && e.GetKind() != "child_process" {
			continue // ignore unknown kinds rather than failing the batch
		}
		at := time.Unix(e.GetAtUnix(), 0)
		if e.GetAtUnix() == 0 {
			at = time.Now()
		}
		evs = append(evs, store.RingfenceEvent{
			Kind: e.GetKind(), Program: e.GetProgram(), Detail: e.GetDetail(),
			Enforced: e.GetEnforced(), At: at,
		})
	}
	if err := s.d.Store.AppendRingfenceEvents(ctx, dev.TenantID, dev.ID, evs); err != nil {
		s.d.Log.Error("append ringfence events", "device", dev.ID, "err", err)
		return nil, status.Error(codes.Internal, "could not record events")
	}
	// ASR availability is recorded for the calling device only -- deviceFrom
	// comes from the mTLS cert, never the request body -- so one device
	// cannot report another's Defender state.
	if err := s.d.Store.SetDeviceASRAvailable(ctx, dev.TenantID, dev.ID, req.GetAsrAvailable()); err != nil {
		s.d.Log.Error("set device asr available", "device", dev.ID, "err", err)
		return nil, status.Error(codes.Internal, "could not record events")
	}
	return &flv1.Ack{}, nil
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
