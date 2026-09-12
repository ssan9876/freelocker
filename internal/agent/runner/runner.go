// Package runner is the agent's main control loop: enroll, connect,
// heartbeat, obey commands, renew, and reconnect.
package runner

import (
	"context"
	"log/slog"
	"math/rand/v2"
	"sync"
	"time"

	"crypto/ed25519"

	flv1 "freelocker/gen/freelocker/v1"
	"freelocker/internal/agent/blocks"
	"freelocker/internal/agent/controls"
	"freelocker/internal/agent/enforcer"
	"freelocker/internal/agent/events"
	"freelocker/internal/agent/executor"
	"freelocker/internal/agent/identity"
	"freelocker/internal/agent/inventory"
	"freelocker/internal/agent/metrics"
	"freelocker/internal/agent/scan"
	"freelocker/internal/appcontrol/signature"
	"freelocker/internal/server/ca"
	"freelocker/internal/server/commands"
	"freelocker/internal/sim"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

type Runner struct {
	ServerURL         string
	Identity          *identity.Store
	Inventory         inventory.Collector
	Executor          *executor.Executor
	HeartbeatInterval time.Duration
	Log               *slog.Logger
	Clock             func() time.Time

	// Application control (optional). When Enforcer is set, the runner
	// periodically pulls the assigned policy, verifies its signature with
	// UpdatePub, applies it, reports observed apps, and forwards block
	// events. Scan defaults to scan.Running.
	Enforcer           enforcer.Enforcer
	UpdatePub          ed25519.PublicKey
	Scan               func() ([]scan.Observed, error)
	AppControlInterval time.Duration

	// Telemetry (optional). When MetricsInterval > 0, the runner reports a
	// resource sample on that interval. Metrics defaults to metrics.Collect.
	MetricsInterval time.Duration
	Metrics         func() (metrics.Sample, error)

	// Device controls (optional). When Controls is set, the runner pulls
	// and applies device controls on the app-control tick.
	Controls controls.Enforcer

	// Events (optional). When set, the runner reports device events
	// (process launches, logons) on the metrics ticker.
	Events events.Reader

	refreshOnce sync.Once
	refresh     chan struct{}
}

func (r *Runner) refreshCh() chan struct{} {
	r.refreshOnce.Do(func() { r.refresh = make(chan struct{}, 1) })
	return r.refresh
}

// RequestHeartbeat asks the current session to send a heartbeat (with fresh
// inventory) now rather than at the next interval. Requests made while one is
// already pending coalesce; it never blocks.
func (r *Runner) RequestHeartbeat() {
	select {
	case r.refreshCh() <- struct{}{}:
	default:
	}
}

func HardwareInfo(c inventory.Collector) *flv1.HardwareInfo {
	inv := c.Collect()
	return &flv1.HardwareInfo{Hostname: inv.GetHostname(), OsBuild: inv.GetOsBuild()}
}

func (r *Runner) log() *slog.Logger {
	if r.Log != nil {
		return r.Log
	}
	return slog.Default()
}

func (r *Runner) now() time.Time {
	if r.Clock != nil {
		return r.Clock()
	}
	return time.Now()
}

func (r *Runner) EnsureEnrolled(ctx context.Context, token string, hw *flv1.HardwareInfo) error {
	if r.Identity.Enrolled() {
		return nil
	}
	_, err := r.Identity.Enroll(ctx, r.ServerURL, token, hw)
	return err
}

func (r *Runner) Run(ctx context.Context) error {
	attempt := 0
	for {
		err := r.session(ctx, func() { attempt = 0 })
		if ctx.Err() != nil {
			return nil
		}
		if status.Code(err) == codes.Unauthenticated {
			r.log().Error("server rejected agent; stopping", "err", err)
			return err
		}
		d := sim.Backoff(attempt, rand.Float64)
		attempt++
		r.log().Warn("disconnected; will retry", "err", err, "in", d)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(d):
		}
	}
}

func (r *Runner) session(ctx context.Context, connected func()) error {
	l, err := r.Identity.Load()
	if err != nil {
		return err
	}
	if time.Until(l.CertNotAfter) < ca.RenewAfter {
		if err := r.Identity.Renew(ctx, r.ServerURL, l); err != nil {
			r.log().Warn("certificate renewal failed", "err", err)
		} else if l, err = r.Identity.Load(); err != nil {
			return err
		}
	}
	tlsCfg, err := l.TLSConfig()
	if err != nil {
		return err
	}
	conn, err := grpc.NewClient(r.ServerURL, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	if err != nil {
		return err
	}
	defer conn.Close()
	client := flv1.NewAgentClient(conn)
	stream, err := client.Connect(ctx)
	if err != nil {
		return err
	}
	if err := r.heartbeat(stream); err != nil {
		return err
	}
	connected()

	if r.Enforcer != nil || r.Controls != nil {
		go r.appControlLoop(ctx, client)
	}
	if r.MetricsInterval > 0 {
		go r.metricsLoop(ctx, client)
	}

	recv := make(chan *flv1.ServerMessage, 16)
	recvErr := make(chan error, 1)
	go func() {
		for {
			m, err := stream.Recv()
			if err != nil {
				recvErr <- err
				return
			}
			recv <- m
		}
	}()

	tick := time.NewTicker(r.HeartbeatInterval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			stream.Send(&flv1.AgentMessage{Body: &flv1.AgentMessage_Goodbye{Goodbye: &flv1.Goodbye{Reason: "shutdown"}}})
			stream.CloseSend()
			return ctx.Err()
		case err := <-recvErr:
			return err
		case <-tick.C:
			if err := r.heartbeat(stream); err != nil {
				return err
			}
		case <-r.refreshCh():
			if err := r.heartbeat(stream); err != nil {
				return err
			}
		case m := <-recv:
			if sc := m.GetCommand(); sc != nil {
				r.handleCommand(ctx, stream, l, sc)
			}
		}
	}
}

func (r *Runner) heartbeat(stream flv1.Agent_ConnectClient) error {
	inv := r.Inventory.Collect()
	if r.Enforcer != nil {
		inv.PolicyVersion = r.Enforcer.Status().AppliedVersion
	}
	return stream.Send(&flv1.AgentMessage{Body: &flv1.AgentMessage_Heartbeat{Heartbeat: &flv1.Heartbeat{
		Inventory: inv, SentAtUnix: r.now().Unix(),
	}}})
}

// appControlLoop pulls and applies policy, reports observed apps, and
// forwards block events until the session's context is cancelled.
func (r *Runner) appControlLoop(ctx context.Context, client flv1.AgentClient) {
	interval := r.AppControlInterval
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	r.appControlTick(ctx, client)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.appControlTick(ctx, client)
		}
	}
}

func (r *Runner) appControlTick(ctx context.Context, client flv1.AgentClient) {
	if r.Enforcer != nil {
		r.syncPolicy(ctx, client)
		r.reportObservations(ctx, client)
		r.reportBlocks(ctx, client)
	}
	r.syncControls(ctx, client)
}

func (r *Runner) syncControls(ctx context.Context, client flv1.AgentClient) {
	if r.Controls == nil {
		return
	}
	resp, err := client.GetControls(ctx, &flv1.GetControlsRequest{})
	if err != nil {
		if status.Code(err) != codes.Unavailable {
			r.log().Warn("get controls", "err", err)
		}
		return
	}
	if err := r.Controls.Apply(ctx, controls.Controls{
		USBStorageBlocked: resp.GetUsbStorageBlocked(),
		NetworkBlocked:    resp.GetNetworkBlocked(),
		ElevationBlocked:  resp.GetElevationBlocked(),
	}); err != nil {
		r.log().Error("apply controls", "err", err)
	}
}

func (r *Runner) syncPolicy(ctx context.Context, client flv1.AgentClient) {
	resp, err := client.GetPolicy(ctx, &flv1.GetPolicyRequest{})
	if err != nil {
		if status.Code(err) != codes.Unavailable {
			r.log().Warn("get policy", "err", err)
		}
		return
	}
	if resp.GetVersion() == r.Enforcer.Status().AppliedVersion {
		return
	}
	if !ed25519.Verify(r.UpdatePub, []byte(resp.GetVersion()), resp.GetSignature()) {
		r.log().Error("policy signature invalid; not applying", "version", resp.GetVersion())
		return
	}
	if err := r.Enforcer.Apply(ctx, resp.GetVersion(), resp.GetMode(), resp.GetXml()); err != nil {
		r.log().Error("apply policy", "version", resp.GetVersion(), "err", err)
		return
	}
	r.log().Info("applied policy", "version", resp.GetVersion(), "mode", resp.GetMode())
}

func (r *Runner) reportObservations(ctx context.Context, client flv1.AgentClient) {
	scanFn := r.Scan
	if scanFn == nil {
		scanFn = scan.Running
	}
	obs, err := scanFn()
	if err != nil || len(obs) == 0 {
		return
	}
	apps := make([]*flv1.ObservedApp, 0, len(obs))
	for _, o := range obs {
		apps = append(apps, &flv1.ObservedApp{Sha256: o.SHA256, Path: o.Path, Signer: o.Signer,
			SignerTbs: o.SignerTBS, SignerVerified: o.SignerVerified})
	}
	if _, err := client.Observe(ctx, &flv1.ObserveRequest{Apps: apps}); err != nil {
		r.log().Warn("report observations", "err", err)
	}
}

func (r *Runner) metricsLoop(ctx context.Context, client flv1.AgentClient) {
	collect := r.Metrics
	if collect == nil {
		collect = metrics.Collect
	}
	report := func() {
		s, err := collect()
		if err != nil {
			r.log().Warn("collect metrics", "err", err)
		} else if _, err := client.ReportMetrics(ctx, &flv1.MetricsRequest{
			CpuPct: s.CPUPct, MemPct: s.MemPct, DiskPct: s.DiskPct,
		}); err != nil {
			r.log().Warn("report metrics", "err", err)
		}
		r.reportEvents(ctx, client)
	}
	report()
	t := time.NewTicker(r.MetricsInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			report()
		}
	}
}

func (r *Runner) reportEvents(ctx context.Context, client flv1.AgentClient) {
	if r.Events == nil {
		return
	}
	evs, err := r.Events.Read()
	if err != nil || len(evs) == 0 {
		return
	}
	out := make([]*flv1.DeviceEvent, 0, len(evs))
	for _, e := range evs {
		out = append(out, &flv1.DeviceEvent{Kind: e.Kind, Summary: e.Summary, AtUnix: e.At.Unix()})
	}
	if _, err := client.ReportEvents(ctx, &flv1.EventsRequest{Events: out}); err != nil {
		r.log().Warn("report events", "err", err)
	}
}

// EnrichBlockEvents fills in publisher identity from each event's file on
// disk: the CodeIntegrity log carries only a name, and WDAC publisher rules
// need the certificate's TBS hash. Missing or unsigned files are left as they
// are, so an event is never dropped for lack of a signature.
func EnrichBlockEvents(evs []blocks.BlockEvent) []blocks.BlockEvent {
	for i := range evs {
		if evs[i].Path == "" || evs[i].SignerTBS != "" {
			continue
		}
		info, err := signature.FromFile(evs[i].Path)
		if err != nil {
			continue
		}
		evs[i].SignerTBS, evs[i].SignerVerified = info.TBSHash, info.Verified
		if evs[i].Signer == "" {
			evs[i].Signer = info.SubjectName
		}
	}
	return evs
}

func (r *Runner) reportBlocks(ctx context.Context, client flv1.AgentClient) {
	events, err := r.Enforcer.Events(ctx)
	if err != nil || len(events) == 0 {
		return
	}
	events = EnrichBlockEvents(events)
	out := make([]*flv1.BlockEvent, 0, len(events))
	for _, e := range events {
		out = append(out, &flv1.BlockEvent{
			Sha256: e.SHA256, Path: e.Path, Signer: e.Signer, Blocked: e.Blocked, AtUnix: e.At.Unix(),
			SignerTbs: e.SignerTBS, SignerVerified: e.SignerVerified,
		})
	}
	if _, err := client.ReportBlocks(ctx, &flv1.ReportBlocksRequest{Events: out}); err != nil {
		r.log().Warn("report blocks", "err", err)
	}
}

func (r *Runner) handleCommand(ctx context.Context, stream flv1.Agent_ConnectClient, l *identity.Loaded, sc *flv1.SignedCommand) {
	cmd, err := commands.Verify(l.CommandPub, sc, l.DeviceID, r.now())
	if err != nil {
		r.log().Warn("rejected command", "err", err)
		return
	}
	res := r.Executor.Run(ctx, cmd)
	if err := stream.Send(&flv1.AgentMessage{Body: &flv1.AgentMessage_CommandResult{CommandResult: res}}); err != nil {
		r.log().Warn("send command result", "err", err)
	}
}
