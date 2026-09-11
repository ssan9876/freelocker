// Package runner is the agent's main control loop: enroll, connect,
// heartbeat, obey commands, renew, and reconnect.
package runner

import (
	"context"
	"log/slog"
	"math/rand/v2"
	"time"

	flv1 "freelocker/gen/freelocker/v1"
	"freelocker/internal/agent/executor"
	"freelocker/internal/agent/identity"
	"freelocker/internal/agent/inventory"
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
	stream, err := flv1.NewAgentClient(conn).Connect(ctx)
	if err != nil {
		return err
	}
	if err := r.heartbeat(stream); err != nil {
		return err
	}
	connected()

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
		case m := <-recv:
			if sc := m.GetCommand(); sc != nil {
				r.handleCommand(ctx, stream, l, sc)
			}
		}
	}
}

func (r *Runner) heartbeat(stream flv1.Agent_ConnectClient) error {
	return stream.Send(&flv1.AgentMessage{Body: &flv1.AgentMessage_Heartbeat{Heartbeat: &flv1.Heartbeat{
		Inventory: r.Inventory.Collect(), SentAtUnix: r.now().Unix(),
	}}})
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
