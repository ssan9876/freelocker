package sim

import (
	"context"
	"log/slog"
	"math/rand/v2"
	"time"

	flv1 "freelocker/gen/freelocker/v1"
	"freelocker/internal/server/commands"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Runner struct {
	Addr     string
	Identity *Identity
	Hostname string
	Interval time.Duration
	Log      *slog.Logger
}

func (r *Runner) Run(ctx context.Context) error {
	if r.Log == nil {
		r.Log = slog.Default()
	}
	started := time.Now()
	attempt := 0
	for {
		err := r.session(ctx, started, func() { attempt = 0 })
		if ctx.Err() != nil {
			return nil
		}
		if status.Code(err) == codes.Unauthenticated {
			r.Log.Error("server rejected device; stopping", "device", r.Identity.DeviceID, "err", err)
			return err
		}
		d := Backoff(attempt, rand.Float64)
		attempt++
		r.Log.Warn("disconnected; will retry", "device", r.Identity.DeviceID, "err", err, "in", d)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(d):
		}
	}
}

func (r *Runner) session(ctx context.Context, started time.Time, connected func()) error {
	sess, err := Connect(ctx, r.Addr, r.Identity)
	if err != nil {
		return err
	}
	defer sess.Close()
	heartbeat := func() error {
		return sess.Heartbeat(&flv1.Inventory{
			Hostname: r.Hostname, OsBuild: "sim", AgentVersion: "sim-0.1", IpAddresses: []string{"127.0.0.1"},
			LoggedOnUser: `SIM\user`, UptimeSeconds: int64(time.Since(started).Seconds()),
		})
	}
	if err := heartbeat(); err != nil {
		return err
	}
	connected()
	tick := time.NewTicker(r.Interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			sess.Goodbye("shutdown")
			return ctx.Err()
		case err := <-sess.Done():
			return err
		case sc, ok := <-sess.Commands():
			if !ok {
				return <-sess.Done()
			}
			cmd, err := commands.Verify(r.Identity.CommandPub, sc, r.Identity.DeviceID, time.Now())
			if err != nil {
				r.Log.Warn("rejected command", "err", err)
				continue
			}
			if err := sess.SendResult(&flv1.CommandResult{CommandId: cmd.GetId(), Success: true,
				Message: "sim handled " + commands.TypeName(cmd.GetType())}); err != nil {
				return err
			}
		case <-tick.C:
			if err := heartbeat(); err != nil {
				return err
			}
		}
	}
}
