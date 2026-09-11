//go:build windows

package service

import (
	"context"

	"freelocker/internal/agent/runner"

	"golang.org/x/sys/windows/svc"
)

const Name = "FreeLockerAgent"

type handler struct {
	runner *runner.Runner
}

// Run runs as a Windows service if launched by the SCM, else in console mode.
func Run(ctx context.Context, r *runner.Runner) error {
	isService, err := svc.IsWindowsService()
	if err != nil {
		return err
	}
	if !isService {
		return r.Run(ctx)
	}
	return svc.Run(Name, &handler{runner: r})
}

func (h *handler) Execute(args []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown
	status <- svc.Status{State: svc.StartPending}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { h.runner.Run(ctx); close(done) }()
	status <- svc.Status{State: svc.Running, Accepts: accepted}

	for {
		select {
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
				<-done
				return false, 0
			}
		case <-done:
			return false, 0
		}
	}
}
