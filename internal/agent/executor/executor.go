// Package executor runs signed server commands on the agent.
package executor

import (
	"context"
	"log/slog"
	"sync"

	flv1 "freelocker/gen/freelocker/v1"
)

type Actions interface {
	RefreshInventory(ctx context.Context) error
	RotateCertificate(ctx context.Context) error
	Uninstall(ctx context.Context) error
	UpdateAgent(ctx context.Context, cmd *flv1.Command) error
}

type Executor struct {
	Actions Actions
	Log     *slog.Logger

	mu   sync.Mutex
	seen map[string]*flv1.CommandResult
}

func (e *Executor) log() *slog.Logger {
	if e.Log != nil {
		return e.Log
	}
	return slog.Default()
}

func (e *Executor) Run(ctx context.Context, cmd *flv1.Command) *flv1.CommandResult {
	e.mu.Lock()
	if e.seen == nil {
		e.seen = map[string]*flv1.CommandResult{}
	}
	if prev, ok := e.seen[cmd.GetId()]; ok {
		e.mu.Unlock()
		return prev
	}
	e.mu.Unlock()

	res := e.dispatch(ctx, cmd)
	res.CommandId = cmd.GetId()

	e.mu.Lock()
	e.seen[cmd.GetId()] = res
	e.mu.Unlock()
	return res
}

func (e *Executor) dispatch(ctx context.Context, cmd *flv1.Command) *flv1.CommandResult {
	var err error
	switch cmd.GetType() {
	case flv1.CommandType_COMMAND_TYPE_PING:
		return ok("pong")
	case flv1.CommandType_COMMAND_TYPE_REFRESH_INVENTORY:
		err = e.Actions.RefreshInventory(ctx)
	case flv1.CommandType_COMMAND_TYPE_ROTATE_CERTIFICATE:
		err = e.Actions.RotateCertificate(ctx)
	case flv1.CommandType_COMMAND_TYPE_UNINSTALL:
		err = e.Actions.Uninstall(ctx)
	case flv1.CommandType_COMMAND_TYPE_UPDATE_AGENT:
		err = e.Actions.UpdateAgent(ctx, cmd)
	default:
		return fail("unsupported command")
	}
	if err != nil {
		e.log().Warn("command failed", "id", cmd.GetId(), "type", cmd.GetType().String(), "err", err)
		return fail(err.Error())
	}
	return ok("done")
}

func ok(msg string) *flv1.CommandResult   { return &flv1.CommandResult{Success: true, Message: msg} }
func fail(msg string) *flv1.CommandResult { return &flv1.CommandResult{Success: false, Message: msg} }
