package executor

import (
	"context"
	"errors"
	"testing"

	flv1 "freelocker/gen/freelocker/v1"
)

type fakeActions struct {
	refresh, rotate, uninstall, update int
	updateErr                          error
}

func (f *fakeActions) RefreshInventory(context.Context) error  { f.refresh++; return nil }
func (f *fakeActions) RotateCertificate(context.Context) error { f.rotate++; return nil }
func (f *fakeActions) Uninstall(context.Context) error         { f.uninstall++; return nil }
func (f *fakeActions) UpdateAgent(context.Context, *flv1.Command) error {
	f.update++
	return f.updateErr
}

func cmd(id string, t flv1.CommandType) *flv1.Command { return &flv1.Command{Id: id, Type: t} }

func TestDispatchAndResults(t *testing.T) {
	fa := &fakeActions{}
	e := &Executor{Actions: fa}
	ctx := context.Background()

	if r := e.Run(ctx, cmd("c1", flv1.CommandType_COMMAND_TYPE_PING)); !r.GetSuccess() || r.GetCommandId() != "c1" {
		t.Fatalf("ping = %+v", r)
	}
	e.Run(ctx, cmd("c2", flv1.CommandType_COMMAND_TYPE_REFRESH_INVENTORY))
	e.Run(ctx, cmd("c3", flv1.CommandType_COMMAND_TYPE_ROTATE_CERTIFICATE))
	if fa.refresh != 1 || fa.rotate != 1 {
		t.Fatalf("actions = %+v", fa)
	}
	if r := e.Run(ctx, cmd("c9", flv1.CommandType_COMMAND_TYPE_UNSPECIFIED)); r.GetSuccess() {
		t.Error("unspecified must fail")
	}
}

func TestDedupeReturnsFirstResult(t *testing.T) {
	fa := &fakeActions{updateErr: errors.New("nope")}
	e := &Executor{Actions: fa}
	ctx := context.Background()
	first := e.Run(ctx, cmd("dup", flv1.CommandType_COMMAND_TYPE_UPDATE_AGENT))
	second := e.Run(ctx, cmd("dup", flv1.CommandType_COMMAND_TYPE_UPDATE_AGENT))
	if fa.update != 1 {
		t.Errorf("action ran %d times, want 1", fa.update)
	}
	if first.GetSuccess() || second.GetSuccess() || second.GetMessage() != first.GetMessage() {
		t.Errorf("dedupe should replay first failure: %+v %+v", first, second)
	}
}
