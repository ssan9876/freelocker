package hub

import (
	"context"
	"errors"
	"testing"

	flv1 "freelocker/gen/freelocker/v1"

	"github.com/google/uuid"
)

func TestRegisterSendReplaceDisconnect(t *testing.T) {
	h := New()
	id := uuid.New()
	if h.Send(id, &flv1.ServerMessage{}) || h.Connected(id) {
		t.Fatal("unknown device must not be connected")
	}

	ctx1, cancel1 := context.WithCancelCause(context.Background())
	c1 := h.Register(id, cancel1)
	if !h.Connected(id) || !h.Send(id, &flv1.ServerMessage{}) || len(c1.Send) != 1 {
		t.Fatal("send to registered conn failed")
	}

	ctx2, cancel2 := context.WithCancelCause(context.Background())
	c2 := h.Register(id, cancel2)
	if !errors.Is(context.Cause(ctx1), ErrReplaced) {
		t.Errorf("old conn cause = %v, want ErrReplaced", context.Cause(ctx1))
	}
	h.Unregister(id, c1) // stale unregister must not remove the new conn
	if !h.Connected(id) {
		t.Fatal("stale Unregister removed the new connection")
	}

	boom := errors.New("revoked")
	h.Disconnect(id, boom)
	if !errors.Is(context.Cause(ctx2), boom) {
		t.Errorf("cause = %v", context.Cause(ctx2))
	}
	h.Unregister(id, c2)
	if h.Connected(id) {
		t.Error("still connected after Unregister")
	}
}
