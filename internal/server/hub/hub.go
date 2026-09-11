// Package hub tracks the live stream for each connected agent so other
// parts of the server can push messages to it or cut it off.
package hub

import (
	"context"
	"errors"
	"sync"

	flv1 "freelocker/gen/freelocker/v1"

	"github.com/google/uuid"
)

var ErrReplaced = errors.New("replaced by a newer connection from the same device")

const sendBuffer = 64

type Conn struct {
	Send   chan *flv1.ServerMessage
	cancel context.CancelCauseFunc
}

type Hub struct {
	mu    sync.Mutex
	conns map[uuid.UUID]*Conn
}

func New() *Hub { return &Hub{conns: map[uuid.UUID]*Conn{}} }

// Register adds a connection, cancelling any previous one for the device.
func (h *Hub) Register(id uuid.UUID, cancel context.CancelCauseFunc) *Conn {
	c := &Conn{Send: make(chan *flv1.ServerMessage, sendBuffer), cancel: cancel}
	h.mu.Lock()
	old := h.conns[id]
	h.conns[id] = c
	h.mu.Unlock()
	if old != nil {
		old.cancel(ErrReplaced)
	}
	return c
}

func (h *Hub) Unregister(id uuid.UUID, c *Conn) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.conns[id] == c {
		delete(h.conns, id)
	}
}

// Send is non-blocking; it reports false if the device is not connected
// or its buffer is full (the message stays pending in the database).
func (h *Hub) Send(id uuid.UUID, m *flv1.ServerMessage) bool {
	h.mu.Lock()
	c := h.conns[id]
	h.mu.Unlock()
	if c == nil {
		return false
	}
	select {
	case c.Send <- m:
		return true
	default:
		return false
	}
}

func (h *Hub) Disconnect(id uuid.UUID, cause error) {
	h.mu.Lock()
	c := h.conns[id]
	h.mu.Unlock()
	if c != nil {
		c.cancel(cause)
	}
}

func (h *Hub) Connected(id uuid.UUID) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.conns[id] != nil
}
