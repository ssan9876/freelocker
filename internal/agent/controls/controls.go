// Package controls applies device/behavior controls on the endpoint. v1
// covers USB mass-storage. The Windows enforcer toggles the USBSTOR
// service; other platforms use a no-op. Default is allow — a control
// blocks only when explicitly set.
package controls

import "context"

type Controls struct {
	USBStorageBlocked bool
}

type Enforcer interface {
	Apply(ctx context.Context, c Controls) error
	Last() Controls
}

// NoopEnforcer records the last applied controls without changing the host.
type NoopEnforcer struct{ last Controls }

func (n *NoopEnforcer) Apply(_ context.Context, c Controls) error {
	n.last = c
	return nil
}
func (n *NoopEnforcer) Last() Controls { return n.last }
