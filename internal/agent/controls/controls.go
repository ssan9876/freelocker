// Package controls applies device/behavior controls on the endpoint:
// USB mass-storage, network access, and elevation. The Windows enforcer
// makes reversible registry/firewall changes; other platforms use a
// no-op. Default is allow — a control blocks only when explicitly set.
//
// SAFETY: network blocking always keeps an allow-exception for the
// FreeLocker server so the agent can never cut its own management link.
package controls

import "context"

type Controls struct {
	USBStorageBlocked bool
	NetworkBlocked    bool
	ElevationBlocked  bool
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
