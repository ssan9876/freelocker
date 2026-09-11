// Package enforcer applies application-control policy on the endpoint. The
// WDAC implementation is Windows-only; a NoopEnforcer is used off-Windows
// and in tests. Enforcement defaults to audit mode; enforce mode requires
// an explicit opt-in so a policy can never silently lock a machine.
package enforcer

import (
	"context"
	"errors"

	"freelocker/internal/agent/blocks"
)

type Status struct {
	AppliedVersion string
	AppliedMode    string
}

type Enforcer interface {
	// Apply installs the given WDAC policy XML in the given mode
	// ("audit" or "enforce"). It must be idempotent for an unchanged
	// version.
	Apply(ctx context.Context, version, mode string, xml []byte) error
	// Events returns block/audit events observed since the last call.
	Events(ctx context.Context) ([]blocks.BlockEvent, error)
	Status() Status
}

var ErrBadMode = errors.New("mode must be audit or enforce")

// NoopEnforcer records what would be applied but changes nothing on the
// host. Used off-Windows and in tests.
type NoopEnforcer struct {
	status Status
}

func (n *NoopEnforcer) Apply(_ context.Context, version, mode string, _ []byte) error {
	if mode != "audit" && mode != "enforce" {
		return ErrBadMode
	}
	n.status = Status{AppliedVersion: version, AppliedMode: mode}
	return nil
}

func (n *NoopEnforcer) Events(context.Context) ([]blocks.BlockEvent, error) { return nil, nil }
func (n *NoopEnforcer) Status() Status                                      { return n.status }
