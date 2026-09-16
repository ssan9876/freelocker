// Package ringfence constrains what an allowed application may do: per-program
// outbound network containment and Defender ASR child-process protections.
// The Windows enforcer makes reversible firewall and registry changes; other
// platforms use a no-op.
//
// SAFETY: the enforcer refuses to ringfence the agent's own image or the
// updater, so a ringfence can never sever the management link.
package ringfence

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// RulePrefix names every firewall rule this package owns, so reconcile can
// enumerate exactly ours and never touch a rule an admin added by hand.
const RulePrefix = "FreeLocker-RF-"

type Program struct {
	Path           string
	NetworkBlocked bool
}

type Protection struct {
	ASRRule string
	Action  string // audit|block
}

type Ringfence struct {
	Version     string // content hash; "" means nothing assigned
	Mode        string // audit|enforce
	Programs    []Program
	Protections []Protection
}

type Violation struct {
	Kind     string // network|child_process
	Program  string
	Detail   string
	Enforced bool
	At       time.Time
}

type Status struct {
	Applied      string // version last applied
	ASRAvailable bool   // Defender is active, so ASR values actually bite
}

type Enforcer interface {
	Apply(ctx context.Context, r Ringfence) error
	Violations(ctx context.Context) ([]Violation, error)
	Status() Status
}

// RuleName is the deterministic firewall rule name for a program path.
func RuleName(path string) string {
	sum := sha256.Sum256([]byte(path))
	return RulePrefix + hex.EncodeToString(sum[:])[:16]
}

// Diff compares the firewall rules already present (names starting with
// RulePrefix) against the programs that should have one, returning what to
// add and what to remove. Only network-blocked programs get a rule.
func Diff(existing []string, desired map[string]Program) (add []Program, remove []string) {
	have := make(map[string]bool, len(existing))
	for _, n := range existing {
		have[n] = true
	}
	for name, p := range desired {
		if p.NetworkBlocked && !have[name] {
			add = append(add, p)
		}
	}
	for _, n := range existing {
		p, ok := desired[n]
		if !ok || !p.NetworkBlocked {
			remove = append(remove, n)
		}
	}
	return add, remove
}

// NoopEnforcer records what would be applied without changing the host.
type NoopEnforcer struct{ status Status }

func (n *NoopEnforcer) Apply(_ context.Context, r Ringfence) error {
	n.status = Status{Applied: r.Version}
	return nil
}
func (n *NoopEnforcer) Violations(context.Context) ([]Violation, error) { return nil, nil }
func (n *NoopEnforcer) Status() Status                                  { return n.status }
