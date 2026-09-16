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
	"strings"
	"time"
)

// RulePrefix names every firewall rule this package owns, so reconcile can
// enumerate exactly ours and never touch a rule an admin added by hand.
const RulePrefix = "FreeLocker-RF-"

// CuratedASRRules is the fixed set of ASR rule GUIDs FreeLocker manages,
// mirroring asrRules in internal/server/httpapi/ringfences.go (the agent
// cannot import the server package, so the set is duplicated here). Keys are
// upper-case GUIDs.
//
// This is the authority for what the enforcer is ever allowed to delete from
// the Defender machine-policy ASR key: an endpoint's ASR rules may also be
// managed by GPO or Intune in the same registry key, and deleting a value
// this product never wrote would silently strip that unrelated
// configuration. See StaleASRValues.
var CuratedASRRules = map[string]bool{
	"D4F940AB-401B-4EFC-AADC-AD5F3C50688A": true,
	"3B576869-A4EC-4529-8536-B80A7769E899": true,
	"D3E037E1-3EB8-44C8-A917-57927947596D": true,
	"5BEB7EFE-FD9A-4556-801D-275E5FFC04CC": true,
	"92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B": true,
	"D1E49AAC-8F56-4280-B9BA-993A6D77406C": true,
}

// StaleASRValues returns the subset of `present` (value names currently in
// the Defender ASR policy key) that this package is both allowed to delete
// (member of CuratedASRRules) and no longer wants (absent from `want`, whose
// keys must be upper-case GUIDs). Comparison against CuratedASRRules and
// `want` is case-insensitive on `present` since GUIDs may be stored in
// either case; the values returned are exactly as they appear in `present`,
// so the caller can delete them by that name.
//
// This is deliberately pure and platform-independent so the deletion
// boundary can be unit-tested without touching the Windows registry.
func StaleASRValues(present []string, want map[string]string) []string {
	var stale []string
	for _, n := range present {
		u := strings.ToUpper(n)
		if !CuratedASRRules[u] {
			continue // never ours to delete: GPO/Intune or unrelated
		}
		if _, ok := want[u]; !ok {
			stale = append(stale, n)
		}
	}
	return stale
}

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
