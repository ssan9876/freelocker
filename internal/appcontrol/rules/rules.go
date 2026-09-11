// Package rules defines application-control allow rules and their
// validation and normalization, independent of storage or WDAC output.
package rules

import (
	"fmt"
	"regexp"
	"strings"
)

type Kind string

const (
	Hash      Kind = "hash"      // SHA-256 of a file (64 hex chars)
	Publisher Kind = "publisher" // code-signing certificate TBS hash (64 hex chars)
	Path      Kind = "path"      // Windows path, optional trailing \*
)

type Rule struct {
	Kind          Kind
	Value         string
	PublisherName string // optional friendly name for publisher rules
	Description   string
}

var (
	hex64   = regexp.MustCompile(`^[0-9A-F]{64}$`)
	winPath = regexp.MustCompile(`^[A-Za-z]:\\[^<>:"|?\n]*$`)
)

// Normalize validates a rule and returns a canonical copy: hashes and TBS
// values upper-cased, paths trimmed. It is idempotent.
func Normalize(r Rule) (Rule, error) {
	r.Value = strings.TrimSpace(r.Value)
	r.PublisherName = strings.TrimSpace(r.PublisherName)
	r.Description = strings.TrimSpace(r.Description)
	switch r.Kind {
	case Hash, Publisher:
		r.Value = strings.ToUpper(r.Value)
		if !hex64.MatchString(r.Value) {
			return Rule{}, fmt.Errorf("%s value must be 64 hex characters", r.Kind)
		}
	case Path:
		// Allow a single trailing \* wildcard; validate the rest as a path.
		base := strings.TrimSuffix(r.Value, `\*`)
		if base == "" || !winPath.MatchString(base) {
			return Rule{}, fmt.Errorf("path must be an absolute Windows path (optionally ending in \\*)")
		}
	default:
		return Rule{}, fmt.Errorf("unknown rule kind %q", r.Kind)
	}
	return r, nil
}
