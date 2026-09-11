package wdac

import (
	"bytes"
	"strings"
	"testing"

	"freelocker/internal/appcontrol/rules"
)

func hashRule(v string) rules.Rule { return rules.Rule{Kind: rules.Hash, Value: v} }

func TestAuditModeToggle(t *testing.T) {
	audit, _ := Compile(Policy{Mode: "audit", Rules: []rules.Rule{hashRule(hex64("a"))}})
	enforce, _ := Compile(Policy{Mode: "enforce", Rules: []rules.Rule{hashRule(hex64("a"))}})
	if !bytes.Contains(audit, []byte("Enabled:Audit Mode")) {
		t.Error("audit policy must contain the audit-mode option")
	}
	if bytes.Contains(enforce, []byte("Enabled:Audit Mode")) {
		t.Error("enforce policy must NOT contain the audit-mode option")
	}
}

func TestHashesUpperCasedAndPresentOnce(t *testing.T) {
	xml, err := Compile(Policy{Mode: "audit", Rules: []rules.Rule{hashRule(strings.ToLower(hex64("b")))}})
	if err != nil {
		t.Fatal(err)
	}
	up := hex64("b")
	if c := strings.Count(string(xml), up); c != 1 {
		t.Errorf("hash appears %d times, want 1 (upper-cased)", c)
	}
}

func TestDeterministicRegardlessOfOrder(t *testing.T) {
	a := []rules.Rule{hashRule(hex64("1")), hashRule(hex64("2")), {Kind: rules.Path, Value: `C:\a\*`}}
	b := []rules.Rule{{Kind: rules.Path, Value: `C:\a\*`}, hashRule(hex64("2")), hashRule(hex64("1"))}
	xa, _ := Compile(Policy{Mode: "audit", Rules: a})
	xb, _ := Compile(Policy{Mode: "audit", Rules: b})
	if !bytes.Equal(xa, xb) {
		t.Error("compilation must be independent of input order")
	}
	if ContentHash(xa) != ContentHash(xb) {
		t.Error("content hash must match for equal rule sets")
	}
}

func TestEmptyPolicyIsValidSkeleton(t *testing.T) {
	xml, err := Compile(Policy{Mode: "enforce"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"<SiPolicy", "<FileRules>", "<SigningScenarios>", "</SiPolicy>"} {
		if !strings.Contains(string(xml), want) {
			t.Errorf("skeleton missing %q", want)
		}
	}
}

func TestCompilePropagatesRuleErrors(t *testing.T) {
	if _, err := Compile(Policy{Rules: []rules.Rule{{Kind: rules.Hash, Value: "bad"}}}); err == nil {
		t.Error("invalid rule should fail compilation")
	}
}

// hex64 returns a 64-char hex string seeded by c.
func hex64(c string) string {
	return strings.ToUpper(strings.Repeat(c, 64)[:64])
}
