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

// Every policy — including the empty default — must carry Microsoft's
// DefaultWindows baseline so Windows itself is never blocked.
func TestWindowsBaselineAlwaysPresent(t *testing.T) {
	for _, p := range []Policy{
		{Mode: "audit"},
		{Mode: "enforce", Rules: []rules.Rule{hashRule(hex64("c"))}},
	} {
		xml, err := Compile(p)
		if err != nil {
			t.Fatal(err)
		}
		s := string(xml)
		for _, want := range []string{
			`<EKU ID="ID_EKU_WINDOWS" Value="010A2B0601040182370A0306" />`,
			`<CertRoot Type="Wellknown" Value="06" />`, // Microsoft Product Root 2010
			`<CertEKU ID="ID_EKU_WINDOWS" />`,
			`<SigningScenario Value="131" ID="ID_SIGNINGSCENARIO_KMCI"`,
			`<SigningScenario Value="12" ID="ID_SIGNINGSCENARIO_UMCI"`,
			`<AllowedSigner SignerId="ID_SIGNER_WINDOWS_PRODUCTION" />`,
			`<AllowedSigner SignerId="ID_SIGNER_WINDOWS_PRODUCTION_USER" />`,
			`Enabled:Update Policy No Reboot`,
			`Enabled:Revoked Expired As Unsigned`,
		} {
			if !strings.Contains(s, want) {
				t.Errorf("mode %s: baseline missing %q", p.Mode, want)
			}
		}
		for _, unwanted := range []string{
			`Enabled:Advanced Boot Options Menu`,
			`Value="0A"`, // Microsoft test root
			`Enabled:Allow Supplemental Policies`,
		} {
			if strings.Contains(s, unwanted) {
				t.Errorf("mode %s: must not contain %q", p.Mode, unwanted)
			}
		}
	}
}

// Admin publisher rules apply to user-mode code only; kernel mode stays
// limited to the Microsoft baseline.
func TestPublisherRulesAreUserModeOnly(t *testing.T) {
	xml, err := Compile(Policy{Rules: []rules.Rule{{Kind: rules.Publisher, Value: hex64("d"), PublisherName: "Acme"}}})
	if err != nil {
		t.Fatal(err)
	}
	s := string(xml)
	k, u := strings.Index(s, `ID="ID_SIGNINGSCENARIO_KMCI"`), strings.Index(s, `ID="ID_SIGNINGSCENARIO_UMCI"`)
	if k < 0 || u < 0 || k > u {
		t.Fatalf("want a kernel-mode scenario followed by a user-mode one (kmci at %d, umci at %d)", k, u)
	}
	kmci, umci := s[k:u], s[u:]
	if !strings.Contains(umci, `SignerId="ID_SIGNER_P_0"`) {
		t.Error("publisher rule must be allowed in user mode")
	}
	if strings.Contains(kmci, `SignerId="ID_SIGNER_P_0"`) {
		t.Error("publisher rule must not be allowed in kernel mode")
	}
}

// hex64 returns a 64-char hex string seeded by c.
func hex64(c string) string {
	return strings.ToUpper(strings.Repeat(c, 64)[:64])
}
