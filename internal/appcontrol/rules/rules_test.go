package rules

import "testing"

func TestNormalizeHash(t *testing.T) {
	lower := "ab" + repeat("cd", 31)
	r, err := Normalize(Rule{Kind: Hash, Value: lower})
	if err != nil {
		t.Fatal(err)
	}
	if r.Value != upper(lower) {
		t.Errorf("hash not upper-cased: %s", r.Value)
	}
	// idempotent
	r2, _ := Normalize(r)
	if r2 != r {
		t.Errorf("not idempotent: %+v vs %+v", r2, r)
	}
	if _, err := Normalize(Rule{Kind: Hash, Value: "tooshort"}); err == nil {
		t.Error("short hash must fail")
	}
}

func TestNormalizePath(t *testing.T) {
	for _, ok := range []string{`C:\Program Files\App\app.exe`, `C:\Windows\System32\*`, `D:\tools\`} {
		if _, err := Normalize(Rule{Kind: Path, Value: ok}); err != nil {
			t.Errorf("path %q should be valid: %v", ok, err)
		}
	}
	for _, bad := range []string{"", `relative\path`, `\\server\share`, `C:`} {
		if _, err := Normalize(Rule{Kind: Path, Value: bad}); err == nil {
			t.Errorf("path %q should be invalid", bad)
		}
	}
}

func TestNormalizePublisherAndUnknown(t *testing.T) {
	if _, err := Normalize(Rule{Kind: Publisher, Value: repeat("aa", 32), PublisherName: "Acme Corp"}); err != nil {
		t.Errorf("valid publisher rejected: %v", err)
	}
	if _, err := Normalize(Rule{Kind: "bogus", Value: "x"}); err == nil {
		t.Error("unknown kind must fail")
	}
}

func repeat(s string, n int) string {
	out := ""
	for i := 0; i < n; i++ {
		out += s
	}
	return out
}
func upper(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'a' && b[i] <= 'z' {
			b[i] -= 32
		}
	}
	return string(b)
}
