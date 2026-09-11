package tokens

import (
	"bytes"
	"strings"
	"testing"
)

func TestGenerateParseHash(t *testing.T) {
	pin := strings.Repeat("ab", 16)
	full, hash, err := Generate(pin)
	if err != nil {
		t.Fatal(err)
	}
	secret, gotPin, err := Parse(full)
	if err != nil {
		t.Fatal(err)
	}
	if gotPin != pin {
		t.Errorf("pin = %q", gotPin)
	}
	if len(secret) != 43 { // 32 bytes, base64url no padding
		t.Errorf("secret len = %d", len(secret))
	}
	if !bytes.Equal(Hash(secret), hash) {
		t.Error("Hash(secret) must equal hash from Generate")
	}
	other, _, _ := Generate(pin)
	if other == full {
		t.Error("tokens must be unique")
	}
}

func TestParseRejectsMalformed(t *testing.T) {
	for _, s := range []string{"", "nodot", "a.b.c", ".pin", "secret."} {
		if _, _, err := Parse(s); err == nil {
			t.Errorf("Parse(%q) should fail", s)
		}
	}
}
