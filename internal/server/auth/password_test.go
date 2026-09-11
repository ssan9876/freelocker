package auth

import (
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

func TestPasswordHashing(t *testing.T) {
	if _, err := HashPassword("short"); err == nil {
		t.Error("short password must be rejected")
	}
	h, err := HashPassword("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if !CheckPassword(h, "correct horse battery") || CheckPassword(h, "wrong password!!") {
		t.Error("CheckPassword wrong")
	}
	if CheckPasswordOrDummy(nil, "anything at all") {
		t.Error("missing user must never authenticate")
	}
	if !CheckPasswordOrDummy(&h, "correct horse battery") {
		t.Error("existing user with right password must authenticate")
	}
}

func TestTOTP(t *testing.T) {
	secret, url, err := NewTOTPSecret("bob@example.com")
	if err != nil || !strings.HasPrefix(url, "otpauth://totp/") {
		t.Fatalf("NewTOTPSecret = %q, %v", url, err)
	}
	now := time.Now()
	code, _ := totp.GenerateCode(secret, now)
	if !ValidateTOTP(secret, code, now) {
		t.Error("current code must validate")
	}
	if ValidateTOTP(secret, code, now.Add(5*time.Minute)) {
		t.Error("code from 5 minutes ago must not validate")
	}
}

func TestAllows(t *testing.T) {
	cases := []struct {
		role, required string
		want           bool
	}{
		{"owner", "admin", true}, {"admin", "admin", true}, {"readonly", "admin", false},
		{"admin", "owner", false}, {"readonly", "readonly", true}, {"bogus", "readonly", false},
	}
	for _, c := range cases {
		if got := Allows(c.role, c.required); got != c.want {
			t.Errorf("Allows(%s, %s) = %v", c.role, c.required, got)
		}
	}
}
