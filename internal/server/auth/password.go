// Package auth holds console authentication primitives: passwords, TOTP,
// sessions, and role checks.
package auth

import (
	"fmt"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

const (
	MinPasswordLen = 12
	bcryptCost     = 12
)

// dummyHash lets login spend bcrypt time even for unknown users.
var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("freelocker-dummy-password"), bcryptCost)

func HashPassword(pw string) (string, error) {
	if len(pw) < MinPasswordLen {
		return "", fmt.Errorf("password must be at least %d characters", MinPasswordLen)
	}
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcryptCost)
	return string(h), err
}

func CheckPassword(hash, pw string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(pw)) == nil
}

func CheckPasswordOrDummy(hash *string, pw string) bool {
	if hash == nil {
		bcrypt.CompareHashAndPassword(dummyHash, []byte(pw))
		return false
	}
	return CheckPassword(*hash, pw)
}

func NewTOTPSecret(email string) (secret, otpauthURL string, err error) {
	k, err := totp.Generate(totp.GenerateOpts{Issuer: "FreeLocker", AccountName: email})
	if err != nil {
		return "", "", err
	}
	return k.Secret(), k.URL(), nil
}

func ValidateTOTP(secret, code string, now time.Time) bool {
	ok, err := totp.ValidateCustom(code, secret, now, totp.ValidateOpts{
		Period: 30, Skew: 1, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
	})
	return err == nil && ok
}

var Roles = []string{"owner", "admin", "readonly"}

var roleRank = map[string]int{"readonly": 1, "admin": 2, "owner": 3}

func Allows(role, required string) bool {
	r, ok := roleRank[role]
	return ok && r >= roleRank[required]
}
