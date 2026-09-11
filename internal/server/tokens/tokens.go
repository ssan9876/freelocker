// Package tokens creates and parses install tokens of the form
// "<secret>.<ca-pin>". Only SHA-256(secret) is ever stored.
package tokens

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
)

func Generate(caPin string) (full string, hash []byte, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", nil, err
	}
	secret := base64.RawURLEncoding.EncodeToString(b)
	return secret + "." + caPin, Hash(secret), nil
}

func Parse(full string) (secret, caPin string, err error) {
	parts := strings.Split(full, ".")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", errors.New("malformed install token")
	}
	return parts[0], parts[1], nil
}

func Hash(secret string) []byte {
	sum := sha256.Sum256([]byte(secret))
	return sum[:]
}
