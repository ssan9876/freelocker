// Package keys protects server secrets at rest using keys derived from a
// single master secret held outside the database.
package keys

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
)

const masterLen = 32

func LoadOrCreateMasterSecret(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err == nil {
		if len(b) < masterLen {
			return nil, fmt.Errorf("master secret %s is shorter than %d bytes", path, masterLen)
		}
		return b, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	b = make([]byte, masterLen)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return nil, fmt.Errorf("write master secret: %w", err)
	}
	return b, nil
}

func Derive(master []byte, purpose string) ([]byte, error) {
	if len(master) < masterLen {
		return nil, fmt.Errorf("master secret must be at least %d bytes", masterLen)
	}
	return hkdf.Key(sha256.New, master, nil, purpose, 32)
}

type Sealer struct {
	aead cipher.AEAD
}

func NewSealer(master []byte, purpose string) (*Sealer, error) {
	k, err := Derive(master, purpose)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Sealer{aead: aead}, nil
}

// Seal returns nonce || ciphertext.
func (s *Sealer) Seal(plain []byte) []byte {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		panic(err) // crypto/rand never fails on supported platforms
	}
	return s.aead.Seal(nonce, nonce, plain, nil)
}

func (s *Sealer) Open(sealed []byte) ([]byte, error) {
	n := s.aead.NonceSize()
	if len(sealed) < n {
		return nil, errors.New("sealed value too short")
	}
	return s.aead.Open(nil, sealed[:n], sealed[n:], nil)
}
