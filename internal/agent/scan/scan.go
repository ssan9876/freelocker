// Package scan observes the executables a device runs, for learning mode.
// It computes each binary's Authenticode SHA-256 (AuthenticodeHash) — the
// hash WDAC rules match — so observations can be promoted straight into
// hash rules. Process enumeration and signer resolution are
// platform-specific (real on Windows, empty elsewhere).
package scan

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"strings"
)

type Observed struct {
	SHA256         string
	Path           string
	Signer         string // friendly publisher name
	SignerTBS      string // signing certificate TBS hash, "" when unsigned
	SignerVerified bool   // Windows verified the signature
}

// HashFile returns the upper-case hex SHA-256 of a file's contents.
func HashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return strings.ToUpper(hex.EncodeToString(h.Sum(nil))), nil
}

// Running returns the distinct executables of currently-running processes.
// The Windows build enumerates real processes; other platforms return nil.
func Running() ([]Observed, error) { return runningImpl() }
