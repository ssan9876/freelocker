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

	// Downloaded reports a Mark-of-the-Web from outside the machine's trust
	// boundary. It is a provenance hint, not a security boundary: a user can
	// strip the mark from a file they own, so its presence is meaningful and
	// its absence is unproven.
	Downloaded bool
	// DownloadSource is the origin URL the mark carried, when it carried one.
	DownloadSource string
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
