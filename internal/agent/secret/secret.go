// Package secret protects the agent's private key at rest. On Windows it
// uses DPAPI machine scope; elsewhere a non-encrypting file protector is
// used only so the surrounding logic is testable off-Windows.
package secret

type Protector interface {
	Protect(plain []byte) ([]byte, error)
	Unprotect(sealed []byte) ([]byte, error)
}

// FileProtector performs no encryption. NOT for production key storage.
type FileProtector struct{}

func (FileProtector) Protect(plain []byte) ([]byte, error)    { return append([]byte(nil), plain...), nil }
func (FileProtector) Unprotect(sealed []byte) ([]byte, error) { return append([]byte(nil), sealed...), nil }
