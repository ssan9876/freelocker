//go:build !windows

package signature

// verify is Windows-only; elsewhere a signature is never treated as verified.
func verify(string) bool { return false }
