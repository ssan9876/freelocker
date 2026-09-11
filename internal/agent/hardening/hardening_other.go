//go:build !windows

package hardening

func SecureDataDir(dir string) error        { return nil }
func ConfigureRecovery(service string) error { return nil }
