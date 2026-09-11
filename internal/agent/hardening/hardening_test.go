package hardening

import "testing"

func TestSecureDataDirOnTempDir(t *testing.T) {
	// On non-Windows this is a no-op; on Windows it invokes icacls on a
	// real temp dir. Either way it must succeed and not panic.
	if err := SecureDataDir(t.TempDir()); err != nil {
		t.Errorf("SecureDataDir: %v", err)
	}
}
