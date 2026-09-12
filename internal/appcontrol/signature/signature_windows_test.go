//go:build windows

package signature

import (
	"os"
	"path/filepath"
	"testing"
)

// TestFromFileVerifiesSystemBinary reads a Microsoft-signed system binary.
// Read-only and safe on a dev box. Skips when the file has no embedded
// signature (some builds ship catalog-signed binaries only).
func TestFromFileVerifiesSystemBinary(t *testing.T) {
	const path = `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
	info, err := FromFile(path)
	if err != nil {
		t.Fatalf("FromFile(%s): %v", path, err)
	}
	if info.TBSHash == "" {
		t.Skip("no embedded signature (catalog-signed); nothing to verify here")
	}
	if !info.Verified {
		t.Errorf("%s should verify as trusted; got Verified=false (TBS %s, subject %q)", path, info.TBSHash, info.SubjectName)
	}
	if info.SubjectName == "" {
		t.Error("signed binary should report a subject name")
	}
}

func TestVerifyRejectsUnsignedFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "plain.exe")
	if err := os.WriteFile(p, []byte("MZ not really a binary"), 0o600); err != nil {
		t.Fatal(err)
	}
	if verify(p) {
		t.Error("unsigned file must not verify")
	}
}
