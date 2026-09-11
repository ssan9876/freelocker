//go:build windows

package scan

import (
	"os"
	"os/exec"
	"regexp"
	"testing"
)

var appLockerHash = regexp.MustCompile(`0x([0-9A-Fa-f]{64})`)

// powershell64 is the native Windows PowerShell. Calling it by full path
// from this (64-bit) test avoids a 32-bit shell whose System32 view is
// redirected to SysWOW64 — a different file with a different hash.
const powershell64 = `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`

// oracleHash asks Windows (AppLocker, which uses the same Authenticode
// SHA-256 as WDAC hash rules) for a file's hash. It skips only when the
// AppLocker cmdlet is not installed; any other failure fails the test.
func oracleHash(t *testing.T, path string) string {
	t.Helper()
	out, err := exec.Command(powershell64, "-NoProfile", "-Command",
		`if (-not (Get-Command Get-AppLockerFileInformation -ErrorAction SilentlyContinue)) { 'NO-APPLOCKER'; exit 0 }
		(Get-AppLockerFileInformation -Path '`+path+`').Hash.HashDataString`).CombinedOutput()
	if err != nil {
		t.Fatalf("powershell failed for %s: %v\n%s", path, err, out)
	}
	if string(out[:min(len(out), 12)]) == "NO-APPLOCKER" {
		t.Skip("Get-AppLockerFileInformation not available on this machine")
	}
	m := appLockerHash.FindSubmatch(out)
	if m == nil {
		t.Fatalf("no hash in AppLocker output for %s: %q", path, out)
	}
	return string(m[1])
}

// TestAuthenticodeHashMatchesWindows compares against Windows for a
// catalog-signed system binary, an embedded-signature binary, and an
// unsigned one (skipping any that are absent on this machine).
func TestAuthenticodeHashMatchesWindows(t *testing.T) {
	self, _ := os.Executable() // the unsigned test binary
	for _, p := range []string{
		`C:\Windows\System32\notepad.exe`,  // catalog-signed, no embedded cert
		`C:\Program Files\nodejs\node.exe`, // embedded Authenticode signature
		self,
	} {
		if _, err := os.Stat(p); err != nil {
			continue
		}
		t.Run(p, func(t *testing.T) {
			want := oracleHash(t, p)
			got, err := AuthenticodeHash(p)
			if err != nil {
				t.Fatal(err)
			}
			if got != want {
				t.Fatalf("AuthenticodeHash = %s, Windows says %s", got, want)
			}
		})
	}
}
