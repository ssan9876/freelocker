//go:build windows

package motw

import (
	"os"
	"path/filepath"
	"testing"
)

// Reading a real alternate data stream is the part that cannot be proven by
// parsing a byte slice: the ":Zone.Identifier" path form, the missing-stream
// error shape, and the fact that Go's os.Open handles ADS at all.
//
// Everything here happens inside t.TempDir(), so it writes nothing outside
// the test and needs no VM.
func TestReadRealAlternateDataStream(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "setup.exe")
	if err := os.WriteFile(path, []byte("MZ not really a binary"), 0o600); err != nil {
		t.Fatal(err)
	}

	// A file with no mark: the normal state of anything Windows installed.
	got, err := Read(path)
	if err != nil {
		t.Fatalf("Read on an unmarked file = %v, want nil — a missing stream is not an error", err)
	}
	if got.Present || got.Downloaded() {
		t.Fatalf("unmarked file reported %+v, want a zero Info", got)
	}

	// Now attach a mark exactly as a browser would.
	mark := "[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://example.com/setup.exe\r\n"
	if err := os.WriteFile(path+streamName, []byte(mark), 0o600); err != nil {
		t.Skipf("cannot create an alternate data stream here (non-NTFS temp dir?): %v", err)
	}

	got, err = Read(path)
	if err != nil {
		t.Fatalf("Read on a marked file = %v", err)
	}
	if !got.Present {
		t.Fatal("the mark was written but Read reported no stream")
	}
	if !got.Downloaded() {
		t.Errorf("got %+v, want Downloaded", got)
	}
	if got.Source() != "https://example.com/setup.exe" {
		t.Errorf("Source() = %q", got.Source())
	}
}

// A path that does not exist must not be reported as an unmarked file —
// that would silently turn a broken scan into "nothing was downloaded".
func TestReadMissingFile(t *testing.T) {
	got, err := Read(filepath.Join(t.TempDir(), "does-not-exist.exe"))
	if err != nil {
		// Acceptable: the file genuinely is not there.
		return
	}
	if got.Present {
		t.Errorf("missing file reported a mark: %+v", got)
	}
}
