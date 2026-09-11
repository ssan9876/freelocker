package scan

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHashFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "f.bin")
	content := []byte("freelocker application control")
	if err := os.WriteFile(p, content, 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := HashFile(p)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	want := strings.ToUpper(hex.EncodeToString(sum[:]))
	if got != want {
		t.Fatalf("HashFile = %s, want %s", got, want)
	}
}

func TestHashFileMissing(t *testing.T) {
	if _, err := HashFile(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Error("missing file must error")
	}
}
