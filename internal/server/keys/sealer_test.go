package keys

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestSealerRoundtripAndPurposeIsolation(t *testing.T) {
	master := bytes.Repeat([]byte{7}, 32)
	a, err := NewSealer(master, "server-keys")
	if err != nil {
		t.Fatal(err)
	}
	sealed := a.Seal([]byte("secret"))
	got, err := a.Open(sealed)
	if err != nil || string(got) != "secret" {
		t.Fatalf("Open = %q, %v", got, err)
	}
	b, _ := NewSealer(master, "other-purpose")
	if _, err := b.Open(sealed); err == nil {
		t.Fatal("different purpose must not decrypt")
	}
	sealed[len(sealed)-1] ^= 1
	if _, err := a.Open(sealed); err == nil {
		t.Fatal("tampered ciphertext must fail")
	}
}

func TestNewSealerRejectsShortMaster(t *testing.T) {
	if _, err := NewSealer(make([]byte, 16), "x"); err == nil {
		t.Fatal("expected error for 16-byte master")
	}
}

func TestLoadOrCreateMasterSecret(t *testing.T) {
	p := filepath.Join(t.TempDir(), "master.key")
	first, err := LoadOrCreateMasterSecret(p)
	if err != nil || len(first) != 32 {
		t.Fatalf("create: len=%d err=%v", len(first), err)
	}
	second, err := LoadOrCreateMasterSecret(p)
	if err != nil || !bytes.Equal(first, second) {
		t.Fatal("second load must return same secret")
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatal(err)
	}
}
