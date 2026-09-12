package signature

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTBSHashMatchesManualSHA256(t *testing.T) {
	leafC, _, _ := chain(t, x509.ECDSAWithSHA256)
	got, err := TBSHash(leafC)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(leafC.RawTBSCertificate)
	want := strings.ToUpper(hex.EncodeToString(sum[:]))
	if got != want {
		t.Fatalf("TBSHash = %s, want %s", got, want)
	}
	if len(got) != 64 {
		t.Errorf("SHA-256 TBS hash must be 64 hex chars, got %d", len(got))
	}
}

func TestTBSHashFollowsCertificateAlgorithm(t *testing.T) {
	leafC, _, _ := chain(t, x509.ECDSAWithSHA384)
	got, err := TBSHash(leafC)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 96 {
		t.Fatalf("SHA-384-signed cert should hash to 96 hex chars, got %d (%s)", len(got), got)
	}
}

func TestLeafPicksNonIssuer(t *testing.T) {
	leafC, mid, root := chain(t, x509.ECDSAWithSHA256)
	for _, order := range [][]*x509.Certificate{
		{leafC, mid, root}, {root, mid, leafC}, {mid, root, leafC},
	} {
		if got := leaf(order); got == nil || got.Subject.CommonName != "Contoso Ltd" {
			t.Fatalf("leaf = %v, want Contoso Ltd", got)
		}
	}
}

func TestFromFileReadsEmbeddedCertificate(t *testing.T) {
	leafC, mid, root := chain(t, x509.ECDSAWithSHA256)
	path := signedPE(t, []*x509.Certificate{leafC, mid, root})

	info, err := FromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := TBSHash(leafC)
	if info.TBSHash != want {
		t.Errorf("TBSHash = %q, want %q", info.TBSHash, want)
	}
	if info.SubjectName != "Contoso Ltd" || info.Issuer != "Test Intermediate" {
		t.Errorf("names = %q / %q", info.SubjectName, info.Issuer)
	}
	if info.Verified {
		t.Error("portable parsing must not claim the signature is verified")
	}
}

func TestFromFileUnsignedAndBroken(t *testing.T) {
	// A PE with no certificate table: unsigned, no error.
	path := signedPE(t, nil)
	info, err := FromFile(path)
	if err != nil || info.TBSHash != "" {
		t.Errorf("empty cert table = %+v, %v; want zero Info and nil error", info, err)
	}
	// Not a PE at all: an error, not a panic.
	junk := filepath.Join(t.TempDir(), "junk.exe")
	os.WriteFile(junk, []byte("not a PE file at all"), 0o600)
	if _, err := FromFile(junk); err == nil {
		t.Error("non-PE file should error")
	}
	if _, err := FromFile(filepath.Join(t.TempDir(), "missing.exe")); err == nil {
		t.Error("missing file should error")
	}
}
