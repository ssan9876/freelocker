package updater

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDownloadVerifiesHash(t *testing.T) {
	payload := []byte("new-agent-binary")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(payload) }))
	defer srv.Close()
	sum := sha256.Sum256(payload)

	got, err := Download(context.Background(), srv.URL, sum[:])
	if err != nil || string(got) != string(payload) {
		t.Fatalf("Download = %q, %v", got, err)
	}
	if _, err := Download(context.Background(), srv.URL, make([]byte, 32)); err == nil {
		t.Error("hash mismatch must fail")
	}
}

func TestVerifySignature(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sum := sha256.Sum256([]byte("x"))
	sig := ed25519.Sign(priv, sum[:])
	if err := Verify(pub, sum[:], sig); err != nil {
		t.Fatalf("valid sig rejected: %v", err)
	}
	if err := Verify(pub, sum[:], []byte("bad")); err == nil {
		t.Error("bad sig must fail")
	}
}

func TestStageWritesExecutable(t *testing.T) {
	p, err := Stage(t.TempDir(), []byte("bin"))
	if err != nil {
		t.Fatal(err)
	}
	if p == "" {
		t.Fatal("empty staged path")
	}
}
