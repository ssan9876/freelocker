package bootstrap

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"freelocker/internal/server/store/storetest"

	"github.com/google/uuid"
)

func TestInitThenLoad(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	master := bytes.Repeat([]byte{1}, 32)

	tenant, err := Init(ctx, s, master, "Acme", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Init(ctx, s, master, "Acme", time.Now()); !errors.Is(err, ErrAlreadyInitialized) {
		t.Fatalf("second Init err = %v, want ErrAlreadyInitialized", err)
	}

	k, err := Load(ctx, s, master)
	if err != nil {
		t.Fatal(err)
	}
	if k.TenantID != tenant || !k.CA.Cert.IsCA {
		t.Fatalf("keys = %+v", k)
	}
	msg := []byte("hello")
	if !ed25519.Verify(k.CommandKey.Public().(ed25519.PublicKey), msg, ed25519.Sign(k.CommandKey, msg)) {
		t.Error("command key unusable")
	}
	if bytes.Equal(k.CommandKey, k.UpdateKey) {
		t.Error("command and update keys must differ")
	}

	dev := uuid.New()
	code := k.UninstallCode(dev)
	if len(code) != 16 || code != k.UninstallCode(dev) || code == k.UninstallCode(uuid.New()) {
		t.Errorf("uninstall code %q not stable/unique", code)
	}
	sum := sha256.Sum256([]byte(code))
	if !bytes.Equal(k.UninstallCodeHash(dev), sum[:]) {
		t.Error("UninstallCodeHash mismatch")
	}

	if _, err := Load(ctx, s, bytes.Repeat([]byte{2}, 32)); err == nil {
		t.Error("Load with wrong master secret must fail")
	}
}
