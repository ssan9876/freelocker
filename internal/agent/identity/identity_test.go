package identity_test

import (
	"bytes"
	"context"
	"log/slog"
	"testing"
	"time"

	flv1 "freelocker/gen/freelocker/v1"
	"freelocker/internal/agent/agentpaths"
	"freelocker/internal/agent/identity"
	"freelocker/internal/agent/secret"
	"freelocker/internal/server/app"
	"freelocker/internal/server/config"
	"freelocker/internal/server/store/storetest"

	"github.com/google/uuid"
)

func startServer(t *testing.T) (addr, token string) {
	t.Helper()
	cfg := config.Config{AgentListen: "127.0.0.1:0", PublicHostnames: []string{"127.0.0.1"}, InsecureCookies: true}
	a, err := app.NewWithStore(cfg, storetest.New(t), bytes.Repeat([]byte{6}, 32), slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	if _, err := a.Initialize(context.Background(), "Acme", "o@example.com", "owner-password-123"); err != nil {
		t.Fatal(err)
	}
	if err := a.ActivateForTests(context.Background()); err != nil {
		t.Fatal(err)
	}
	tok, err := a.TokenForTests(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return a.AgentAddr(), tok
}

func paths(t *testing.T) agentpaths.Paths {
	d := t.TempDir()
	return agentpaths.Paths{InstallDir: d, DataDir: d}
}

func TestEnrollLoadRenew(t *testing.T) {
	ctx := context.Background()
	addr, token := startServer(t)
	st := &identity.Store{Paths: paths(t), Protector: secret.Default()}

	if st.Enrolled() {
		t.Fatal("should not be enrolled yet")
	}
	enr, err := st.Enroll(ctx, addr, token, &flv1.HardwareInfo{Hostname: "pc-1", OsBuild: "26100"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := uuid.Parse(enr.DeviceID); err != nil {
		t.Fatalf("device id = %q", enr.DeviceID)
	}
	if !st.Enrolled() {
		t.Fatal("should be enrolled after Enroll")
	}

	l, err := st.Load()
	if err != nil || l.DeviceID != enr.DeviceID || len(l.CommandPub) != 32 {
		t.Fatalf("Load = %+v, %v", l, err)
	}
	if time.Until(l.CertNotAfter) < 80*24*time.Hour {
		t.Errorf("cert expiry too soon: %v", l.CertNotAfter)
	}
	if _, err := l.TLSConfig(); err != nil {
		t.Fatalf("TLSConfig: %v", err)
	}

	oldNotAfter := l.CertNotAfter
	if err := st.Renew(ctx, addr, l); err != nil {
		t.Fatal(err)
	}
	l2, _ := st.Load()
	if !l2.CertNotAfter.After(oldNotAfter.Add(-time.Second)) {
		t.Errorf("renew did not extend expiry: %v -> %v", oldNotAfter, l2.CertNotAfter)
	}
}
