package app

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"freelocker/internal/server/config"
	"freelocker/internal/server/store/storetest"
)

func testConfig() config.Config {
	return config.Config{AgentListen: "127.0.0.1:0", ConsoleListen: "127.0.0.1:0",
		PublicHostnames: []string{"127.0.0.1"}, InsecureCookies: true}
}

func TestSetupActivatesAgentAPIAndRunReactivates(t *testing.T) {
	s := storetest.New(t)
	master := bytes.Repeat([]byte{4}, 32)

	a, err := NewWithStore(testConfig(), s, master, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	if a.AgentAddr() != "" {
		t.Fatal("agent API must not listen before setup")
	}
	srv := httptest.NewServer(a.Handler())
	defer srv.Close()
	resp, err := http.Post(srv.URL+"/api/setup", "application/json",
		strings.NewReader(`{"org_name":"Acme","email":"o@example.com","password":"owner-password-123"}`))
	if err != nil || resp.StatusCode != 201 {
		t.Fatalf("setup = %v %v", resp.StatusCode, err)
	}
	if a.AgentAddr() == "" {
		t.Fatal("agent API should listen after setup")
	}
	a.Close()

	// A restarted server with the same DB + master secret activates in Run.
	b, err := NewWithStore(testConfig(), s, master, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Close)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- b.Run(ctx) }()
	deadline := time.Now().Add(5 * time.Second)
	for b.AgentAddr() == "" && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if b.AgentAddr() == "" {
		t.Fatal("Run did not activate the agent API")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run returned %v", err)
	}
}

func TestInitializeValidatesInput(t *testing.T) {
	a, _ := NewWithStore(testConfig(), storetest.New(t), bytes.Repeat([]byte{4}, 32), slog.Default())
	t.Cleanup(a.Close)
	if _, err := a.Initialize(context.Background(), "", "o@example.com", "owner-password-123"); err == nil {
		t.Error("empty org must fail")
	}
	if _, err := a.Initialize(context.Background(), "Acme", "o@example.com", "short"); err == nil {
		t.Error("short password must fail")
	}
	if _, err := a.Initialize(context.Background(), "Acme", "o@example.com", "owner-password-123"); err != nil {
		t.Fatal(err)
	}
	if err := a.CreateAdmin(context.Background(), "r@example.com", "recovery-password-1", "owner"); err != nil {
		t.Fatal(err)
	}
	if err := a.CreateAdmin(context.Background(), "x@example.com", "recovery-password-1", "god"); err == nil {
		t.Error("bad role must fail")
	}
}

// TestHealthRoutesThroughMux guards against the mux shadowing /healthz and
// /readyz with the SPA fallback (they must reach the API handler).
func TestHealthRoutesThroughMux(t *testing.T) {
	s := storetest.New(t)
	a, err := NewWithStore(testConfig(), s, bytes.Repeat([]byte{7}, 32), slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	srv := httptest.NewServer(a.Handler())
	defer srv.Close()

	for _, path := range []string{"/healthz", "/readyz"} {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		ct := resp.Header.Get("Content-Type")
		resp.Body.Close()
		if resp.StatusCode != 200 || !strings.HasPrefix(ct, "application/json") {
			t.Errorf("%s = %d %q, want 200 application/json (not the SPA)", path, resp.StatusCode, ct)
		}
	}
}
