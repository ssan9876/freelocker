// Package integration exercises the full server through its public
// console API and the agent gRPC protocol.
package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"testing"
	"time"

	flv1 "freelocker/gen/freelocker/v1"
	"freelocker/internal/server/app"
	"freelocker/internal/server/config"
	"freelocker/internal/server/store/storetest"
	"freelocker/internal/sim"

	"github.com/pquerna/otp/totp"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type console struct {
	t    *testing.T
	base string
	c    *http.Client
	csrf string
}

func (k *console) do(method, path string, body, out any) int {
	k.t.Helper()
	var b []byte
	if body != nil {
		b, _ = json.Marshal(body)
	}
	req, _ := http.NewRequest(method, k.base+path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", k.csrf)
	resp, err := k.c.Do(req)
	if err != nil {
		k.t.Fatal(err)
	}
	defer resp.Body.Close()
	if out != nil {
		json.NewDecoder(resp.Body).Decode(out)
	}
	return resp.StatusCode
}

func eventually(t *testing.T, what string, timeout time.Duration, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(timeout); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestEndToEnd(t *testing.T) {
	ctx := context.Background()
	cfg := config.Config{AgentListen: "127.0.0.1:0", PublicHostnames: []string{"127.0.0.1"}, InsecureCookies: true}
	a, err := app.NewWithStore(cfg, storetest.New(t), bytes.Repeat([]byte{5}, 32), slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	srv := httptest.NewServer(a.Handler())
	defer srv.Close()
	jar, _ := cookiejar.New(nil)
	k := &console{t: t, base: srv.URL, c: &http.Client{Jar: jar}}

	// 1. First-run setup, login, TOTP enrollment.
	if code := k.do("POST", "/api/setup", map[string]string{"org_name": "Acme", "email": "owner@example.com", "password": "owner-password-123"}, nil); code != 201 {
		t.Fatalf("setup = %d", code)
	}
	var lr struct {
		CSRF string `json:"csrf_token"`
	}
	k.do("POST", "/api/login", map[string]string{"email": "owner@example.com", "password": "owner-password-123"}, &lr)
	k.csrf = lr.CSRF
	var ms struct{ Secret string }
	k.do("POST", "/api/mfa/setup", nil, &ms)
	code, _ := totp.GenerateCode(ms.Secret, time.Now())
	if st := k.do("POST", "/api/mfa/verify", map[string]string{"code": code}, nil); st != 204 {
		t.Fatalf("mfa verify = %d", st)
	}

	// 2. Create an install token and enroll a simulated agent with it.
	var tok struct{ Token string }
	if st := k.do("POST", "/api/tokens", map[string]any{"name": "e2e", "max_uses": 5}, &tok); st != 201 {
		t.Fatalf("create token = %d", st)
	}
	id, err := sim.Enroll(ctx, a.AgentAddr(), tok.Token, &flv1.HardwareInfo{Hostname: "e2e-pc", OsBuild: "26100"})
	if err != nil {
		t.Fatal(err)
	}
	runCtx, stopRunner := context.WithCancel(ctx)
	defer stopRunner()
	runErr := make(chan error, 1)
	go func() {
		runErr <- (&sim.Runner{Addr: a.AgentAddr(), Identity: id, Hostname: "e2e-pc", Interval: 200 * time.Millisecond}).Run(runCtx)
	}()

	// 3. Device shows online (spec target: within 60 s; locally well under 5 s).
	eventually(t, "device online", 5*time.Second, func() bool {
		var devs []struct{ Hostname, Status string }
		k.do("GET", "/api/devices", nil, &devs)
		return len(devs) == 1 && devs[0].Hostname == "e2e-pc" && devs[0].Status == "online"
	})

	// 4. Issue a command; the sim verifies its signature and acknowledges it.
	var cmd struct{ ID string }
	if st := k.do("POST", "/api/devices/"+id.DeviceID+"/commands", map[string]string{"type": "ping"}, &cmd); st != 201 {
		t.Fatalf("issue = %d", st)
	}
	eventually(t, "command succeeded", 5*time.Second, func() bool {
		var cmds []struct{ ID, State string }
		k.do("GET", "/api/devices/"+id.DeviceID+"/commands", nil, &cmds)
		return len(cmds) == 1 && cmds[0].ID == cmd.ID && cmds[0].State == "succeeded"
	})

	// 5. Revoke: the live stream is cut and the agent stops retrying.
	if st := k.do("POST", "/api/devices/"+id.DeviceID+"/revoke", nil, nil); st != 204 {
		t.Fatalf("revoke = %d", st)
	}
	select {
	case err := <-runErr:
		if status.Code(err) != codes.Unauthenticated {
			t.Fatalf("runner ended with %v, want Unauthenticated", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("runner did not stop after revoke")
	}

	// 6. Every step is in the audit log.
	var audit []struct{ Action string }
	k.do("GET", "/api/audit?limit=100", nil, &audit)
	seen := map[string]bool{}
	for _, e := range audit {
		seen[e.Action] = true
	}
	for _, want := range []string{"setup.complete", "admin.login", "token.create", "device.enroll", "command.issue", "command.result", "device.revoke"} {
		if !seen[want] {
			t.Errorf("audit log missing %q; have %v", want, seen)
		}
	}
}
