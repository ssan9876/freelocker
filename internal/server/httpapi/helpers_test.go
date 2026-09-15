package httpapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"freelocker/internal/server/auth"
	"freelocker/internal/server/bootstrap"
	"freelocker/internal/server/commands"
	"freelocker/internal/server/config"
	"freelocker/internal/server/httpapi"
	"freelocker/internal/server/hub"
	"freelocker/internal/server/keys"
	"freelocker/internal/server/keyset"
	"freelocker/internal/server/notify"
	"freelocker/internal/server/policysvc"
	"freelocker/internal/server/rollout"
	"freelocker/internal/server/store"
	"freelocker/internal/server/store/storetest"

	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
)

type env struct {
	srv    *httptest.Server
	store  *store.Store
	hub    *hub.Hub
	master []byte
	rt     func() *httpapi.Runtime
}

const ownerEmail, ownerPass = "owner@example.com", "owner-password-123"

// newEnv starts an uninitialized API. The Setup func mirrors what the app
// does in Task 14 (init + owner + runtime).
func newEnv(t *testing.T) *env {
	t.Helper()
	s := storetest.New(t)
	master := bytes.Repeat([]byte{3}, 32)
	sealer, _ := keys.NewSealer(master, "totp")
	notifySealer, _ := keys.NewSealer(master, "notify")
	h := hub.New()
	var mu sync.Mutex
	var rt *httpapi.Runtime
	e := &env{store: s, hub: h, master: master}
	e.rt = func() *httpapi.Runtime { mu.Lock(); defer mu.Unlock(); return rt }

	api := &httpapi.API{
		Store: s, Hub: h, TOTPSealer: sealer, NotifySealer: notifySealer, SMTPConfigured: false,
		Sessions: &auth.Sessions{Store: s}, Runtime: e.rt, ReleaseDir: t.TempDir(),
		ReleaseURL: func(tid uuid.UUID, v string) string {
			return "http://test.local/agent/releases/" + tid.String() + "/" + v
		},
		KeyFor: keyset.New(s, master).For,
		Setup: func(ctx context.Context, org, email, pw string) error {
			if _, err := bootstrap.Init(ctx, s, master, org, time.Now()); err != nil {
				return err
			}
			k, err := bootstrap.Load(ctx, s, master)
			if err != nil {
				return err
			}
			hash, err := auth.HashPassword(pw)
			if err != nil {
				return err
			}
			// The setup owner is the provider, mirroring app.Initialize.
			if _, err := s.CreateAdmin(ctx, k.TenantID, store.Admin{Email: email, PasswordHash: hash, Role: "owner", Provider: true}); err != nil {
				return err
			}
			mu.Lock()
			cmds := &commands.Service{Store: s, Keys: k, Hub: h}
			rt = &httpapi.Runtime{
				Keys:     k,
				Commands: cmds,
				Policy:   &policysvc.Service{Store: s, Keys: k},
				Rollouts: &rollout.Service{Store: s, Commands: cmds, Online: h.Connected, ReleaseURL: func(tid uuid.UUID, v string) string {
					return "http://test.local/agent/releases/" + tid.String() + "/" + v
				}},
				Notify: notify.New(s, notifySealer, config.SMTP{}, nil),
			}
			mu.Unlock()
			return nil
		},
		ProvisionTenant: func(ctx context.Context, org, ownerEmail, ownerPass string) (uuid.UUID, error) {
			tid, err := bootstrap.ProvisionTenant(ctx, s, master, org, time.Now())
			if err != nil {
				return uuid.Nil, err
			}
			hash, err := auth.HashPassword(ownerPass)
			if err != nil {
				return uuid.Nil, err
			}
			if _, err := s.CreateAdmin(ctx, tid, store.Admin{Email: ownerEmail, PasswordHash: hash, Role: "owner"}); err != nil {
				return uuid.Nil, err
			}
			return tid, nil
		},
	}
	e.srv = httptest.NewServer(api.Handler())
	t.Cleanup(e.srv.Close)
	return e
}

type client struct {
	t    *testing.T
	base string
	http *http.Client
	csrf string
}

func (e *env) client(t *testing.T) *client {
	jar, _ := cookiejar.New(nil)
	return &client{t: t, base: e.srv.URL, http: &http.Client{Jar: jar}}
}

// do sends JSON and decodes a JSON response into out (if non-nil).
func (c *client) do(method, path string, body, out any) int {
	c.t.Helper()
	var buf []byte
	if body != nil {
		buf, _ = json.Marshal(body)
	}
	req, _ := http.NewRequest(method, c.base+path, bytes.NewReader(buf))
	req.Header.Set("Content-Type", "application/json")
	if c.csrf != "" {
		req.Header.Set("X-CSRF-Token", c.csrf)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	if out != nil {
		json.NewDecoder(resp.Body).Decode(out)
	}
	return resp.StatusCode
}

// loginFull performs password login and TOTP enrollment/verification.
// It returns the TOTP secret so later logins can reuse it.
func (c *client) loginFull(email, pw, secret string) string {
	c.t.Helper()
	var lr struct {
		CSRF        string `json:"csrf_token"`
		MFAEnrolled bool   `json:"mfa_enrolled"`
	}
	if code := c.do("POST", "/api/login", map[string]string{"email": email, "password": pw}, &lr); code != 200 {
		c.t.Fatalf("login = %d", code)
	}
	c.csrf = lr.CSRF
	if !lr.MFAEnrolled {
		var ms struct {
			Secret string `json:"secret"`
		}
		if code := c.do("POST", "/api/mfa/setup", nil, &ms); code != 200 {
			c.t.Fatalf("mfa setup = %d", code)
		}
		secret = ms.Secret
	}
	code, _ := totp.GenerateCode(secret, time.Now())
	if st := c.do("POST", "/api/mfa/verify", map[string]string{"code": code}, nil); st != 204 {
		c.t.Fatalf("mfa verify = %d", st)
	}
	return secret
}

// initialized runs setup and returns a fully logged-in owner client.
func (e *env) initialized(t *testing.T) *client {
	t.Helper()
	c := e.client(t)
	if code := c.do("POST", "/api/setup", map[string]string{"org_name": "Acme", "email": ownerEmail, "password": ownerPass}, nil); code != 201 {
		t.Fatalf("setup = %d", code)
	}
	c.loginFull(ownerEmail, ownerPass, "")
	return c
}
