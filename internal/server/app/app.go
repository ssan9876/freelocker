// Package app wires the server components together and owns their
// lifecycle.
package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"freelocker/internal/server/agentapi"
	"freelocker/internal/server/auth"
	"freelocker/internal/server/bootstrap"
	"freelocker/internal/server/commands"
	"freelocker/internal/server/config"
	"freelocker/internal/server/httpapi"
	"freelocker/internal/server/alerting"
	"freelocker/internal/server/hub"
	"freelocker/internal/server/keys"
	"freelocker/internal/server/policysvc"
	"freelocker/internal/server/store"
	"freelocker/internal/server/tokens"
	"freelocker/internal/server/webui"

	"github.com/google/uuid"
	"google.golang.org/grpc"
)

type App struct {
	cfg       config.Config
	store     *store.Store
	ownsStore bool
	master    []byte
	log       *slog.Logger
	hub       *hub.Hub
	handler   http.Handler

	setupMu   sync.Mutex
	mu        sync.Mutex
	rt        *httpapi.Runtime
	agentSrv  *grpc.Server
	agentAddr net.Addr
}

func New(ctx context.Context, cfg config.Config, log *slog.Logger) (*App, error) {
	s, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return nil, err
	}
	if err := s.Migrate(ctx); err != nil {
		s.Close()
		return nil, err
	}
	master, err := keys.LoadOrCreateMasterSecret(cfg.MasterSecretFile)
	if err != nil {
		s.Close()
		return nil, err
	}
	a, err := NewWithStore(cfg, s, master, log)
	if err != nil {
		s.Close()
		return nil, err
	}
	a.ownsStore = true
	return a, nil
}

func NewWithStore(cfg config.Config, s *store.Store, master []byte, log *slog.Logger) (*App, error) {
	totpSealer, err := keys.NewSealer(master, "totp")
	if err != nil {
		return nil, err
	}
	a := &App{cfg: cfg, store: s, master: master, log: log, hub: hub.New()}
	api := &httpapi.API{
		Store: s, Runtime: a.runtime, Setup: a.setup, Hub: a.hub, TOTPSealer: totpSealer,
		Sessions: &auth.Sessions{Store: s, Secure: !cfg.InsecureCookies}, ReleaseDir: cfg.ReleaseDir, Log: log,
	}
	apiHandler := api.Handler()

	// The API owns /api and /agent; everything else is the embedded SPA
	// (when a console build is present).
	mux := http.NewServeMux()
	mux.Handle("/api/", apiHandler)
	mux.Handle("/agent/", apiHandler)
	if webui.Enabled() {
		mux.Handle("/", webui.Handler())
	} else {
		mux.Handle("/", apiHandler)
		if log != nil {
			log.Info("console UI not embedded; serving API only")
		}
	}
	a.handler = mux
	return a, nil
}

func (a *App) runtime() *httpapi.Runtime {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.rt
}

func (a *App) Handler() http.Handler { return a.handler }

func (a *App) AgentAddr() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.agentAddr == nil {
		return ""
	}
	return a.agentAddr.String()
}

func (a *App) Initialize(ctx context.Context, org, email, password string) (*bootstrap.Keys, error) {
	if strings.TrimSpace(org) == "" || !strings.Contains(email, "@") {
		return nil, errors.New("organization name and a valid email are required")
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		return nil, err
	}
	if _, err := bootstrap.Init(ctx, a.store, a.master, org, time.Now()); err != nil {
		return nil, err
	}
	k, err := bootstrap.Load(ctx, a.store, a.master)
	if err != nil {
		return nil, err
	}
	if _, err := a.store.CreateAdmin(ctx, k.TenantID, store.Admin{Email: email, PasswordHash: hash, Role: "owner"}); err != nil {
		return nil, err
	}
	if err := a.store.AppendAudit(ctx, k.TenantID, store.AuditEntry{
		Actor: "system", Action: "setup.complete", Detail: map[string]any{"org": org, "owner": email}, Result: "success",
	}); err != nil {
		a.log.Error("audit write failed", "err", err)
	}
	return k, nil
}

func (a *App) CreateAdmin(ctx context.Context, email, password, role string) error {
	if !slices.Contains(auth.Roles, role) {
		return fmt.Errorf("role must be one of %v", auth.Roles)
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		return err
	}
	tenant, err := a.store.FirstTenant(ctx)
	if err != nil {
		return fmt.Errorf("server not initialized: %w", err)
	}
	id, err := a.store.CreateAdmin(ctx, tenant, store.Admin{Email: email, PasswordHash: hash, Role: role})
	if err != nil {
		return err
	}
	return a.store.AppendAudit(ctx, tenant, store.AuditEntry{
		Actor: "system", Action: "admin.create", TargetType: "admin", TargetID: id.String(),
		Detail: map[string]any{"email": email, "role": role, "via": "cli"}, Result: "success",
	})
}

// TokenForTests creates an unlimited install token. Intended for tests
// and manual bring-up; requires the server to be initialized.
func (a *App) TokenForTests(ctx context.Context) (string, error) {
	rt := a.runtime()
	if rt == nil {
		return "", errors.New("not initialized")
	}
	full, hash, err := tokens.Generate(rt.Keys.CA.Pin())
	if err != nil {
		return "", err
	}
	if _, err := a.store.CreateInstallToken(ctx, rt.Keys.TenantID, store.InstallToken{Name: "bring-up"}, hash); err != nil {
		return "", err
	}
	return full, nil
}

// ActivateForTests starts the agent API and runtime for an already
// Initialize-d server, without serving the console. Tests that need a
// live agent endpoint call this instead of Run.
func (a *App) ActivateForTests(ctx context.Context) error {
	k, err := bootstrap.Load(ctx, a.store, a.master)
	if err != nil {
		return err
	}
	return a.activate(k)
}

// KeysForTest returns the loaded server keys (tests only).
func (a *App) KeysForTest() *bootstrap.Keys {
	rt := a.runtime()
	if rt == nil {
		return nil
	}
	return rt.Keys
}

// Store exposes the underlying store (tests and CLI recovery).
func (a *App) Store() *store.Store { return a.store }

// Hub exposes the connection hub (tests).
func (a *App) Hub() *hub.Hub { return a.hub }

// Tenant returns the initialized tenant id (tests).
func (a *App) Tenant() (uuid.UUID, bool) {
	rt := a.runtime()
	if rt == nil {
		return uuid.Nil, false
	}
	return rt.Keys.TenantID, true
}

func (a *App) setup(ctx context.Context, org, email, password string) error {
	a.setupMu.Lock()
	defer a.setupMu.Unlock()
	k, err := a.Initialize(ctx, org, email, password)
	if err != nil {
		return err
	}
	return a.activate(k)
}

func (a *App) activate(k *bootstrap.Keys) error {
	cmds := &commands.Service{Store: a.store, Keys: k, Hub: a.hub, Log: a.log}
	policy := &policysvc.Service{Store: a.store, Keys: k}
	// Rebuild every policy with the current compiler so devices never keep
	// a version compiled by an older one. Failure is logged, not fatal: the
	// existing versions stay, and the next admin edit recompiles anyway.
	if n, err := policy.RecompileAll(context.Background(), k.TenantID); err != nil {
		a.log.Error("recompile policies at startup", "err", err)
	} else if n > 0 {
		a.log.Info("recompiled policies", "count", n)
	}
	alerts := alerting.New(a.store)
	tlsCfg, err := agentapi.TLSConfig(k, a.cfg.PublicHostnames, time.Now())
	if err != nil {
		return err
	}
	lis, err := net.Listen("tcp", a.cfg.AgentListen)
	if err != nil {
		return fmt.Errorf("agent listener: %w", err)
	}
	srv := agentapi.NewGRPCServer(agentapi.Deps{Store: a.store, Keys: k, Hub: a.hub, Commands: cmds, Policy: policy, Alerting: alerts, Log: a.log}, tlsCfg)
	go func() {
		if err := srv.Serve(lis); err != nil {
			a.log.Error("agent API stopped", "err", err)
		}
	}()
	a.mu.Lock()
	a.rt = &httpapi.Runtime{Keys: k, Commands: cmds, Policy: policy}
	a.agentSrv, a.agentAddr = srv, lis.Addr()
	a.mu.Unlock()
	a.log.Info("agent API listening", "addr", lis.Addr().String(), "ca_pin", k.CA.Pin())
	return nil
}

func (a *App) Run(ctx context.Context) error {
	k, err := bootstrap.Load(ctx, a.store, a.master)
	switch {
	case err == nil:
		if err := a.activate(k); err != nil {
			return err
		}
	case errors.Is(err, store.ErrNotFound):
		a.log.Warn("server not initialized; complete setup in the console or run `freelocker-server init`")
	default:
		return err
	}

	httpSrv := &http.Server{Addr: a.cfg.ConsoleListen, Handler: a.handler, ReadHeaderTimeout: 10 * time.Second}
	errc := make(chan error, 1)
	go func() {
		var err error
		if a.cfg.ConsoleTLSCert != "" {
			err = httpSrv.ListenAndServeTLS(a.cfg.ConsoleTLSCert, a.cfg.ConsoleTLSKey)
		} else {
			err = httpSrv.ListenAndServe()
		}
		if !errors.Is(err, http.ErrServerClosed) {
			errc <- err
		}
	}()
	a.log.Info("console API listening", "addr", a.cfg.ConsoleListen, "tls", a.cfg.ConsoleTLSCert != "")

	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			return httpSrv.Shutdown(shutdownCtx)
		case err := <-errc:
			return err
		case <-ticker.C:
			if rt := a.runtime(); rt != nil {
				if n, err := rt.Commands.ExpireStale(ctx); err != nil {
					a.log.Error("expire commands", "err", err)
				} else if n > 0 {
					a.log.Info("expired stale commands", "count", n)
				}
			}
			// Housekeeping: drop login failures older than the rate-limit window.
			if _, err := a.store.PruneLoginFailures(ctx, time.Now().Add(-15*time.Minute)); err != nil {
				a.log.Error("prune login failures", "err", err)
			}
		}
	}
}

// Close stops the agent API (long-lived streams are cut, agents
// reconnect to the next instance) and closes the store if owned.
func (a *App) Close() {
	a.mu.Lock()
	srv := a.agentSrv
	a.agentSrv, a.agentAddr = nil, nil
	a.mu.Unlock()
	if srv != nil {
		srv.Stop()
	}
	if a.ownsStore {
		a.store.Close()
	}
}
