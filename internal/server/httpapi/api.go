// Package httpapi is the console's REST/JSON API.
package httpapi

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"freelocker/internal/server/auth"
	"freelocker/internal/server/bootstrap"
	"freelocker/internal/server/commands"
	"freelocker/internal/server/hub"
	"freelocker/internal/server/keys"
	"freelocker/internal/server/store"

	"github.com/go-chi/chi/v5"
)

type Runtime struct {
	Keys     *bootstrap.Keys
	Commands *commands.Service
}

type API struct {
	Store      *store.Store
	Runtime    func() *Runtime // nil until the server is initialized
	Setup      func(ctx context.Context, org, email, password string) error
	Hub        *hub.Hub
	TOTPSealer *keys.Sealer
	Sessions   *auth.Sessions
	Now        func() time.Time
	Log        *slog.Logger

	limiter *loginLimiter
}

func (a *API) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

func (a *API) Handler() http.Handler {
	if a.Log == nil {
		a.Log = slog.Default()
	}
	a.limiter = newLoginLimiter()
	r := chi.NewRouter()
	r.Get("/api/setup/status", a.setupStatus)
	r.Post("/api/setup", a.setup)
	r.Group(func(r chi.Router) {
		r.Use(a.requireRuntime)
		r.Post("/api/login", a.login)
		r.Group(func(r chi.Router) {
			r.Use(a.withSession(false))
			r.Post("/api/logout", a.logout)
			r.Post("/api/mfa/setup", a.mfaSetup)
			r.Post("/api/mfa/verify", a.mfaVerify)
		})
		r.Group(func(r chi.Router) {
			r.Use(a.withSession(true))
			r.Get("/api/me", a.me)
			a.routes(r)
		})
	})
	return r
}

// routes registers resource endpoints; filled in by Task 13.
func (a *API) routes(r chi.Router) {}

func (a *API) requireRuntime(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.Runtime() == nil {
			writeErr(w, http.StatusServiceUnavailable, "not initialized")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *API) audit(r *http.Request, p principal, action, targetType, targetID string, detail map[string]any, result string) {
	err := a.Store.AppendAudit(r.Context(), p.TenantID, store.AuditEntry{
		Actor: "admin:" + p.Admin.Email, Action: action, TargetType: targetType, TargetID: targetID,
		Detail: detail, IP: auth.ClientIP(r), Result: result,
	})
	if err != nil {
		a.Log.Error("audit write failed", "action", action, "err", err)
	}
}
