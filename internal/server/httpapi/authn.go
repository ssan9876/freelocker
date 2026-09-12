package httpapi

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"

	"freelocker/internal/server/auth"
	"freelocker/internal/server/bootstrap"
	"freelocker/internal/server/store"

	"github.com/google/uuid"
)

type principalKey struct{}

type principal struct {
	Admin    store.Admin
	Session  store.Session
	TenantID uuid.UUID
}

func principalFrom(r *http.Request) principal { return r.Context().Value(principalKey{}).(principal) }

func (a *API) withSession(requireMFA bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sess, err := a.Sessions.Load(r.Context(), r)
			if err != nil {
				writeErr(w, http.StatusUnauthorized, "not logged in")
				return
			}
			admin, err := a.Store.GetAdmin(r.Context(), sess.TenantID, sess.AdminID)
			if err != nil || admin.Disabled {
				writeErr(w, http.StatusUnauthorized, "not logged in")
				return
			}
			if r.Method != http.MethodGet &&
				subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(sess.CSRFToken)) != 1 {
				writeErr(w, http.StatusForbidden, "bad CSRF token")
				return
			}
			if requireMFA && !sess.MFAPassed {
				writeErr(w, http.StatusForbidden, "mfa_required")
				return
			}
			p := principal{Admin: admin, Session: sess, TenantID: sess.TenantID}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), principalKey{}, p)))
		})
	}
}

func (a *API) requireRole(role string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !auth.Allows(principalFrom(r).Admin.Role, role) {
				writeErr(w, http.StatusForbidden, "requires role "+role)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func (a *API) setupStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]bool{"initialized": a.Runtime() != nil})
}

func (a *API) setup(w http.ResponseWriter, r *http.Request) {
	var req struct {
		OrgName  string `json:"org_name"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if a.Runtime() != nil {
		writeErr(w, http.StatusConflict, "already initialized")
		return
	}
	if strings.TrimSpace(req.OrgName) == "" || !strings.Contains(req.Email, "@") || len(req.Password) < auth.MinPasswordLen {
		writeErr(w, http.StatusBadRequest, "org_name, a valid email, and a password of at least 12 characters are required")
		return
	}
	err := a.Setup(r.Context(), strings.TrimSpace(req.OrgName), req.Email, req.Password)
	switch {
	case errors.Is(err, bootstrap.ErrAlreadyInitialized):
		writeErr(w, http.StatusConflict, "already initialized")
	case err != nil:
		a.Log.Error("setup failed", "err", err)
		writeErr(w, http.StatusInternalServerError, "setup failed")
	default:
		writeJSON(w, http.StatusCreated, map[string]bool{"initialized": true})
	}
}

func (a *API) login(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	tenant := a.Runtime().Keys.TenantID
	email := strings.ToLower(strings.TrimSpace(req.Email))
	key := auth.ClientIP(r) + "|" + email
	now := a.now()
	if !a.limiter.allow(r.Context(), tenant, key, now) {
		writeErr(w, http.StatusTooManyRequests, "too many failed attempts; try again later")
		return
	}

	admin, err := a.Store.GetAdminByEmail(r.Context(), tenant, email)
	var hash *string
	if err == nil && !admin.Disabled {
		hash = &admin.PasswordHash
	}
	if !auth.CheckPasswordOrDummy(hash, req.Password) {
		a.limiter.fail(r.Context(), tenant, key, now)
		a.audit(r, principal{TenantID: tenant, Admin: store.Admin{Email: email}}, "admin.login", "admin", "", map[string]any{"stage": "password"}, "failure")
		writeErr(w, http.StatusUnauthorized, "invalid email or password")
		return
	}
	a.limiter.reset(r.Context(), tenant, key)

	sess, err := a.Sessions.Create(r.Context(), w, r, tenant, admin.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not create session")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"csrf_token": sess.CSRFToken, "mfa_enrolled": admin.TOTPConfirmed})
}

func (a *API) logout(w http.ResponseWriter, r *http.Request) {
	a.Sessions.Destroy(r.Context(), w, r)
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) mfaSetup(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r)
	if p.Admin.TOTPConfirmed {
		writeErr(w, http.StatusConflict, "MFA already enrolled")
		return
	}
	secret, url, err := auth.NewTOTPSecret(p.Admin.Email)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not create TOTP secret")
		return
	}
	if err := a.Store.SetAdminTOTP(r.Context(), p.TenantID, p.Admin.ID, a.TOTPSealer.Seal([]byte(secret)), false); err != nil {
		writeErr(w, http.StatusInternalServerError, "could not store TOTP secret")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"secret": secret, "otpauth_url": url})
}

func (a *API) mfaVerify(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Code string `json:"code"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	p := principalFrom(r)
	if p.Admin.TOTPSecretEnc == nil {
		writeErr(w, http.StatusBadRequest, "MFA not set up; call /api/mfa/setup first")
		return
	}
	key := "mfa|" + p.Session.ID
	now := a.now()
	if !a.limiter.allow(r.Context(), p.TenantID, key, now) {
		writeErr(w, http.StatusTooManyRequests, "too many failed attempts; try again later")
		return
	}
	secret, err := a.TOTPSealer.Open(p.Admin.TOTPSecretEnc)
	if err != nil || !auth.ValidateTOTP(string(secret), strings.TrimSpace(req.Code), now) {
		a.limiter.fail(r.Context(), p.TenantID, key, now)
		a.audit(r, p, "admin.login", "admin", p.Admin.ID.String(), map[string]any{"stage": "mfa"}, "failure")
		writeErr(w, http.StatusUnauthorized, "invalid code")
		return
	}
	a.limiter.reset(r.Context(), p.TenantID, key)
	if !p.Admin.TOTPConfirmed {
		if err := a.Store.SetAdminTOTP(r.Context(), p.TenantID, p.Admin.ID, p.Admin.TOTPSecretEnc, true); err != nil {
			writeErr(w, http.StatusInternalServerError, "could not confirm MFA")
			return
		}
	}
	if err := a.Store.MarkSessionMFA(r.Context(), p.Session.ID); err != nil {
		writeErr(w, http.StatusInternalServerError, "could not update session")
		return
	}
	a.audit(r, p, "admin.login", "admin", p.Admin.ID.String(), nil, "success")
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) me(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r)
	writeJSON(w, http.StatusOK, map[string]string{"id": p.Admin.ID.String(), "email": p.Admin.Email, "role": p.Admin.Role})
}
