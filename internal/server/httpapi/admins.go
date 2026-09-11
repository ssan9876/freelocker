package httpapi

import (
	"net/http"
	"slices"
	"strings"
	"time"

	"freelocker/internal/server/auth"
	"freelocker/internal/server/store"
)

type adminJSON struct {
	ID          string    `json:"id"`
	Email       string    `json:"email"`
	Role        string    `json:"role"`
	Disabled    bool      `json:"disabled"`
	MFAEnrolled bool      `json:"mfa_enrolled"`
	CreatedAt   time.Time `json:"created_at"`
}

func (a *API) listAdmins(w http.ResponseWriter, r *http.Request) {
	admins, err := a.Store.ListAdmins(r.Context(), principalFrom(r).TenantID)
	if err != nil {
		a.storeErr(w, err)
		return
	}
	out := make([]adminJSON, 0, len(admins))
	for _, ad := range admins {
		out = append(out, adminJSON{ID: ad.ID.String(), Email: ad.Email, Role: ad.Role, Disabled: ad.Disabled,
			MFAEnrolled: ad.TOTPConfirmed, CreatedAt: ad.CreatedAt})
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *API) createAdmin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))
	if !strings.Contains(req.Email, "@") || !slices.Contains(auth.Roles, req.Role) {
		writeErr(w, http.StatusBadRequest, "a valid email and role (owner, admin, readonly) are required")
		return
	}
	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	p := principalFrom(r)
	id, err := a.Store.CreateAdmin(r.Context(), p.TenantID, store.Admin{Email: req.Email, PasswordHash: hash, Role: req.Role})
	if err != nil {
		a.storeErr(w, err)
		return
	}
	a.audit(r, p, "admin.create", "admin", id.String(), map[string]any{"email": req.Email, "role": req.Role}, "success")
	writeJSON(w, http.StatusCreated, map[string]string{"id": id.String()})
}

func (a *API) disableAdmin(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	p := principalFrom(r)
	if id == p.Admin.ID {
		writeErr(w, http.StatusBadRequest, "cannot disable yourself")
		return
	}
	if err := a.Store.SetAdminDisabled(r.Context(), p.TenantID, id, true); err != nil {
		a.storeErr(w, err)
		return
	}
	if err := a.Store.DeleteAdminSessions(r.Context(), p.TenantID, id); err != nil {
		a.storeErr(w, err)
		return
	}
	a.audit(r, p, "admin.disable", "admin", id.String(), nil, "success")
	w.WriteHeader(http.StatusNoContent)
}
