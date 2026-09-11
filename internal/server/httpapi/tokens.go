package httpapi

import (
	"net/http"
	"strings"
	"time"

	"freelocker/internal/server/store"
	"freelocker/internal/server/tokens"

	"github.com/google/uuid"
)

func (a *API) listGroups(w http.ResponseWriter, r *http.Request) {
	groups, err := a.Store.ListDeviceGroups(r.Context(), principalFrom(r).TenantID)
	if err != nil {
		a.storeErr(w, err)
		return
	}
	out := make([]map[string]string, 0, len(groups))
	for _, g := range groups {
		out = append(out, map[string]string{"id": g.ID.String(), "name": g.Name})
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *API) createGroup(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		writeErr(w, http.StatusBadRequest, "name is required")
		return
	}
	p := principalFrom(r)
	id, err := a.Store.CreateDeviceGroup(r.Context(), p.TenantID, name)
	if err != nil {
		a.storeErr(w, err)
		return
	}
	a.audit(r, p, "group.create", "group", id.String(), map[string]any{"name": name}, "success")
	writeJSON(w, http.StatusCreated, map[string]string{"id": id.String()})
}

type tokenJSON struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	GroupID   *uuid.UUID `json:"group_id"`
	ExpiresAt *time.Time `json:"expires_at"`
	MaxUses   *int       `json:"max_uses"`
	Uses      int        `json:"uses"`
	Revoked   bool       `json:"revoked"`
	CreatedAt time.Time  `json:"created_at"`
}

func (a *API) listTokens(w http.ResponseWriter, r *http.Request) {
	toks, err := a.Store.ListInstallTokens(r.Context(), principalFrom(r).TenantID)
	if err != nil {
		a.storeErr(w, err)
		return
	}
	out := make([]tokenJSON, 0, len(toks))
	for _, t := range toks {
		out = append(out, tokenJSON{ID: t.ID.String(), Name: t.Name, GroupID: t.GroupID, ExpiresAt: t.ExpiresAt,
			MaxUses: t.MaxUses, Uses: t.Uses, Revoked: t.Revoked, CreatedAt: t.CreatedAt})
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *API) createToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name           string     `json:"name"`
		GroupID        *uuid.UUID `json:"group_id"`
		ExpiresInHours *int       `json:"expires_in_hours"`
		MaxUses        *int       `json:"max_uses"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" || (req.ExpiresInHours != nil && *req.ExpiresInHours < 1) || (req.MaxUses != nil && *req.MaxUses < 1) {
		writeErr(w, http.StatusBadRequest, "name is required; expires_in_hours and max_uses must be positive when set")
		return
	}
	p := principalFrom(r)
	if req.GroupID != nil && !a.groupExists(r, p, *req.GroupID) {
		writeErr(w, http.StatusBadRequest, "unknown group_id")
		return
	}
	full, hash, err := tokens.Generate(a.Runtime().Keys.CA.Pin())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not generate token")
		return
	}
	t := store.InstallToken{Name: req.Name, GroupID: req.GroupID, MaxUses: req.MaxUses, CreatedBy: &p.Admin.ID}
	if req.ExpiresInHours != nil {
		exp := a.now().Add(time.Duration(*req.ExpiresInHours) * time.Hour)
		t.ExpiresAt = &exp
	}
	id, err := a.Store.CreateInstallToken(r.Context(), p.TenantID, t, hash)
	if err != nil {
		a.storeErr(w, err)
		return
	}
	a.audit(r, p, "token.create", "token", id.String(), map[string]any{"name": req.Name}, "success")
	writeJSON(w, http.StatusCreated, map[string]string{"id": id.String(), "token": full})
}

func (a *API) groupExists(r *http.Request, p principal, id uuid.UUID) bool {
	groups, err := a.Store.ListDeviceGroups(r.Context(), p.TenantID)
	if err != nil {
		return false
	}
	for _, g := range groups {
		if g.ID == id {
			return true
		}
	}
	return false
}

func (a *API) revokeToken(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	p := principalFrom(r)
	if err := a.Store.RevokeInstallToken(r.Context(), p.TenantID, id); err != nil {
		a.storeErr(w, err)
		return
	}
	a.audit(r, p, "token.revoke", "token", id.String(), nil, "success")
	w.WriteHeader(http.StatusNoContent)
}
