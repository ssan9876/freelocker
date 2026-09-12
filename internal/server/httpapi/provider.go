package httpapi

import (
	"net/http"
	"strings"

	"freelocker/internal/server/auth"
)

// requireProvider gates the provider tenant-management endpoints. A provider is
// the MSP operator; ordinary owners of a single tenant are not providers.
func (a *API) requireProvider(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !principalFrom(r).Admin.Provider {
			writeErr(w, http.StatusForbidden, "requires provider")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *API) listProviderTenants(w http.ResponseWriter, r *http.Request) {
	tenants, err := a.Store.ListTenantDetails(r.Context())
	if err != nil {
		a.storeErr(w, err)
		return
	}
	out := make([]map[string]any, 0, len(tenants))
	for _, t := range tenants {
		out = append(out, map[string]any{"id": t.ID.String(), "name": t.Name, "suspended": t.Suspended, "created_at": t.CreatedAt})
	}
	writeJSON(w, http.StatusOK, out)
}

// updateProviderTenant renames and/or suspends a tenant. Suspension signs the
// tenant's admins out and refuses its agents; the provider's own tenant cannot
// be suspended.
func (a *API) updateProviderTenant(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var req struct {
		Name      *string `json:"name"`
		Suspended *bool   `json:"suspended"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	p := principalFrom(r)
	if req.Name != nil && strings.TrimSpace(*req.Name) == "" {
		writeErr(w, http.StatusBadRequest, "name cannot be blank")
		return
	}
	if req.Suspended != nil && *req.Suspended && id == p.TenantID {
		writeErr(w, http.StatusBadRequest, "cannot suspend the provider's own tenant")
		return
	}
	if req.Name != nil {
		name := strings.TrimSpace(*req.Name)
		if err := a.Store.RenameTenant(r.Context(), id, name); err != nil {
			a.storeErr(w, err)
			return
		}
		a.audit(r, p, "provider.tenant.rename", "tenant", id.String(), map[string]any{"name": name}, "success")
	}
	if req.Suspended != nil {
		if err := a.Store.SetTenantSuspended(r.Context(), id, *req.Suspended); err != nil {
			a.storeErr(w, err)
			return
		}
		action := "provider.tenant.unsuspend"
		if *req.Suspended {
			action = "provider.tenant.suspend"
		}
		a.audit(r, p, action, "tenant", id.String(), nil, "success")
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) createProviderTenant(w http.ResponseWriter, r *http.Request) {
	var req struct {
		OrgName       string `json:"org_name"`
		OwnerEmail    string `json:"owner_email"`
		OwnerPassword string `json:"owner_password"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	req.OrgName = strings.TrimSpace(req.OrgName)
	req.OwnerEmail = strings.ToLower(strings.TrimSpace(req.OwnerEmail))
	if req.OrgName == "" || !strings.Contains(req.OwnerEmail, "@") || len(req.OwnerPassword) < auth.MinPasswordLen {
		writeErr(w, http.StatusBadRequest, "org_name, a valid owner_email, and a password of at least 12 characters are required")
		return
	}
	if a.ProvisionTenant == nil {
		writeErr(w, http.StatusInternalServerError, "tenant provisioning not available")
		return
	}
	p := principalFrom(r)
	tid, err := a.ProvisionTenant(r.Context(), req.OrgName, req.OwnerEmail, req.OwnerPassword)
	if err != nil {
		// A duplicate owner email (globally unique) surfaces as a conflict.
		a.audit(r, p, "provider.tenant.create", "tenant", "", map[string]any{"org": req.OrgName, "owner": req.OwnerEmail}, "failure")
		a.storeErr(w, err)
		return
	}
	a.audit(r, p, "provider.tenant.create", "tenant", tid.String(), map[string]any{"org": req.OrgName, "owner": req.OwnerEmail}, "success")
	writeJSON(w, http.StatusCreated, map[string]string{"tenant_id": tid.String()})
}
