package httpapi

import (
	"errors"
	"net/http"
	"strconv"

	"freelocker/internal/server/store"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

func (a *API) routes(r chi.Router) {
	r.Get("/api/devices", a.listDevices)
	r.Get("/api/devices/{id}", a.getDevice)
	r.Get("/api/devices/{id}/commands", a.listDeviceCommands)
	r.Get("/api/groups", a.listGroups)
	r.Get("/api/tokens", a.listTokens)
	r.Get("/api/releases", a.listReleases)
	r.Get("/api/audit", a.listAudit)

	r.Group(func(r chi.Router) {
		r.Use(a.requireRole("admin"))
		r.Post("/api/devices/{id}/revoke", a.revokeDevice)
		r.Post("/api/devices/{id}/commands", a.issueCommand)
		r.Post("/api/groups", a.createGroup)
		r.Post("/api/tokens", a.createToken)
		r.Post("/api/tokens/{id}/revoke", a.revokeToken)
	})

	r.Group(func(r chi.Router) {
		r.Use(a.requireRole("owner"))
		r.Get("/api/admins", a.listAdmins)
		r.Post("/api/admins", a.createAdmin)
		r.Post("/api/admins/{id}/disable", a.disableAdmin)
		r.Post("/api/releases", a.uploadRelease)
	})
}

func pathID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return uuid.Nil, false
	}
	return id, true
}

// queryInt parses an optional positive integer, clamped to [1, max].
func queryInt(r *http.Request, name string, def, max int) int {
	n, err := strconv.Atoi(r.URL.Query().Get(name))
	if err != nil || n < 1 {
		return def
	}
	return min(n, max)
}

func (a *API) storeErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeErr(w, http.StatusNotFound, "not found")
	case errors.Is(err, store.ErrConflict):
		writeErr(w, http.StatusConflict, "already exists")
	default:
		a.Log.Error("store error", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal error")
	}
}
