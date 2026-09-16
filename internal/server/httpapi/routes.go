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
	r.Get("/api/policies", a.listPolicies)
	r.Get("/api/policies/{id}", a.getPolicy)
	r.Get("/api/devices/{id}/observations", a.listObservations)
	r.Get("/api/devices/{id}/metrics", a.listMetrics)
	r.Get("/api/blocks", a.listBlocks)
	r.Get("/api/approvals", a.listApprovals)
	r.Get("/api/approvals/count", a.countApprovals)
	r.Get("/api/alert-rules", a.listAlertRules)
	r.Get("/api/alerts", a.listAlerts)
	r.Get("/api/events", a.listDeviceEvents)
	r.Get("/api/groups/{id}/controls", a.getControls)
	r.Get("/api/devices/{id}/controls", a.getDeviceControls)
	r.Get("/api/rollouts", a.listRollouts)
	r.Get("/api/rollouts/{id}", a.getRollout)
	r.Get("/api/notifications/status", a.notificationStatus)
	r.Get("/api/notification-channels", a.listChannels)
	r.Get("/api/notification-deliveries", a.listDeliveries)
	r.Get("/api/ringfences", a.listRingfences)
	r.Get("/api/ringfences/{id}", a.getRingfence)
	r.Get("/api/ringfence-events", a.listRingfenceEvents)

	r.Group(func(r chi.Router) {
		r.Use(a.requireRole("admin"))
		r.Post("/api/notification-channels", a.createChannel)
		r.Patch("/api/notification-channels/{id}", a.updateChannel)
		r.Delete("/api/notification-channels/{id}", a.deleteChannel)
		r.Post("/api/notification-channels/{id}/test", a.testChannel)
		r.Post("/api/devices/{id}/revoke", a.revokeDevice)
		r.Post("/api/devices/{id}/commands", a.issueCommand)
		r.Post("/api/groups", a.createGroup)
		r.Patch("/api/groups/{id}", a.renameGroup)
		r.Delete("/api/groups/{id}", a.deleteGroup)
		r.Post("/api/devices/{id}/group", a.setDeviceGroup)
		r.Patch("/api/alert-rules/{id}", a.updateAlertRule)
		r.Post("/api/tokens", a.createToken)
		r.Post("/api/tokens/{id}/revoke", a.revokeToken)
		r.Post("/api/policies", a.createPolicy)
		r.Post("/api/policies/{id}/mode", a.setPolicyMode)
		r.Delete("/api/policies/{id}", a.deletePolicy)
		r.Post("/api/policies/{id}/rules", a.addRule)
		r.Delete("/api/policies/{id}/rules/{ruleId}", a.deleteRule)
		r.Post("/api/policies/{id}/assign", a.assignPolicy)
		r.Post("/api/policies/{id}/recompile", a.recompilePolicy)
		r.Post("/api/observations/promote", a.promoteObservation)
		r.Post("/api/approvals/{id}/approve", a.approveApproval)
		r.Post("/api/approvals/{id}/deny", a.denyApproval)
		r.Post("/api/alert-rules", a.createAlertRule)
		r.Delete("/api/alert-rules/{id}", a.deleteAlertRule)
		r.Post("/api/groups/{id}/controls", a.setControls)
		r.Post("/api/devices/{id}/controls", a.setDeviceControls)
		r.Post("/api/rollouts", a.createRollout)
		r.Post("/api/rollouts/{id}/pause", a.transitionRollout("pause", []string{"active"}, "paused"))
		r.Post("/api/rollouts/{id}/resume", a.transitionRollout("resume", []string{"paused"}, "active"))
		r.Post("/api/rollouts/{id}/cancel", a.transitionRollout("cancel", []string{"active", "paused"}, "cancelled"))
		r.Post("/api/rollouts/{id}/rollback", a.rollbackRollout)
		r.Post("/api/ringfences", a.createRingfence)
		r.Patch("/api/ringfences/{id}", a.renameRingfence)
		r.Delete("/api/ringfences/{id}", a.deleteRingfence)
		r.Post("/api/ringfences/{id}/mode", a.setRingfenceMode)
		r.Post("/api/ringfences/{id}/programs", a.addRingfenceProgram)
		r.Delete("/api/ringfences/{id}/programs/{programId}", a.deleteRingfenceProgram)
		r.Put("/api/ringfences/{id}/protections", a.setRingfenceProtection)
		r.Post("/api/ringfences/{id}/assign", a.assignRingfence)
		r.Delete("/api/groups/{id}/ringfence", a.unassignRingfence)
	})

	r.Group(func(r chi.Router) {
		r.Use(a.requireRole("owner"))
		r.Get("/api/admins", a.listAdmins)
		r.Post("/api/admins", a.createAdmin)
		r.Post("/api/admins/{id}/disable", a.disableAdmin)
		r.Post("/api/admins/{id}/enable", a.enableAdmin)
		r.Post("/api/admins/{id}/role", a.setAdminRole)
		r.Post("/api/releases", a.uploadRelease)
	})

	// Provider-only: manage tenants across the deployment (MSP operator).
	r.Group(func(r chi.Router) {
		r.Use(a.requireProvider)
		r.Get("/api/provider/tenants", a.listProviderTenants)
		r.Post("/api/provider/tenants", a.createProviderTenant)
		r.Patch("/api/provider/tenants/{id}", a.updateProviderTenant)
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
