package httpapi

import (
	"errors"
	"net/http"
	"time"

	flv1 "freelocker/gen/freelocker/v1"
	"freelocker/internal/server/agentapi"
	"freelocker/internal/server/auth"
	"freelocker/internal/server/commands"
	"freelocker/internal/server/store"

	"github.com/google/uuid"
)

type deviceJSON struct {
	ID            string     `json:"id"`
	Hostname      string     `json:"hostname"`
	Status        string     `json:"status"`
	Connected     bool       `json:"connected"`
	GroupID       *uuid.UUID `json:"group_id"`
	OSBuild       string     `json:"os_build"`
	AgentVersion  string     `json:"agent_version"`
	IPAddresses   []string   `json:"ip_addresses"`
	LoggedOnUser  string     `json:"logged_on_user"`
	UptimeSeconds int64      `json:"uptime_seconds"`
	LastSeenAt    *time.Time `json:"last_seen_at"`
	CertExpiresAt time.Time  `json:"cert_expires_at"`
	EnrolledAt    time.Time  `json:"enrolled_at"`
	// ASRAvailable is nil when the device has never reported a ringfence
	// status, so the console can tell "not yet reported" apart from a
	// reported false ("not enforced -- Defender inactive").
	ASRAvailable *bool `json:"asr_available"`
}

func (a *API) toDeviceJSON(d store.Device, now time.Time) deviceJSON {
	return deviceJSON{
		ID: d.ID.String(), Hostname: d.Hostname, Status: d.Status(now), Connected: a.Hub.Connected(d.ID),
		GroupID: d.GroupID, OSBuild: d.OSBuild, AgentVersion: d.AgentVersion, IPAddresses: d.IPs,
		LoggedOnUser: d.LoggedOnUser, UptimeSeconds: d.UptimeSeconds, LastSeenAt: d.LastSeenAt,
		CertExpiresAt: d.CertExpiresAt, EnrolledAt: d.EnrolledAt, ASRAvailable: d.ASRAvailable,
	}
}

func (a *API) listDevices(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r)
	devs, err := a.Store.ListDevices(r.Context(), p.TenantID)
	if err != nil {
		a.storeErr(w, err)
		return
	}
	wantStatus := r.URL.Query().Get("status")
	wantGroup := r.URL.Query().Get("group_id")
	now := a.now()
	out := []deviceJSON{}
	for _, d := range devs {
		dj := a.toDeviceJSON(d, now)
		if wantStatus != "" && dj.Status != wantStatus {
			continue
		}
		if wantGroup != "" && (d.GroupID == nil || d.GroupID.String() != wantGroup) {
			continue
		}
		out = append(out, dj)
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *API) getDevice(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	p := principalFrom(r)
	d, err := a.Store.GetDevice(r.Context(), p.TenantID, id)
	if err != nil {
		a.storeErr(w, err)
		return
	}
	resp := map[string]any{"device": a.toDeviceJSON(d, a.now())}
	if auth.Allows(p.Admin.Role, "admin") {
		if k, err := a.keysFor(r.Context(), p.TenantID); err == nil {
			resp["uninstall_code"] = k.UninstallCode(id)
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

func (a *API) revokeDevice(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	p := principalFrom(r)
	if err := a.Store.RevokeDevice(r.Context(), p.TenantID, id); err != nil {
		a.storeErr(w, err)
		return
	}
	a.Hub.Disconnect(id, agentapi.RevokedError())
	a.audit(r, p, "device.revoke", "device", id.String(), nil, "success")
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) issueCommand(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var req struct {
		Type string `json:"type"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	typ, err := commands.ParseType(req.Type)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	p := principalFrom(r)
	d, err := a.Store.GetDevice(r.Context(), p.TenantID, id)
	if err != nil {
		a.storeErr(w, err)
		return
	}
	if d.Revoked {
		writeErr(w, http.StatusConflict, "device revoked")
		return
	}
	var cmdID uuid.UUID
	if typ == flv1.CommandType_COMMAND_TYPE_UPDATE_AGENT {
		rel, err := a.Store.LatestRelease(r.Context(), p.TenantID)
		if errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusConflict, "no agent release uploaded")
			return
		}
		if err != nil {
			a.storeErr(w, err)
			return
		}
		cmdID, err = a.Runtime().Commands.IssueUpdate(r.Context(), p.TenantID, id, a.updatePayload(p.TenantID, rel), "admin:"+p.Admin.Email)
		if err != nil {
			a.storeErr(w, err)
			return
		}
	} else {
		var err error
		cmdID, err = a.Runtime().Commands.Issue(r.Context(), p.TenantID, id, typ, nil, &p.Admin.ID, "admin:"+p.Admin.Email)
		if err != nil {
			a.storeErr(w, err)
			return
		}
	}
	writeJSON(w, http.StatusCreated, map[string]string{"id": cmdID.String()})
}

// updatePayload turns a stored release into the signed command payload the
// agent verifies before installing.
func (a *API) updatePayload(tenantID uuid.UUID, rel store.Release) commands.UpdatePayload {
	return commands.UpdatePayload{Version: rel.Version, URL: a.ReleaseURL(tenantID, rel.Version), SHA256: rel.SHA256, Signature: rel.Signature}
}

type commandJSON struct {
	ID          string     `json:"id"`
	Type        string     `json:"type"`
	State       string     `json:"state"`
	Result      string     `json:"result"`
	IssuedAt    time.Time  `json:"issued_at"`
	ExpiresAt   time.Time  `json:"expires_at"`
	CompletedAt *time.Time `json:"completed_at"`
}

func (a *API) listDeviceCommands(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	p := principalFrom(r)
	cmds, err := a.Store.ListDeviceCommands(r.Context(), p.TenantID, id, queryInt(r, "limit", 50, 500))
	if err != nil {
		a.storeErr(w, err)
		return
	}
	out := make([]commandJSON, 0, len(cmds))
	for _, c := range cmds {
		out = append(out, commandJSON{ID: c.ID.String(), Type: c.Type, State: c.State, Result: c.Result,
			IssuedAt: c.IssuedAt, ExpiresAt: c.ExpiresAt, CompletedAt: c.CompletedAt})
	}
	writeJSON(w, http.StatusOK, out)
}
