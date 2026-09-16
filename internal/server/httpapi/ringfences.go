package httpapi

import (
	"net/http"
	"strings"
	"time"

	"freelocker/internal/server/store"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// asrRules is the curated set the console exposes. Writing an arbitrary GUID
// into Defender machine policy is not something an admin should be able to do
// through this API, so anything outside this set is a 400.
var asrRules = map[string]string{
	"D4F940AB-401B-4EFC-AADC-AD5F3C50688A": "Office applications creating child processes",
	"3B576869-A4EC-4529-8536-B80A7769E899": "Office applications creating executable content",
	"D3E037E1-3EB8-44C8-A917-57927947596D": "JS/VBScript launching downloaded executable content",
	"5BEB7EFE-FD9A-4556-801D-275E5FFC04CC": "Execution of potentially obfuscated scripts",
	"92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B": "Win32 API calls from Office macros",
	"D1E49AAC-8F56-4280-B9BA-993A6D77406C": "Process creation from PSExec and WMI",
}

type ringfenceJSON struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Mode      string    `json:"mode"`
	CreatedAt time.Time `json:"created_at"`
}

func (a *API) listRingfences(w http.ResponseWriter, r *http.Request) {
	rfs, err := a.Store.ListRingfences(r.Context(), principalFrom(r).TenantID)
	if err != nil {
		a.storeErr(w, err)
		return
	}
	out := make([]ringfenceJSON, 0, len(rfs))
	for _, rf := range rfs {
		out = append(out, ringfenceJSON{ID: rf.ID.String(), Name: rf.Name, Mode: rf.Mode, CreatedAt: rf.CreatedAt})
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *API) getRingfence(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	p := principalFrom(r)
	rf, err := a.Store.GetRingfence(r.Context(), p.TenantID, id)
	if err != nil {
		a.storeErr(w, err)
		return
	}
	progs, _ := a.Store.ListRingfencePrograms(r.Context(), p.TenantID, id)
	progOut := make([]map[string]any, 0, len(progs))
	for _, pr := range progs {
		progOut = append(progOut, map[string]any{
			"id": pr.ID.String(), "path": pr.Path, "network_blocked": pr.NetworkBlocked, "note": pr.Note,
		})
	}
	prots, _ := a.Store.ListRingfenceProtections(r.Context(), p.TenantID, id)
	protOut := make([]map[string]any, 0, len(prots))
	for _, pt := range prots {
		protOut = append(protOut, map[string]any{"asr_rule": pt.ASRRule, "action": pt.Action})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ringfence":   ringfenceJSON{ID: rf.ID.String(), Name: rf.Name, Mode: rf.Mode, CreatedAt: rf.CreatedAt},
		"programs":    progOut,
		"protections": protOut,
	})
}

func (a *API) createRingfence(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		writeErr(w, http.StatusBadRequest, "name is required")
		return
	}
	p := principalFrom(r)
	id := uuid.New()
	// New ringfences always start in audit mode — enforce must be chosen
	// explicitly afterward, never at creation.
	if err := a.Store.CreateRingfence(r.Context(), p.TenantID, store.Ringfence{ID: id, Name: req.Name, Mode: "audit"}); err != nil {
		a.storeErr(w, err)
		return
	}
	a.audit(r, p, "ringfence.create", "ringfence", id.String(), map[string]any{"name": req.Name}, "success")
	writeJSON(w, http.StatusCreated, map[string]string{"id": id.String()})
}

func (a *API) renameRingfence(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		writeErr(w, http.StatusBadRequest, "name is required")
		return
	}
	p := principalFrom(r)
	if err := a.Store.RenameRingfence(r.Context(), p.TenantID, id, req.Name); err != nil {
		a.storeErr(w, err)
		return
	}
	a.audit(r, p, "ringfence.rename", "ringfence", id.String(), map[string]any{"name": req.Name}, "success")
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) setRingfenceMode(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var req struct {
		Mode string `json:"mode"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if req.Mode != "audit" && req.Mode != "enforce" {
		writeErr(w, http.StatusBadRequest, "mode must be audit or enforce")
		return
	}
	p := principalFrom(r)
	if err := a.Store.SetRingfenceMode(r.Context(), p.TenantID, id, req.Mode); err != nil {
		a.storeErr(w, err)
		return
	}
	a.audit(r, p, "ringfence.mode", "ringfence", id.String(), map[string]any{"mode": req.Mode}, "success")
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) deleteRingfence(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	p := principalFrom(r)
	if err := a.Store.DeleteRingfence(r.Context(), p.TenantID, id); err != nil {
		a.storeErr(w, err)
		return
	}
	a.audit(r, p, "ringfence.delete", "ringfence", id.String(), nil, "success")
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) addRingfenceProgram(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var req struct {
		Path           string `json:"path"`
		NetworkBlocked bool   `json:"network_blocked"`
		Note           string `json:"note"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	req.Path = strings.TrimSpace(req.Path)
	if req.Path == "" {
		writeErr(w, http.StatusBadRequest, "path is required")
		return
	}
	p := principalFrom(r)
	progID := uuid.New()
	if err := a.Store.AddRingfenceProgram(r.Context(), p.TenantID, id, store.RingfenceProgram{
		ID: progID, Path: req.Path, NetworkBlocked: req.NetworkBlocked, Note: req.Note,
	}); err != nil {
		a.storeErr(w, err)
		return
	}
	a.audit(r, p, "ringfence.program", "ringfence", id.String(), map[string]any{"path": req.Path, "network_blocked": req.NetworkBlocked}, "success")
	writeJSON(w, http.StatusCreated, map[string]string{"id": progID.String()})
}

func (a *API) deleteRingfenceProgram(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	progID, err := uuid.Parse(chi.URLParam(r, "programId"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid program id")
		return
	}
	p := principalFrom(r)
	if err := a.Store.DeleteRingfenceProgram(r.Context(), p.TenantID, id, progID); err != nil {
		a.storeErr(w, err)
		return
	}
	a.audit(r, p, "ringfence.program", "ringfence", id.String(), map[string]any{"program_id": progID.String(), "action": "delete"}, "success")
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) setRingfenceProtection(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var req struct {
		ASRRule string `json:"asr_rule"`
		Action  string `json:"action"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if _, known := asrRules[strings.ToUpper(req.ASRRule)]; !known {
		writeErr(w, http.StatusBadRequest, "asr_rule is not in the curated set")
		return
	}
	if req.Action != "audit" && req.Action != "block" && req.Action != "off" {
		writeErr(w, http.StatusBadRequest, "action must be audit, block, or off")
		return
	}
	p := principalFrom(r)
	if err := a.Store.SetRingfenceProtection(r.Context(), p.TenantID, id, strings.ToUpper(req.ASRRule), req.Action); err != nil {
		a.storeErr(w, err)
		return
	}
	a.audit(r, p, "ringfence.protection", "ringfence", id.String(), map[string]any{"asr_rule": req.ASRRule, "action": req.Action}, "success")
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) assignRingfence(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var req struct {
		GroupID string `json:"group_id"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	gid, err := uuid.Parse(req.GroupID)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid group_id")
		return
	}
	p := principalFrom(r)
	if err := a.Store.AssignRingfence(r.Context(), p.TenantID, gid, id); err != nil {
		a.storeErr(w, err)
		return
	}
	a.audit(r, p, "ringfence.assign", "ringfence", id.String(), map[string]any{"group_id": gid.String()}, "success")
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) unassignRingfence(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	p := principalFrom(r)
	if err := a.Store.UnassignRingfence(r.Context(), p.TenantID, id); err != nil {
		a.storeErr(w, err)
		return
	}
	a.audit(r, p, "ringfence.unassign", "group", id.String(), nil, "success")
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) listRingfenceEvents(w http.ResponseWriter, r *http.Request) {
	events, err := a.Store.ListRingfenceEvents(r.Context(), principalFrom(r).TenantID, queryInt(r, "limit", 200, 1000))
	if err != nil {
		a.storeErr(w, err)
		return
	}
	out := make([]map[string]any, 0, len(events))
	for _, e := range events {
		out = append(out, map[string]any{
			"id": e.ID, "device_id": e.DeviceID.String(), "hostname": e.Hostname,
			"kind": e.Kind, "program": e.Program, "detail": e.Detail,
			"enforced": e.Enforced, "at": e.At,
		})
	}
	writeJSON(w, http.StatusOK, out)
}
