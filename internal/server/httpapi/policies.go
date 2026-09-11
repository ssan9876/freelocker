package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"freelocker/internal/appcontrol/rules"
	"freelocker/internal/server/store"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

type policyJSON struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Mode      string    `json:"mode"`
	CreatedAt time.Time `json:"created_at"`
}

func (a *API) listPolicies(w http.ResponseWriter, r *http.Request) {
	ps, err := a.Store.ListPolicies(r.Context(), principalFrom(r).TenantID)
	if err != nil {
		a.storeErr(w, err)
		return
	}
	out := make([]policyJSON, 0, len(ps))
	for _, p := range ps {
		out = append(out, policyJSON{ID: p.ID.String(), Name: p.Name, Mode: p.Mode, CreatedAt: p.CreatedAt})
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *API) createPolicy(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
		Mode string `json:"mode"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		writeErr(w, http.StatusBadRequest, "name is required")
		return
	}
	if req.Mode != "" && req.Mode != "audit" && req.Mode != "enforce" {
		writeErr(w, http.StatusBadRequest, "mode must be audit or enforce")
		return
	}
	p := principalFrom(r)
	id, err := a.Store.CreatePolicy(r.Context(), p.TenantID, req.Name, req.Mode)
	if err != nil {
		a.storeErr(w, err)
		return
	}
	if _, err := a.Runtime().Policy.Recompile(r.Context(), p.TenantID, id); err != nil {
		a.Log.Error("recompile new policy", "err", err)
	}
	a.audit(r, p, "policy.create", "policy", id.String(), map[string]any{"name": req.Name}, "success")
	writeJSON(w, http.StatusCreated, map[string]string{"id": id.String()})
}

func (a *API) getPolicy(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	p := principalFrom(r)
	pol, err := a.Store.GetPolicy(r.Context(), p.TenantID, id)
	if err != nil {
		a.storeErr(w, err)
		return
	}
	rs, _ := a.Store.ListRules(r.Context(), p.TenantID, id)
	ruleOut := make([]map[string]string, 0, len(rs))
	for _, ru := range rs {
		ruleOut = append(ruleOut, map[string]string{
			"id": ru.ID.String(), "kind": ru.Kind, "value": ru.Value,
			"publisher_name": ru.PublisherName, "description": ru.Description,
		})
	}
	version := ""
	if v, err := a.Store.LatestPolicyVersion(r.Context(), p.TenantID, id); err == nil {
		version = v.Version
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"policy":  policyJSON{ID: pol.ID.String(), Name: pol.Name, Mode: pol.Mode, CreatedAt: pol.CreatedAt},
		"rules":   ruleOut,
		"version": version,
	})
}

func (a *API) setPolicyMode(w http.ResponseWriter, r *http.Request) {
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
	if err := a.Store.SetPolicyMode(r.Context(), p.TenantID, id, req.Mode); err != nil {
		a.storeErr(w, err)
		return
	}
	a.Runtime().Policy.Recompile(r.Context(), p.TenantID, id)
	a.audit(r, p, "policy.set_mode", "policy", id.String(), map[string]any{"mode": req.Mode}, "success")
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) deletePolicy(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	p := principalFrom(r)
	if err := a.Store.DeletePolicy(r.Context(), p.TenantID, id); err != nil {
		a.storeErr(w, err)
		return
	}
	a.audit(r, p, "policy.delete", "policy", id.String(), nil, "success")
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) addRule(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var req struct {
		Kind          string `json:"kind"`
		Value         string `json:"value"`
		PublisherName string `json:"publisher_name"`
		Description   string `json:"description"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	norm, err := rules.Normalize(rules.Rule{
		Kind: rules.Kind(req.Kind), Value: req.Value, PublisherName: req.PublisherName, Description: req.Description,
	})
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	p := principalFrom(r)
	rid, err := a.Store.AddRule(r.Context(), p.TenantID, id, store.PolicyRule{
		Kind: string(norm.Kind), Value: norm.Value, PublisherName: norm.PublisherName, Description: norm.Description,
	}, &p.Admin.ID)
	if err != nil {
		a.storeErr(w, err)
		return
	}
	version, err := a.Runtime().Policy.Recompile(r.Context(), p.TenantID, id)
	if err != nil {
		a.storeErr(w, err)
		return
	}
	a.audit(r, p, "policy.add_rule", "policy", id.String(), map[string]any{"kind": norm.Kind, "value": norm.Value}, "success")
	writeJSON(w, http.StatusCreated, map[string]string{"id": rid.String(), "version": version})
}

func (a *API) deleteRule(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	ruleID, err := uuid.Parse(chi.URLParam(r, "ruleId"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid rule id")
		return
	}
	p := principalFrom(r)
	if err := a.Store.DeleteRule(r.Context(), p.TenantID, id, ruleID); err != nil {
		a.storeErr(w, err)
		return
	}
	a.Runtime().Policy.Recompile(r.Context(), p.TenantID, id)
	a.audit(r, p, "policy.delete_rule", "policy", id.String(), map[string]any{"rule_id": ruleID.String()}, "success")
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) assignPolicy(w http.ResponseWriter, r *http.Request) {
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
	if err := a.Store.AssignPolicy(r.Context(), p.TenantID, gid, id); err != nil {
		a.storeErr(w, err)
		return
	}
	a.audit(r, p, "policy.assign", "policy", id.String(), map[string]any{"group_id": gid.String()}, "success")
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) recompilePolicy(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	p := principalFrom(r)
	version, err := a.Runtime().Policy.Recompile(r.Context(), p.TenantID, id)
	if err != nil {
		a.storeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"version": version})
}

func (a *API) listObservations(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	obs, err := a.Store.ListObservations(r.Context(), principalFrom(r).TenantID, id, queryInt(r, "limit", 200, 1000))
	if err != nil {
		a.storeErr(w, err)
		return
	}
	out := make([]map[string]any, 0, len(obs))
	for _, o := range obs {
		out = append(out, map[string]any{
			"sha256": o.SHA256, "path": o.Path, "signer": o.Signer,
			"count": o.Count, "first_seen": o.FirstSeen, "last_seen": o.LastSeen,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *API) promoteObservation(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PolicyID    string `json:"policy_id"`
		SHA256      string `json:"sha256"`
		Description string `json:"description"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	pid, err := uuid.Parse(req.PolicyID)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid policy_id")
		return
	}
	norm, err := rules.Normalize(rules.Rule{Kind: rules.Hash, Value: req.SHA256, Description: req.Description})
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	p := principalFrom(r)
	version, err := a.addHashRule(r.Context(), p, pid, norm)
	if err != nil {
		a.storeErr(w, err)
		return
	}
	a.audit(r, p, "policy.add_rule", "policy", pid.String(), map[string]any{"kind": "hash", "value": norm.Value, "via": "learning"}, "success")
	writeJSON(w, http.StatusCreated, map[string]string{"version": version})
}

// addHashRule adds a normalized hash allow rule to a policy and recompiles
// it, returning the new version. An identical rule already on the policy is
// not an error, so retrying is safe.
func (a *API) addHashRule(ctx context.Context, p principal, policyID uuid.UUID, rule rules.Rule) (string, error) {
	_, err := a.Store.AddRule(ctx, p.TenantID, policyID, store.PolicyRule{
		Kind: string(rule.Kind), Value: rule.Value, Description: rule.Description,
	}, &p.Admin.ID)
	if err != nil && !errors.Is(err, store.ErrConflict) {
		return "", err
	}
	return a.Runtime().Policy.Recompile(ctx, p.TenantID, policyID)
}

func (a *API) listBlocks(w http.ResponseWriter, r *http.Request) {
	events, err := a.Store.ListBlockEvents(r.Context(), principalFrom(r).TenantID, queryInt(r, "limit", 200, 1000))
	if err != nil {
		a.storeErr(w, err)
		return
	}
	out := make([]map[string]any, 0, len(events))
	for _, e := range events {
		out = append(out, map[string]any{
			"id": e.ID, "device_id": e.DeviceID.String(), "sha256": e.SHA256, "path": e.Path,
			"signer": e.Signer, "blocked": e.Blocked, "at": e.At,
		})
	}
	writeJSON(w, http.StatusOK, out)
}
