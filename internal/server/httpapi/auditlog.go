package httpapi

import (
	"net/http"
	"strconv"
	"time"
)

type auditJSON struct {
	ID         int64          `json:"id"`
	Actor      string         `json:"actor"`
	Action     string         `json:"action"`
	TargetType string         `json:"target_type"`
	TargetID   string         `json:"target_id"`
	Detail     map[string]any `json:"detail"`
	IP         string         `json:"ip"`
	Result     string         `json:"result"`
	CreatedAt  time.Time      `json:"created_at"`
}

func (a *API) listAudit(w http.ResponseWriter, r *http.Request) {
	before, _ := strconv.ParseInt(r.URL.Query().Get("before"), 10, 64)
	entries, err := a.Store.ListAudit(r.Context(), principalFrom(r).TenantID, queryInt(r, "limit", 100, 500), before)
	if err != nil {
		a.storeErr(w, err)
		return
	}
	out := make([]auditJSON, 0, len(entries))
	for _, e := range entries {
		out = append(out, auditJSON{ID: e.ID, Actor: e.Actor, Action: e.Action, TargetType: e.TargetType,
			TargetID: e.TargetID, Detail: e.Detail, IP: e.IP, Result: e.Result, CreatedAt: e.CreatedAt})
	}
	writeJSON(w, http.StatusOK, out)
}
