package httpapi

import (
	"net/http"
	"strings"
	"time"

	"freelocker/internal/server/store"
)

func (a *API) listMetrics(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	since := time.Now().Add(-6 * time.Hour)
	if v := r.URL.Query().Get("since"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			since = t
		}
	}
	samples, err := a.Store.ListMetrics(r.Context(), principalFrom(r).TenantID, id, since, queryInt(r, "limit", 500, 5000))
	if err != nil {
		a.storeErr(w, err)
		return
	}
	out := make([]map[string]any, 0, len(samples))
	for _, m := range samples {
		out = append(out, map[string]any{"at": m.At, "cpu_pct": m.CPUPct, "mem_pct": m.MemPct, "disk_pct": m.DiskPct})
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *API) listAlertRules(w http.ResponseWriter, r *http.Request) {
	rules, err := a.Store.ListAlertRules(r.Context(), principalFrom(r).TenantID)
	if err != nil {
		a.storeErr(w, err)
		return
	}
	out := make([]map[string]any, 0, len(rules))
	for _, ru := range rules {
		out = append(out, map[string]any{
			"id": ru.ID.String(), "name": ru.Name, "metric": ru.Metric, "op": ru.Op,
			"threshold": ru.Threshold, "duration_seconds": ru.DurationSeconds, "enabled": ru.Enabled,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *API) createAlertRule(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name            string  `json:"name"`
		Metric          string  `json:"metric"`
		Op              string  `json:"op"`
		Threshold       float64 `json:"threshold"`
		DurationSeconds int     `json:"duration_seconds"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	rule := store.AlertRule{Name: strings.TrimSpace(req.Name), Metric: req.Metric, Op: req.Op,
		Threshold: req.Threshold, DurationSeconds: req.DurationSeconds, Enabled: true}
	if !validAlertRule(w, rule) {
		return
	}
	p := principalFrom(r)
	id, err := a.Store.CreateAlertRule(r.Context(), p.TenantID, rule)
	if err != nil {
		a.storeErr(w, err)
		return
	}
	a.audit(r, p, "alert_rule.create", "alert_rule", id.String(), map[string]any{"metric": req.Metric, "op": req.Op, "threshold": req.Threshold}, "success")
	writeJSON(w, http.StatusCreated, map[string]string{"id": id.String()})
}

func validAlertRule(w http.ResponseWriter, r store.AlertRule) bool {
	if r.Name == "" || (r.Metric != "cpu" && r.Metric != "mem" && r.Metric != "disk") ||
		(r.Op != "gt" && r.Op != "lt") || r.Threshold < 0 || r.Threshold > 100 || r.DurationSeconds < 0 {
		writeErr(w, http.StatusBadRequest, "name, metric (cpu|mem|disk), op (gt|lt), threshold 0-100, and non-negative duration are required")
		return false
	}
	return true
}

func (a *API) updateAlertRule(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var req struct {
		Name            string  `json:"name"`
		Metric          string  `json:"metric"`
		Op              string  `json:"op"`
		Threshold       float64 `json:"threshold"`
		DurationSeconds int     `json:"duration_seconds"`
		Enabled         bool    `json:"enabled"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	rule := store.AlertRule{ID: id, Name: strings.TrimSpace(req.Name), Metric: req.Metric, Op: req.Op,
		Threshold: req.Threshold, DurationSeconds: req.DurationSeconds, Enabled: req.Enabled}
	if !validAlertRule(w, rule) {
		return
	}
	p := principalFrom(r)
	if err := a.Store.UpdateAlertRule(r.Context(), p.TenantID, rule); err != nil {
		a.storeErr(w, err)
		return
	}
	a.audit(r, p, "alert_rule.update", "alert_rule", id.String(),
		map[string]any{"metric": rule.Metric, "op": rule.Op, "threshold": rule.Threshold, "enabled": rule.Enabled}, "success")
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) deleteAlertRule(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	p := principalFrom(r)
	if err := a.Store.DeleteAlertRule(r.Context(), p.TenantID, id); err != nil {
		a.storeErr(w, err)
		return
	}
	a.audit(r, p, "alert_rule.delete", "alert_rule", id.String(), nil, "success")
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) getControls(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	c, err := a.Store.GetControls(r.Context(), principalFrom(r).TenantID, id)
	if err == store.ErrNotFound {
		c = store.DeviceControls{} // default: nothing blocked
	} else if err != nil {
		a.storeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, controlsJSON(c))
}

func controlsJSON(c store.DeviceControls) map[string]bool {
	return map[string]bool{
		"usb_storage_blocked": c.USBStorageBlocked,
		"network_blocked":     c.NetworkBlocked,
		"elevation_blocked":   c.ElevationBlocked,
	}
}

func (a *API) setControls(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var req struct {
		USBStorageBlocked bool `json:"usb_storage_blocked"`
		NetworkBlocked    bool `json:"network_blocked"`
		ElevationBlocked  bool `json:"elevation_blocked"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	c := store.DeviceControls{USBStorageBlocked: req.USBStorageBlocked, NetworkBlocked: req.NetworkBlocked, ElevationBlocked: req.ElevationBlocked}
	p := principalFrom(r)
	if err := a.Store.SetControls(r.Context(), p.TenantID, id, c); err != nil {
		a.storeErr(w, err)
		return
	}
	a.audit(r, p, "controls.set", "group", id.String(), map[string]any{
		"usb_storage_blocked": c.USBStorageBlocked, "network_blocked": c.NetworkBlocked, "elevation_blocked": c.ElevationBlocked,
	}, "success")
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) listDeviceEvents(w http.ResponseWriter, r *http.Request) {
	events, err := a.Store.ListDeviceEvents(r.Context(), principalFrom(r).TenantID, r.URL.Query().Get("kind"), queryInt(r, "limit", 200, 1000))
	if err != nil {
		a.storeErr(w, err)
		return
	}
	out := make([]map[string]any, 0, len(events))
	for _, e := range events {
		out = append(out, map[string]any{
			"id": e.ID, "device_id": e.DeviceID.String(), "kind": e.Kind, "summary": e.Summary, "at": e.At,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *API) listAlerts(w http.ResponseWriter, r *http.Request) {
	alerts, err := a.Store.ListAlerts(r.Context(), principalFrom(r).TenantID, queryInt(r, "limit", 200, 1000))
	if err != nil {
		a.storeErr(w, err)
		return
	}
	out := make([]map[string]any, 0, len(alerts))
	for _, al := range alerts {
		out = append(out, map[string]any{
			"id": al.ID, "device_id": al.DeviceID.String(), "metric": al.Metric, "message": al.Message,
			"at": al.At, "resolved_at": al.ResolvedAt,
		})
	}
	writeJSON(w, http.StatusOK, out)
}
