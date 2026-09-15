package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"freelocker/internal/server/store"

	"github.com/google/uuid"
)

type channelJSON struct {
	ID         string    `json:"id"`
	Kind       string    `json:"kind"`
	Name       string    `json:"name"`
	Events     []string  `json:"events"`
	Enabled    bool      `json:"enabled"`
	Recipients []string  `json:"recipients"`
	URL        string    `json:"url"`
	HasSecret  bool      `json:"has_secret"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

func toChannelJSON(c store.NotificationChannel) channelJSON {
	return channelJSON{ID: c.ID.String(), Kind: c.Kind, Name: c.Name, Events: c.Events, Enabled: c.Enabled, Recipients: c.Recipients, URL: c.URL, HasSecret: len(c.Secret) > 0, CreatedAt: c.CreatedAt, UpdatedAt: c.UpdatedAt}
}

func (a *API) notificationStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"smtp_configured": a.SMTPConfigured, "event_kinds": store.EventKinds})
}

func (a *API) listChannels(w http.ResponseWriter, r *http.Request) {
	list, err := a.Store.ListChannels(r.Context(), principalFrom(r).TenantID)
	if err != nil {
		a.storeErr(w, err)
		return
	}
	out := make([]channelJSON, 0, len(list))
	for _, c := range list {
		out = append(out, toChannelJSON(c))
	}
	writeJSON(w, http.StatusOK, out)
}

type channelReq struct {
	Kind       *string  `json:"kind"`
	Name       *string  `json:"name"`
	Events     []string `json:"events"`
	Enabled    *bool    `json:"enabled"`
	Recipients []string `json:"recipients"`
	URL        *string  `json:"url"`
	Secret     *string  `json:"secret"`
}

// channelErr maps validation, smtp-gate and store errors to responses.
func (a *API) channelErr(w http.ResponseWriter, err error) {
	var ve *store.ValidationError
	if errors.As(err, &ve) {
		writeErr(w, http.StatusBadRequest, ve.Msg)
		return
	}
	a.storeErr(w, err)
}

func (a *API) createChannel(w http.ResponseWriter, r *http.Request) {
	var req channelReq
	if !readJSON(w, r, &req) {
		return
	}
	p := principalFrom(r)
	c := store.NotificationChannel{ID: uuid.New(), Enabled: true, Events: req.Events, Recipients: req.Recipients}
	if req.Kind != nil {
		c.Kind = *req.Kind
	}
	if req.Name != nil {
		c.Name = *req.Name
	}
	if req.URL != nil {
		c.URL = *req.URL
	}
	if req.Enabled != nil {
		c.Enabled = *req.Enabled
	}
	if req.Secret != nil && *req.Secret != "" {
		c.Secret = a.NotifySealer.Seal([]byte(*req.Secret))
	}
	if err := store.ValidateChannel(c); err != nil {
		a.channelErr(w, err)
		return
	}
	if c.Kind == "email" && !a.SMTPConfigured {
		writeErr(w, http.StatusBadRequest, "smtp is not configured on this server")
		return
	}
	if err := a.Store.CreateChannel(r.Context(), p.TenantID, c); err != nil {
		a.channelErr(w, err)
		return
	}
	a.audit(r, p, "notification_channel.create", "notification_channel", c.ID.String(), map[string]any{"kind": c.Kind, "name": c.Name, "events": c.Events}, "success")
	writeJSON(w, http.StatusCreated, map[string]string{"id": c.ID.String()})
}

func (a *API) updateChannel(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	p := principalFrom(r)
	c, err := a.Store.GetChannel(r.Context(), p.TenantID, id)
	if err != nil {
		a.storeErr(w, err)
		return
	}
	// Decode into a raw map to learn whether "secret" was present at all
	// (null clears, "" keeps, non-empty replaces, absent keeps).
	var raw map[string]any
	if !readJSON(w, r, &raw) {
		return
	}
	if v, ok := raw["name"].(string); ok {
		c.Name = v
	}
	if v, ok := raw["url"].(string); ok {
		c.URL = v
	}
	if v, ok := raw["enabled"].(bool); ok {
		c.Enabled = v
	}
	if v, ok := raw["events"].([]any); ok {
		c.Events = toStrings(v)
	}
	if v, ok := raw["recipients"].([]any); ok {
		c.Recipients = toStrings(v)
	}
	if sv, present := raw["secret"]; present {
		switch s := sv.(type) {
		case nil:
			c.Secret = []byte{}
		case string:
			if s != "" {
				c.Secret = a.NotifySealer.Seal([]byte(s))
			}
		}
	}
	if err := store.ValidateChannel(c); err != nil {
		a.channelErr(w, err)
		return
	}
	if c.Kind == "email" && c.Enabled && !a.SMTPConfigured {
		writeErr(w, http.StatusBadRequest, "smtp is not configured on this server")
		return
	}
	if err := a.Store.UpdateChannel(r.Context(), p.TenantID, c); err != nil {
		a.channelErr(w, err)
		return
	}
	a.audit(r, p, "notification_channel.update", "notification_channel", id.String(), map[string]any{"name": c.Name, "enabled": c.Enabled, "events": c.Events}, "success")
	w.WriteHeader(http.StatusNoContent)
}

func toStrings(v []any) []string {
	out := make([]string, 0, len(v))
	for _, x := range v {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func (a *API) deleteChannel(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	p := principalFrom(r)
	if err := a.Store.DeleteChannel(r.Context(), p.TenantID, id); err != nil {
		a.storeErr(w, err)
		return
	}
	a.audit(r, p, "notification_channel.delete", "notification_channel", id.String(), nil, "success")
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) testChannel(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	p := principalFrom(r)
	c, err := a.Store.GetChannel(r.Context(), p.TenantID, id)
	if err != nil {
		a.storeErr(w, err)
		return
	}
	result := "success"
	out := map[string]any{"ok": true}
	if err := a.Runtime().Notify.Test(r.Context(), c); err != nil {
		result = "failure"
		out = map[string]any{"ok": false, "error": err.Error()}
	}
	a.audit(r, p, "notification_channel.test", "notification_channel", id.String(), map[string]any{"name": c.Name}, result)
	writeJSON(w, http.StatusOK, out)
}

func (a *API) listDeliveries(w http.ResponseWriter, r *http.Request) {
	list, err := a.Store.ListDeliveries(r.Context(), principalFrom(r).TenantID, queryInt(r, "limit", 50, 500))
	if err != nil {
		a.storeErr(w, err)
		return
	}
	out := make([]map[string]any, 0, len(list))
	for _, d := range list {
		var ev struct {
			Title string `json:"title"`
		}
		_ = json.Unmarshal(d.Payload, &ev)
		out = append(out, map[string]any{
			"id": d.ID, "channel_id": d.ChannelID.String(), "channel_name": d.ChannelName, "event_kind": d.EventKind, "title": ev.Title,
			"state": d.State, "attempts": d.Attempts, "last_error": d.LastError, "created_at": d.CreatedAt, "sent_at": d.SentAt, "next_attempt_at": d.NextAttemptAt,
		})
	}
	writeJSON(w, http.StatusOK, out)
}
