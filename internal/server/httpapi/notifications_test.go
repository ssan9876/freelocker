package httpapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

type channelJSON struct {
	ID         string   `json:"id"`
	Kind       string   `json:"kind"`
	Name       string   `json:"name"`
	Events     []string `json:"events"`
	Enabled    bool     `json:"enabled"`
	Recipients []string `json:"recipients"`
	URL        string   `json:"url"`
	HasSecret  bool     `json:"has_secret"`
}

func TestNotificationChannelsOverHTTP(t *testing.T) {
	e := newEnv(t)
	c := e.initialized(t)

	var st struct {
		SMTPConfigured bool     `json:"smtp_configured"`
		EventKinds     []string `json:"event_kinds"`
	}
	if code := c.do("GET", "/api/notifications/status", nil, &st); code != 200 || st.SMTPConfigured || len(st.EventKinds) != 5 {
		t.Fatalf("status = %d %+v", code, st)
	}

	// Validation + smtp gate.
	if code := c.do("POST", "/api/notification-channels", map[string]any{"kind": "webhook", "name": "x", "events": []string{"alert.raised"}, "url": "ftp://nope"}, nil); code != 400 {
		t.Errorf("bad url = %d", code)
	}
	if code := c.do("POST", "/api/notification-channels", map[string]any{"kind": "email", "name": "mail", "events": []string{"alert.raised"}, "recipients": []string{"a@b.c"}}, nil); code != 400 {
		t.Errorf("email without smtp = %d, want 400", code)
	}

	hits := 0
	var gotSig string
	recv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		gotSig = r.Header.Get("X-FreeLocker-Signature")
		w.WriteHeader(200)
	}))
	defer recv.Close()

	var created idResp
	body := map[string]any{"kind": "webhook", "name": "Slack", "events": []string{"alert.raised", "approval.new"}, "url": recv.URL, "secret": "s3cret"}
	if code := c.do("POST", "/api/notification-channels", body, &created); code != 201 {
		t.Fatalf("create = %d", code)
	}
	if code := c.do("POST", "/api/notification-channels", body, nil); code != 409 {
		t.Errorf("dup name = %d", code)
	}
	var list []channelJSON
	c.do("GET", "/api/notification-channels", nil, &list)
	if len(list) != 1 || list[0].Name != "Slack" || !list[0].HasSecret || !list[0].Enabled || len(list[0].Events) != 2 || list[0].Recipients == nil {
		t.Fatalf("list = %+v", list)
	}

	// Test send: signed, hits the receiver, not recorded.
	var tr struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if code := c.do("POST", "/api/notification-channels/"+created.ID+"/test", nil, &tr); code != 200 || !tr.OK || hits != 1 || gotSig == "" {
		t.Fatalf("test = %d %+v hits=%d sig=%q", code, tr, hits, gotSig)
	}
	var dl []map[string]any
	c.do("GET", "/api/notification-deliveries", nil, &dl)
	if len(dl) != 0 {
		t.Errorf("test send recorded: %+v", dl)
	}

	// Patch: disable, keep secret with "", clear with null.
	if code := c.do("PATCH", "/api/notification-channels/"+created.ID, map[string]any{"enabled": false, "secret": ""}, nil); code != 204 {
		t.Errorf("patch = %d", code)
	}
	c.do("GET", "/api/notification-channels", nil, &list)
	if list[0].Enabled || !list[0].HasSecret {
		t.Errorf("after patch = %+v", list[0])
	}
	if code := c.do("PATCH", "/api/notification-channels/"+created.ID, map[string]any{"secret": nil}, nil); code != 204 {
		t.Errorf("clear secret = %d", code)
	}
	c.do("GET", "/api/notification-channels", nil, &list)
	if list[0].HasSecret {
		t.Errorf("secret not cleared: %+v", list[0])
	}
	// Test on a disabled channel still sends (admin is explicitly asking).
	c.do("POST", "/api/notification-channels/"+created.ID+"/test", nil, &tr)
	if !tr.OK || hits != 2 {
		t.Errorf("test disabled = %+v hits=%d", tr, hits)
	}
	// Failing receiver → ok:false with the error, status still 200.
	recv.Close()
	if code := c.do("POST", "/api/notification-channels/"+created.ID+"/test", nil, &tr); code != 200 || tr.OK || tr.Error == "" {
		t.Errorf("test failing = %d %+v", code, tr)
	}

	if code := c.do("DELETE", "/api/notification-channels/"+created.ID, nil, nil); code != 204 {
		t.Errorf("delete = %d", code)
	}
	c.do("GET", "/api/notification-channels", nil, &list)
	if len(list) != 0 {
		t.Errorf("after delete = %+v", list)
	}

	// Audit trail, no secret in detail.
	k := e.rt().Keys
	entries, _ := e.store.ListAudit(context.Background(), k.TenantID, 100, 0)
	seen := map[string]bool{}
	for _, en := range entries {
		seen[en.Action] = true
		if b, _ := json.Marshal(en.Detail); bytes.Contains(b, []byte("s3cret")) {
			t.Errorf("secret leaked into audit: %s", b)
		}
	}
	for _, a := range []string{"notification_channel.create", "notification_channel.update", "notification_channel.delete", "notification_channel.test"} {
		if !seen[a] {
			t.Errorf("missing audit %s", a)
		}
	}
}

func TestNotificationRbac(t *testing.T) {
	e := newEnv(t)
	owner := e.initialized(t)
	owner.do("POST", "/api/admins", map[string]string{"email": "ro@example.com", "password": "readonly-password-1", "role": "readonly"}, nil)
	ro := e.client(t)
	ro.loginFull("ro@example.com", "readonly-password-1", "")
	if code := ro.do("GET", "/api/notification-channels", nil, nil); code != 200 {
		t.Errorf("readonly list = %d", code)
	}
	if code := ro.do("POST", "/api/notification-channels", map[string]any{"kind": "webhook", "name": "x", "events": []string{"alert.raised"}, "url": "https://h"}, nil); code != 403 {
		t.Errorf("readonly create = %d", code)
	}
}
