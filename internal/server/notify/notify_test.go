package notify_test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"freelocker/internal/server/config"
	"freelocker/internal/server/keys"
	"freelocker/internal/server/notify"
	"freelocker/internal/server/store"
	"freelocker/internal/server/store/storetest"

	"github.com/google/uuid"
)

type fakeMailer struct {
	mu   sync.Mutex
	sent []struct {
		To            []string
		Subject, Body string
	}
	err error
}

func (m *fakeMailer) Send(_ context.Context, to []string, subject, body string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	m.sent = append(m.sent, struct {
		To            []string
		Subject, Body string
	}{to, subject, body})
	return nil
}

type fx struct {
	s      *store.Store
	tenant uuid.UUID
	svc    *notify.Service
	mail   *fakeMailer
	sealer *keys.Sealer
	now    time.Time
}

func newFx(t *testing.T) *fx {
	t.Helper()
	s := storetest.New(t)
	tenant, _ := s.CreateTenant(context.Background(), "Acme")
	sealer, _ := keys.NewSealer(bytes.Repeat([]byte{9}, 32), "notify")
	f := &fx{s: s, tenant: tenant, mail: &fakeMailer{}, sealer: sealer, now: time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)}
	f.svc = notify.New(s, sealer, config.SMTP{Host: "mail", From: "fl@example.com"}, nil)
	f.svc.Mailer = f.mail
	f.svc.Now = func() time.Time { return f.now }
	return f
}

func (f *fx) webhook(t *testing.T, name, url, secret string, events ...string) store.NotificationChannel {
	t.Helper()
	c := store.NotificationChannel{ID: uuid.New(), Kind: "webhook", Name: name, Events: events, Enabled: true, URL: url}
	if secret != "" {
		c.Secret = f.sealer.Seal([]byte(secret))
	}
	if err := f.s.CreateChannel(context.Background(), f.tenant, c); err != nil {
		t.Fatal(err)
	}
	return c
}

func (f *fx) email(t *testing.T, name string, to []string, events ...string) store.NotificationChannel {
	t.Helper()
	c := store.NotificationChannel{ID: uuid.New(), Kind: "email", Name: name, Events: events, Enabled: true, Recipients: to}
	if err := f.s.CreateChannel(context.Background(), f.tenant, c); err != nil {
		t.Fatal(err)
	}
	return c
}

func (f *fx) event(kind string) notify.Event {
	return notify.Event{Kind: kind, TenantID: f.tenant, Title: "CPU high on pc-1", Body: "cpu 95% above 90%", Detail: map[string]any{"hostname": "pc-1"}, At: f.now}
}

type received struct {
	mu      sync.Mutex
	bodies  [][]byte
	headers []http.Header
}

func receiver(t *testing.T, status int, rec *received) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		rec.mu.Lock()
		rec.bodies = append(rec.bodies, b)
		rec.headers = append(rec.headers, r.Header.Clone())
		rec.mu.Unlock()
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestWebhookSignedAndSent(t *testing.T) {
	f := newFx(t)
	rec := &received{}
	srv := receiver(t, 200, rec)
	f.webhook(t, "hook", srv.URL+"/in", "topsecret", "alert.raised")
	f.email(t, "mail", []string{"ops@example.com"}, "alert.raised")
	f.webhook(t, "other", srv.URL+"/no", "", "approval.new") // not subscribed

	f.svc.Emit(context.Background(), f.event("alert.raised"))
	sent, failed, err := f.svc.Dispatch(context.Background())
	if err != nil || sent != 2 || failed != 0 {
		t.Fatalf("dispatch = %d sent, %d failed, %v", sent, failed, err)
	}
	if len(rec.bodies) != 1 {
		t.Fatalf("receiver got %d requests", len(rec.bodies))
	}
	h := rec.headers[0]
	mac := hmac.New(sha256.New, []byte("topsecret"))
	mac.Write(rec.bodies[0])
	if want := "sha256=" + hex.EncodeToString(mac.Sum(nil)); h.Get("X-FreeLocker-Signature") != want {
		t.Errorf("signature = %q, want %q", h.Get("X-FreeLocker-Signature"), want)
	}
	if h.Get("X-FreeLocker-Event") != "alert.raised" || h.Get("X-FreeLocker-Delivery") == "" || h.Get("Content-Type") != "application/json" {
		t.Errorf("headers = %v", h)
	}
	var ev notify.Event
	if err := json.Unmarshal(rec.bodies[0], &ev); err != nil || ev.Kind != "alert.raised" || ev.Title != "CPU high on pc-1" || ev.Detail["hostname"] != "pc-1" {
		t.Errorf("body = %s (%v)", rec.bodies[0], err)
	}
	if len(f.mail.sent) != 1 || f.mail.sent[0].Subject != "[FreeLocker] CPU high on pc-1" || f.mail.sent[0].To[0] != "ops@example.com" || !bytes.Contains([]byte(f.mail.sent[0].Body), []byte("cpu 95% above 90%")) {
		t.Errorf("mail = %+v", f.mail.sent)
	}
	list, _ := f.s.ListDeliveries(context.Background(), f.tenant, 10)
	if len(list) != 2 || list[0].State != "sent" || list[1].State != "sent" {
		t.Errorf("deliveries = %+v", list)
	}
}

func TestWebhookNoSecretNoSignatureHeader(t *testing.T) {
	f := newFx(t)
	rec := &received{}
	srv := receiver(t, 204, rec)
	f.webhook(t, "hook", srv.URL, "", "alert.raised")
	f.svc.Emit(context.Background(), f.event("alert.raised"))
	f.svc.Dispatch(context.Background())
	if len(rec.headers) != 1 || rec.headers[0].Get("X-FreeLocker-Signature") != "" {
		t.Errorf("headers = %v", rec.headers)
	}
}

func TestWebhookRetryBackoffThenFailed(t *testing.T) {
	f := newFx(t)
	rec := &received{}
	srv := receiver(t, 500, rec)
	f.webhook(t, "hook", srv.URL, "", "alert.raised")
	f.svc.Emit(context.Background(), f.event("alert.raised"))
	ctx := context.Background()

	wantNext := []time.Duration{time.Minute, 5 * time.Minute, 30 * time.Minute, 30 * time.Minute}
	for i, d := range wantNext {
		sent, failed, _ := f.svc.Dispatch(ctx)
		if sent != 0 || failed != 0 {
			t.Fatalf("attempt %d: sent=%d failed=%d (a retry is neither)", i+1, sent, failed)
		}
		list, _ := f.s.ListDeliveries(ctx, f.tenant, 1)
		if list[0].State != "pending" || list[0].Attempts != i+1 || !list[0].NextAttemptAt.Equal(f.now.Add(d)) || list[0].LastError == "" {
			t.Fatalf("after attempt %d: %+v (want next +%s)", i+1, list[0], d)
		}
		f.now = f.now.Add(d)
	}
	_, failed, _ := f.svc.Dispatch(ctx)
	list, _ := f.s.ListDeliveries(ctx, f.tenant, 1)
	if failed != 1 || list[0].State != "failed" || list[0].Attempts != 5 {
		t.Fatalf("final = failed %d, row %+v", failed, list[0])
	}
	if len(rec.bodies) != 5 {
		t.Errorf("receiver got %d requests, want 5", len(rec.bodies))
	}
}

func TestWebhookDoesNotFollowRedirect(t *testing.T) {
	f := newFx(t)
	hit := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit++
		http.Redirect(w, r, "/elsewhere", http.StatusFound)
	}))
	t.Cleanup(srv.Close)
	f.webhook(t, "hook", srv.URL, "", "alert.raised")
	f.svc.Emit(context.Background(), f.event("alert.raised"))
	f.svc.Dispatch(context.Background())
	list, _ := f.s.ListDeliveries(context.Background(), f.tenant, 1)
	if hit != 1 || list[0].State != "pending" {
		t.Errorf("hits=%d row=%+v (302 must count as failure, not be followed)", hit, list[0])
	}
}

func TestDisabledOrDeletedChannelFails(t *testing.T) {
	f := newFx(t)
	rec := &received{}
	srv := receiver(t, 200, rec)
	c := f.webhook(t, "hook", srv.URL, "", "alert.raised")
	f.svc.Emit(context.Background(), f.event("alert.raised"))
	c.Enabled = false
	f.s.UpdateChannel(context.Background(), f.tenant, c)
	_, failed, _ := f.svc.Dispatch(context.Background())
	list, _ := f.s.ListDeliveries(context.Background(), f.tenant, 1)
	if failed != 1 || list[0].State != "failed" || len(rec.bodies) != 0 {
		t.Errorf("disabled: failed=%d row=%+v hits=%d", failed, list[0], len(rec.bodies))
	}
}

func TestEmitNoSubscribersInsertsNothing(t *testing.T) {
	f := newFx(t)
	f.svc.Emit(context.Background(), f.event("alert.raised"))
	list, _ := f.s.ListDeliveries(context.Background(), f.tenant, 10)
	if len(list) != 0 {
		t.Errorf("deliveries = %+v", list)
	}
}

func TestMailerErrorRetries(t *testing.T) {
	f := newFx(t)
	f.mail.err = io.ErrUnexpectedEOF
	f.email(t, "mail", []string{"a@b.c"}, "alert.raised")
	f.svc.Emit(context.Background(), f.event("alert.raised"))
	f.svc.Dispatch(context.Background())
	list, _ := f.s.ListDeliveries(context.Background(), f.tenant, 1)
	if list[0].State != "pending" || list[0].LastError == "" {
		t.Errorf("row = %+v", list[0])
	}
}

func TestEmailWithoutSMTPFails(t *testing.T) {
	f := newFx(t)
	f.svc.SMTP = config.SMTP{}
	f.email(t, "mail", []string{"a@b.c"}, "alert.raised")
	f.svc.Emit(context.Background(), f.event("alert.raised"))
	_, failed, _ := f.svc.Dispatch(context.Background())
	list, _ := f.s.ListDeliveries(context.Background(), f.tenant, 1)
	if failed != 1 || list[0].State != "failed" || list[0].LastError != "smtp is not configured on this server" {
		t.Errorf("row = %+v", list[0])
	}
}

func TestTestSendReturnsReceiverError(t *testing.T) {
	f := newFx(t)
	rec := &received{}
	srv := receiver(t, 401, rec)
	c := f.webhook(t, "hook", srv.URL, "s", "alert.raised")
	if err := f.svc.Test(context.Background(), c); err == nil || !bytes.Contains([]byte(err.Error()), []byte("401")) {
		t.Errorf("test err = %v", err)
	}
	ok := receiver(t, 200, rec)
	c.URL = ok.URL
	if err := f.svc.Test(context.Background(), c); err != nil {
		t.Errorf("test ok err = %v", err)
	}
	if list, _ := f.s.ListDeliveries(context.Background(), f.tenant, 10); len(list) != 0 {
		t.Errorf("test sends must not be recorded: %+v", list)
	}
	var ev notify.Event
	json.Unmarshal(rec.bodies[len(rec.bodies)-1], &ev)
	if ev.Kind != "notify.test" {
		t.Errorf("test event kind = %q", ev.Kind)
	}
}

func TestBackoff(t *testing.T) {
	for _, tc := range []struct {
		attempt int
		next    time.Duration
		giveUp  bool
	}{{1, time.Minute, false}, {2, 5 * time.Minute, false}, {3, 30 * time.Minute, false}, {4, 30 * time.Minute, false}, {5, 0, true}, {9, 0, true}} {
		next, giveUp := notify.Backoff(tc.attempt)
		if next != tc.next || giveUp != tc.giveUp {
			t.Errorf("Backoff(%d) = %s, %v", tc.attempt, next, giveUp)
		}
	}
}
