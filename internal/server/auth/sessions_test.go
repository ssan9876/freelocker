package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"freelocker/internal/server/store"
	"freelocker/internal/server/store/storetest"
)

func TestSessionCreateLoadDestroy(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	tenant, _ := s.CreateTenant(ctx, "Acme")
	admin, _ := s.CreateAdmin(ctx, tenant, store.Admin{Email: "a@example.com", PasswordHash: "h", Role: "owner"})
	m := &Sessions{Store: s, Secure: true}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/login", nil)
	sess, err := m.Create(ctx, rec, req, tenant, admin)
	if err != nil || sess.CSRFToken == "" {
		t.Fatalf("Create = %+v, %v", sess, err)
	}
	cookie := rec.Result().Cookies()[0]
	if cookie.Name != CookieName || !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteStrictMode {
		t.Errorf("cookie flags wrong: %+v", cookie)
	}
	if cookie.Value == sess.ID {
		t.Error("DB session id must be a hash, not the cookie token")
	}

	req2 := httptest.NewRequest("GET", "/api/me", nil)
	req2.AddCookie(cookie)
	got, err := m.Load(ctx, req2)
	if err != nil || got.AdminID != admin {
		t.Fatalf("Load = %+v, %v", got, err)
	}

	m.Destroy(ctx, httptest.NewRecorder(), req2)
	if _, err := m.Load(ctx, req2); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("after destroy err = %v", err)
	}
	if _, err := m.Load(ctx, httptest.NewRequest("GET", "/", nil)); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("no cookie err = %v", err)
	}
}
