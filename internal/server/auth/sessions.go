package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net"
	"net/http"
	"time"

	"freelocker/internal/server/store"

	"github.com/google/uuid"
)

const (
	CookieName = "fl_session"
	SessionTTL = 12 * time.Hour
)

type Sessions struct {
	Store  *store.Store
	Now    func() time.Time
	Secure bool
}

func (m *Sessions) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

func randToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func hashToken(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(sum[:])
}

// ClientIP returns the request's remote IP without the port.
func ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (m *Sessions) Create(ctx context.Context, w http.ResponseWriter, r *http.Request, tenantID, adminID uuid.UUID) (store.Session, error) {
	tok := randToken()
	sess := store.Session{
		ID: hashToken(tok), TenantID: tenantID, AdminID: adminID, CSRFToken: randToken(),
		ExpiresAt: m.now().Add(SessionTTL), IP: ClientIP(r), UserAgent: r.UserAgent(),
	}
	if err := m.Store.CreateSession(ctx, sess); err != nil {
		return store.Session{}, err
	}
	http.SetCookie(w, &http.Cookie{
		Name: CookieName, Value: tok, Path: "/", Expires: sess.ExpiresAt,
		HttpOnly: true, Secure: m.Secure, SameSite: http.SameSiteStrictMode,
	})
	return sess, nil
}

func (m *Sessions) Load(ctx context.Context, r *http.Request) (store.Session, error) {
	c, err := r.Cookie(CookieName)
	if err != nil || c.Value == "" {
		return store.Session{}, store.ErrNotFound
	}
	return m.Store.GetSession(ctx, hashToken(c.Value), m.now())
}

func (m *Sessions) Destroy(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(CookieName); err == nil {
		m.Store.DeleteSession(ctx, hashToken(c.Value))
	}
	http.SetCookie(w, &http.Cookie{Name: CookieName, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: m.Secure, SameSite: http.SameSiteStrictMode})
}
