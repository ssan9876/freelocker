package store

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type Admin struct {
	ID            uuid.UUID
	Email         string
	PasswordHash  string
	TOTPSecretEnc []byte
	TOTPConfirmed bool
	Role          string
	Disabled      bool
	Provider      bool
	CreatedAt     time.Time
}

type Session struct {
	ID        string
	TenantID  uuid.UUID
	AdminID   uuid.UUID
	CSRFToken string
	MFAPassed bool
	ExpiresAt time.Time
	IP        string
	UserAgent string
}

const adminCols = `id, email, password_hash, totp_secret_enc, totp_confirmed, role, disabled, provider, created_at`

func scanAdmin(r pgx.Row) (Admin, error) {
	var a Admin
	err := r.Scan(&a.ID, &a.Email, &a.PasswordHash, &a.TOTPSecretEnc, &a.TOTPConfirmed, &a.Role, &a.Disabled, &a.Provider, &a.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	return a, err
}

func (s *Store) CreateAdmin(ctx context.Context, tenantID uuid.UUID, a Admin) (uuid.UUID, error) {
	id := uuid.New()
	_, err := s.pool.Exec(ctx, `INSERT INTO admins (id, tenant_id, email, password_hash, role, provider) VALUES ($1, $2, $3, $4, $5, $6)`,
		id, tenantID, strings.ToLower(a.Email), a.PasswordHash, a.Role, a.Provider)
	return id, conflict(err)
}

func (s *Store) GetAdmin(ctx context.Context, tenantID, id uuid.UUID) (Admin, error) {
	return scanAdmin(s.pool.QueryRow(ctx, `SELECT `+adminCols+` FROM admins WHERE tenant_id = $1 AND id = $2`, tenantID, id))
}

func (s *Store) GetAdminByEmail(ctx context.Context, tenantID uuid.UUID, email string) (Admin, error) {
	return scanAdmin(s.pool.QueryRow(ctx, `SELECT `+adminCols+` FROM admins WHERE tenant_id = $1 AND email = $2`,
		tenantID, strings.ToLower(email)))
}

// GetAdminByEmailGlobal resolves an admin and its tenant by globally-unique
// email. Login uses it because the tenant is not known until the admin is
// found. Email is matched case-insensitively (stored lowercased).
func (s *Store) GetAdminByEmailGlobal(ctx context.Context, email string) (Admin, uuid.UUID, error) {
	var a Admin
	var tid uuid.UUID
	err := s.pool.QueryRow(ctx, `SELECT `+adminCols+`, tenant_id FROM admins WHERE email = $1`, strings.ToLower(email)).
		Scan(&a.ID, &a.Email, &a.PasswordHash, &a.TOTPSecretEnc, &a.TOTPConfirmed, &a.Role, &a.Disabled, &a.Provider, &a.CreatedAt, &tid)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	return a, tid, err
}

func (s *Store) ListAdmins(ctx context.Context, tenantID uuid.UUID) ([]Admin, error) {
	rows, _ := s.pool.Query(ctx, `SELECT `+adminCols+` FROM admins WHERE tenant_id = $1 ORDER BY email`, tenantID)
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Admin, error) { return scanAdmin(r) })
}

func (s *Store) SetAdminTOTP(ctx context.Context, tenantID, id uuid.UUID, secretEnc []byte, confirmed bool) error {
	return oneRow(s.pool.Exec(ctx, `UPDATE admins SET totp_secret_enc = $3, totp_confirmed = $4 WHERE tenant_id = $1 AND id = $2`,
		tenantID, id, secretEnc, confirmed))
}

func (s *Store) SetAdminDisabled(ctx context.Context, tenantID, id uuid.UUID, disabled bool) error {
	return oneRow(s.pool.Exec(ctx, `UPDATE admins SET disabled = $3 WHERE tenant_id = $1 AND id = $2`, tenantID, id, disabled))
}

func (s *Store) CreateSession(ctx context.Context, sess Session) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO sessions (id, tenant_id, admin_id, csrf_token, mfa_passed, expires_at, ip, user_agent)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		sess.ID, sess.TenantID, sess.AdminID, sess.CSRFToken, sess.MFAPassed, sess.ExpiresAt, sess.IP, sess.UserAgent)
	return err
}

func (s *Store) GetSession(ctx context.Context, id string, now time.Time) (Session, error) {
	var sess Session
	err := s.pool.QueryRow(ctx, `
		SELECT id, tenant_id, admin_id, csrf_token, mfa_passed, expires_at, ip, user_agent
		FROM sessions WHERE id = $1 AND expires_at > $2`, id, now).
		Scan(&sess.ID, &sess.TenantID, &sess.AdminID, &sess.CSRFToken, &sess.MFAPassed, &sess.ExpiresAt, &sess.IP, &sess.UserAgent)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	return sess, err
}

func (s *Store) MarkSessionMFA(ctx context.Context, id string) error {
	return oneRow(s.pool.Exec(ctx, `UPDATE sessions SET mfa_passed = true WHERE id = $1`, id))
}

func (s *Store) DeleteSession(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE id = $1`, id)
	return err
}

func (s *Store) DeleteAdminSessions(ctx context.Context, tenantID, adminID uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE tenant_id = $1 AND admin_id = $2`, tenantID, adminID)
	return err
}
