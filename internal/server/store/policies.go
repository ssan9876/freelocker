package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type Policy struct {
	ID        uuid.UUID
	Name      string
	Mode      string
	CreatedAt time.Time
}

type PolicyRule struct {
	ID            uuid.UUID
	Kind          string
	Value         string
	PublisherName string
	Description   string
	CreatedAt     time.Time
}

type PolicyVersion struct {
	PolicyID  uuid.UUID
	Version   string
	Mode      string
	XML       []byte
	Signature []byte
	CreatedAt time.Time
}

func (s *Store) CreatePolicy(ctx context.Context, tenantID uuid.UUID, name, mode string) (uuid.UUID, error) {
	if mode == "" {
		mode = "audit"
	}
	id := uuid.New()
	_, err := s.pool.Exec(ctx, `INSERT INTO policies (id, tenant_id, name, mode) VALUES ($1,$2,$3,$4)`, id, tenantID, name, mode)
	return id, conflict(err)
}

func (s *Store) ListPolicies(ctx context.Context, tenantID uuid.UUID) ([]Policy, error) {
	rows, _ := s.pool.Query(ctx, `SELECT id, name, mode, created_at FROM policies WHERE tenant_id=$1 ORDER BY name`, tenantID)
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Policy, error) {
		var p Policy
		return p, r.Scan(&p.ID, &p.Name, &p.Mode, &p.CreatedAt)
	})
}

func (s *Store) GetPolicy(ctx context.Context, tenantID, id uuid.UUID) (Policy, error) {
	var p Policy
	err := s.pool.QueryRow(ctx, `SELECT id, name, mode, created_at FROM policies WHERE tenant_id=$1 AND id=$2`, tenantID, id).
		Scan(&p.ID, &p.Name, &p.Mode, &p.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	return p, err
}

func (s *Store) SetPolicyMode(ctx context.Context, tenantID, id uuid.UUID, mode string) error {
	return oneRow(s.pool.Exec(ctx, `UPDATE policies SET mode=$3 WHERE tenant_id=$1 AND id=$2`, tenantID, id, mode))
}

func (s *Store) DeletePolicy(ctx context.Context, tenantID, id uuid.UUID) error {
	return oneRow(s.pool.Exec(ctx, `DELETE FROM policies WHERE tenant_id=$1 AND id=$2`, tenantID, id))
}

func (s *Store) AddRule(ctx context.Context, tenantID, policyID uuid.UUID, r PolicyRule, addedBy *uuid.UUID) (uuid.UUID, error) {
	id := uuid.New()
	_, err := s.pool.Exec(ctx, `
		INSERT INTO policy_rules (id, tenant_id, policy_id, kind, value, publisher_name, description, added_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		id, tenantID, policyID, r.Kind, r.Value, r.PublisherName, r.Description, addedBy)
	return id, conflict(err)
}

func (s *Store) ListRules(ctx context.Context, tenantID, policyID uuid.UUID) ([]PolicyRule, error) {
	rows, _ := s.pool.Query(ctx, `
		SELECT id, kind, value, publisher_name, description, created_at
		FROM policy_rules WHERE tenant_id=$1 AND policy_id=$2 ORDER BY kind, value`, tenantID, policyID)
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (PolicyRule, error) {
		var pr PolicyRule
		return pr, r.Scan(&pr.ID, &pr.Kind, &pr.Value, &pr.PublisherName, &pr.Description, &pr.CreatedAt)
	})
}

func (s *Store) DeleteRule(ctx context.Context, tenantID, policyID, ruleID uuid.UUID) error {
	return oneRow(s.pool.Exec(ctx, `DELETE FROM policy_rules WHERE tenant_id=$1 AND policy_id=$2 AND id=$3`, tenantID, policyID, ruleID))
}

func (s *Store) PutPolicyVersion(ctx context.Context, tenantID uuid.UUID, v PolicyVersion) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO policy_versions (tenant_id, policy_id, version, mode, xml, signature)
		VALUES ($1,$2,$3,$4,$5,$6)
		ON CONFLICT (policy_id, version) DO UPDATE SET mode=EXCLUDED.mode, xml=EXCLUDED.xml, signature=EXCLUDED.signature, created_at=now()`,
		tenantID, v.PolicyID, v.Version, v.Mode, v.XML, v.Signature)
	return err
}

func (s *Store) LatestPolicyVersion(ctx context.Context, tenantID, policyID uuid.UUID) (PolicyVersion, error) {
	var v PolicyVersion
	err := s.pool.QueryRow(ctx, `
		SELECT policy_id, version, mode, xml, signature, created_at
		FROM policy_versions WHERE tenant_id=$1 AND policy_id=$2 ORDER BY created_at DESC LIMIT 1`, tenantID, policyID).
		Scan(&v.PolicyID, &v.Version, &v.Mode, &v.XML, &v.Signature, &v.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	return v, err
}

// AssignPolicy points a group at a policy. Both must belong to the caller's
// tenant: ErrNotFound otherwise.
//
// policy_assignments has group_id as its SOLE primary key, so the guards here
// are load-bearing. Without the EXISTS checks one tenant could name another's
// group, and without the tenant predicate on the ON CONFLICT branch the
// UPDATE would silently repoint an existing assignment belonging to someone
// else — leaving that tenant's devices pointing at a policy outside their
// tenant, which resolves to no policy at all.
func (s *Store) AssignPolicy(ctx context.Context, tenantID, groupID, policyID uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `
		INSERT INTO policy_assignments (tenant_id, group_id, policy_id)
		SELECT $1, $2, $3
		WHERE EXISTS (SELECT 1 FROM device_groups WHERE tenant_id = $1 AND id = $2)
		  AND EXISTS (SELECT 1 FROM policies      WHERE tenant_id = $1 AND id = $3)
		ON CONFLICT (group_id) DO UPDATE SET policy_id = EXCLUDED.policy_id
		  WHERE policy_assignments.tenant_id = $1`, tenantID, groupID, policyID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// EffectivePolicyForDevice returns the latest version for the policy
// assigned to the device's group, or ErrNotFound if the device has no
// group or no assignment/version.
func (s *Store) EffectivePolicyForDevice(ctx context.Context, tenantID, deviceID uuid.UUID) (PolicyVersion, error) {
	var v PolicyVersion
	err := s.pool.QueryRow(ctx, `
		SELECT pv.policy_id, pv.version, pv.mode, pv.xml, pv.signature, pv.created_at
		FROM devices d
		JOIN policy_assignments pa ON pa.group_id = d.group_id AND pa.tenant_id = d.tenant_id
		JOIN policy_versions pv ON pv.policy_id = pa.policy_id AND pv.tenant_id = d.tenant_id
		WHERE d.tenant_id=$1 AND d.id=$2
		ORDER BY pv.created_at DESC LIMIT 1`, tenantID, deviceID).
		Scan(&v.PolicyID, &v.Version, &v.Mode, &v.XML, &v.Signature, &v.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	return v, err
}

func (s *Store) SetDevicePolicyVersion(ctx context.Context, tenantID, deviceID uuid.UUID, version string) error {
	return oneRow(s.pool.Exec(ctx, `UPDATE devices SET policy_version=$3 WHERE tenant_id=$1 AND id=$2`, tenantID, deviceID, version))
}
