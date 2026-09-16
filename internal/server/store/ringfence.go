package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Ringfence constrains what an allowed application may do. It is assigned to
// a device group independently of that group's app-control policy.
type Ringfence struct {
	ID        uuid.UUID
	Name      string
	Mode      string // audit|enforce
	CreatedAt time.Time
}

const ringfenceCols = `id, name, mode, created_at`

func scanRingfence(r pgx.Row) (Ringfence, error) {
	var o Ringfence
	err := r.Scan(&o.ID, &o.Name, &o.Mode, &o.CreatedAt)
	return o, err
}

func (s *Store) CreateRingfence(ctx context.Context, tenantID uuid.UUID, r Ringfence) error {
	if r.Mode == "" {
		r.Mode = "audit"
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO ringfence_policies (id, tenant_id, name, mode) VALUES ($1,$2,$3,$4)`,
		r.ID, tenantID, r.Name, r.Mode)
	return conflict(err)
}

func (s *Store) GetRingfence(ctx context.Context, tenantID, id uuid.UUID) (Ringfence, error) {
	o, err := scanRingfence(s.pool.QueryRow(ctx,
		`SELECT `+ringfenceCols+` FROM ringfence_policies WHERE tenant_id=$1 AND id=$2`, tenantID, id))
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	return o, err
}

func (s *Store) ListRingfences(ctx context.Context, tenantID uuid.UUID) ([]Ringfence, error) {
	rows, _ := s.pool.Query(ctx,
		`SELECT `+ringfenceCols+` FROM ringfence_policies WHERE tenant_id=$1 ORDER BY name`, tenantID)
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Ringfence, error) { return scanRingfence(r) })
}

func (s *Store) RenameRingfence(ctx context.Context, tenantID, id uuid.UUID, name string) error {
	return oneRow(s.pool.Exec(ctx,
		`UPDATE ringfence_policies SET name=$3 WHERE tenant_id=$1 AND id=$2`, tenantID, id, name))
}

// SetRingfenceMode expects an already-validated mode; the CHECK constraint is
// the backstop and the HTTP layer returns 400 for anything else (Task 10).
func (s *Store) SetRingfenceMode(ctx context.Context, tenantID, id uuid.UUID, mode string) error {
	return oneRow(s.pool.Exec(ctx,
		`UPDATE ringfence_policies SET mode=$3 WHERE tenant_id=$1 AND id=$2`, tenantID, id, mode))
}

func (s *Store) DeleteRingfence(ctx context.Context, tenantID, id uuid.UUID) error {
	return oneRow(s.pool.Exec(ctx,
		`DELETE FROM ringfence_policies WHERE tenant_id=$1 AND id=$2`, tenantID, id))
}

type RingfenceProgram struct {
	ID             uuid.UUID
	Path           string
	NetworkBlocked bool
	Note           string
}

type RingfenceProtection struct {
	ASRRule string
	Action  string // audit|block
}

// ResolvedRingfence is everything an agent needs, with a content hash so the
// agent can skip a reconcile when nothing changed.
type ResolvedRingfence struct {
	Version     string
	Mode        string
	Programs    []RingfenceProgram
	Protections []RingfenceProtection
}

func (s *Store) AddRingfenceProgram(ctx context.Context, tenantID, ringfenceID uuid.UUID, p RingfenceProgram) error {
	tag, err := s.pool.Exec(ctx, `
		INSERT INTO ringfence_programs (id, tenant_id, ringfence_id, path, network_blocked, note)
		SELECT $1, $2, $3, $4, $5, $6
		WHERE EXISTS (SELECT 1 FROM ringfence_policies WHERE tenant_id=$2 AND id=$3)`,
		p.ID, tenantID, ringfenceID, p.Path, p.NetworkBlocked, p.Note)
	if err != nil {
		return conflict(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) DeleteRingfenceProgram(ctx context.Context, tenantID, ringfenceID, programID uuid.UUID) error {
	return oneRow(s.pool.Exec(ctx,
		`DELETE FROM ringfence_programs WHERE tenant_id=$1 AND ringfence_id=$2 AND id=$3`,
		tenantID, ringfenceID, programID))
}

func (s *Store) ListRingfencePrograms(ctx context.Context, tenantID, ringfenceID uuid.UUID) ([]RingfenceProgram, error) {
	rows, _ := s.pool.Query(ctx, `
		SELECT id, path, network_blocked, note FROM ringfence_programs
		WHERE tenant_id=$1 AND ringfence_id=$2 ORDER BY path`, tenantID, ringfenceID)
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (RingfenceProgram, error) {
		var p RingfenceProgram
		return p, r.Scan(&p.ID, &p.Path, &p.NetworkBlocked, &p.Note)
	})
}

// SetRingfenceProtection upserts an ASR rule's action. action "off" deletes
// the row, so an absent row is the single representation of "not enabled".
func (s *Store) SetRingfenceProtection(ctx context.Context, tenantID, ringfenceID uuid.UUID, asrRule, action string) error {
	if action == "off" {
		_, err := s.pool.Exec(ctx,
			`DELETE FROM ringfence_protections WHERE tenant_id=$1 AND ringfence_id=$2 AND asr_rule=$3`,
			tenantID, ringfenceID, asrRule)
		return err
	}
	tag, err := s.pool.Exec(ctx, `
		INSERT INTO ringfence_protections (tenant_id, ringfence_id, asr_rule, action)
		SELECT $1, $2, $3, $4
		WHERE EXISTS (SELECT 1 FROM ringfence_policies WHERE tenant_id=$1 AND id=$2)
		ON CONFLICT (ringfence_id, asr_rule) DO UPDATE SET action=EXCLUDED.action`,
		tenantID, ringfenceID, asrRule, action)
	if err != nil {
		return conflict(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) ListRingfenceProtections(ctx context.Context, tenantID, ringfenceID uuid.UUID) ([]RingfenceProtection, error) {
	rows, _ := s.pool.Query(ctx, `
		SELECT asr_rule, action FROM ringfence_protections
		WHERE tenant_id=$1 AND ringfence_id=$2 ORDER BY asr_rule`, tenantID, ringfenceID)
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (RingfenceProtection, error) {
		var p RingfenceProtection
		return p, r.Scan(&p.ASRRule, &p.Action)
	})
}

func (s *Store) AssignRingfence(ctx context.Context, tenantID, groupID, ringfenceID uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `
		INSERT INTO ringfence_assignments (tenant_id, group_id, ringfence_id)
		SELECT $1, $2, $3
		WHERE EXISTS (SELECT 1 FROM device_groups WHERE tenant_id=$1 AND id=$2)
		  AND EXISTS (SELECT 1 FROM ringfence_policies WHERE tenant_id=$1 AND id=$3)
		ON CONFLICT (group_id) DO UPDATE SET ringfence_id=EXCLUDED.ringfence_id
		  WHERE ringfence_assignments.tenant_id = $1`,
		tenantID, groupID, ringfenceID)
	if err != nil {
		return conflict(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) UnassignRingfence(ctx context.Context, tenantID, groupID uuid.UUID) error {
	return oneRow(s.pool.Exec(ctx,
		`DELETE FROM ringfence_assignments WHERE tenant_id=$1 AND group_id=$2`, tenantID, groupID))
}

// RingfenceForDevice resolves the ringfence assigned to the device's group.
// ErrNotFound when the device has no group or its group has no ringfence —
// the agent API turns that into "nothing to enforce".
func (s *Store) RingfenceForDevice(ctx context.Context, tenantID, deviceID uuid.UUID) (ResolvedRingfence, error) {
	var rfID uuid.UUID
	var out ResolvedRingfence
	err := s.pool.QueryRow(ctx, `
		SELECT rp.id, rp.mode FROM devices d
		JOIN ringfence_assignments ra ON ra.group_id = d.group_id AND ra.tenant_id = d.tenant_id
		JOIN ringfence_policies rp ON rp.id = ra.ringfence_id AND rp.tenant_id = $1
		WHERE d.tenant_id=$1 AND d.id=$2`, tenantID, deviceID).Scan(&rfID, &out.Mode)
	if errors.Is(err, pgx.ErrNoRows) {
		return ResolvedRingfence{}, ErrNotFound
	}
	if err != nil {
		return ResolvedRingfence{}, err
	}
	if out.Programs, err = s.ListRingfencePrograms(ctx, tenantID, rfID); err != nil {
		return ResolvedRingfence{}, err
	}
	if out.Protections, err = s.ListRingfenceProtections(ctx, tenantID, rfID); err != nil {
		return ResolvedRingfence{}, err
	}
	out.Version = ringfenceVersion(out)
	return out, nil
}

// ringfenceVersion hashes the resolved content so an unchanged ringfence
// yields an unchanged version and the agent can skip the reconcile. Both
// lists are already ordered by the queries above, so the hash is stable.
func ringfenceVersion(r ResolvedRingfence) string {
	h := sha256.New()
	fmt.Fprintf(h, "mode=%s\n", r.Mode)
	for _, p := range r.Programs {
		fmt.Fprintf(h, "prog=%s|%t\n", p.Path, p.NetworkBlocked)
	}
	for _, p := range r.Protections {
		fmt.Fprintf(h, "prot=%s|%s\n", p.ASRRule, p.Action)
	}
	return hex.EncodeToString(h.Sum(nil))[:32]
}

type RingfenceEvent struct {
	ID       int64
	DeviceID uuid.UUID
	Hostname string
	Kind     string // network|child_process
	Program  string
	Detail   string
	Enforced bool
	At       time.Time
}

func (s *Store) AppendRingfenceEvents(ctx context.Context, tenantID, deviceID uuid.UUID, evs []RingfenceEvent) error {
	if len(evs) == 0 {
		return nil
	}
	batch := &pgx.Batch{}
	for _, e := range evs {
		batch.Queue(`INSERT INTO ringfence_events (tenant_id, device_id, kind, program, detail, enforced, at)
			VALUES ($1,$2,$3,$4,$5,$6,$7)`,
			tenantID, deviceID, e.Kind, e.Program, e.Detail, e.Enforced, e.At)
	}
	br := s.pool.SendBatch(ctx, batch)
	defer br.Close()
	for range evs {
		if _, err := br.Exec(); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) ListRingfenceEvents(ctx context.Context, tenantID uuid.UUID, limit int) ([]RingfenceEvent, error) {
	rows, _ := s.pool.Query(ctx, `
		SELECT e.id, e.device_id, d.hostname, e.kind, e.program, e.detail, e.enforced, e.at
		FROM ringfence_events e JOIN devices d ON d.id = e.device_id
		WHERE e.tenant_id=$1 ORDER BY e.at DESC LIMIT $2`, tenantID, limit)
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (RingfenceEvent, error) {
		var e RingfenceEvent
		return e, r.Scan(&e.ID, &e.DeviceID, &e.Hostname, &e.Kind, &e.Program, &e.Detail, &e.Enforced, &e.At)
	})
}
