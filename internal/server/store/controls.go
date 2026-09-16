package store

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type DeviceControls struct {
	USBStorageBlocked bool
	NetworkBlocked    bool
	ElevationBlocked  bool
}

// DeviceControlOverrides is a device's per-control override: nil = inherit
// from the group, true = block, false = allow.
type DeviceControlOverrides struct {
	USBStorageBlocked *bool
	NetworkBlocked    *bool
	ElevationBlocked  *bool
}

func (o DeviceControlOverrides) empty() bool {
	return o.USBStorageBlocked == nil && o.NetworkBlocked == nil && o.ElevationBlocked == nil
}

// GetDeviceOverrides returns a device's overrides (all nil when none are
// set). ErrNotFound when the device is not in the tenant.
func (s *Store) GetDeviceOverrides(ctx context.Context, tenantID, deviceID uuid.UUID) (DeviceControlOverrides, error) {
	var o DeviceControlOverrides
	err := s.pool.QueryRow(ctx, `
		SELECT o.usb_storage_blocked, o.network_blocked, o.elevation_blocked
		FROM devices d LEFT JOIN device_control_overrides o ON o.device_id = d.id
		WHERE d.tenant_id = $1 AND d.id = $2`, tenantID, deviceID).
		Scan(&o.USBStorageBlocked, &o.NetworkBlocked, &o.ElevationBlocked)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	return o, err
}

// SetDeviceOverrides stores a device's overrides, removing the row when all
// three inherit. ErrNotFound when the device is not in the tenant.
func (s *Store) SetDeviceOverrides(ctx context.Context, tenantID, deviceID uuid.UUID, o DeviceControlOverrides) error {
	var exists bool
	if err := s.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM devices WHERE tenant_id = $1 AND id = $2)`,
		tenantID, deviceID).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return ErrNotFound
	}
	if o.empty() {
		_, err := s.pool.Exec(ctx, `DELETE FROM device_control_overrides WHERE tenant_id = $1 AND device_id = $2`, tenantID, deviceID)
		return err
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO device_control_overrides (tenant_id, device_id, usb_storage_blocked, network_blocked, elevation_blocked, updated_at)
		VALUES ($1, $2, $3, $4, $5, now())
		ON CONFLICT (device_id) DO UPDATE SET
			usb_storage_blocked = EXCLUDED.usb_storage_blocked,
			network_blocked = EXCLUDED.network_blocked,
			elevation_blocked = EXCLUDED.elevation_blocked,
			updated_at = now()`,
		tenantID, deviceID, o.USBStorageBlocked, o.NetworkBlocked, o.ElevationBlocked)
	return err
}

// SetControls stores a group's controls. The group must belong to the
// caller's tenant: ErrNotFound otherwise.
//
// device_controls has group_id as its SOLE primary key, and group_id does
// not determine the tenant — the caller names the group — so the guards
// here are load-bearing. Without the EXISTS check one tenant could name
// another's group, and without the tenant predicate on the ON CONFLICT
// branch the UPDATE would rewrite an existing row belonging to someone
// else, clearing a block they believe is enforced or cutting their fleet
// off the network. Compare AssignPolicy, which is the same shape.
func (s *Store) SetControls(ctx context.Context, tenantID, groupID uuid.UUID, c DeviceControls) error {
	tag, err := s.pool.Exec(ctx, `
		INSERT INTO device_controls (tenant_id, group_id, usb_storage_blocked, network_blocked, elevation_blocked, updated_at)
		SELECT $1, $2, $3, $4, $5, now()
		WHERE EXISTS (SELECT 1 FROM device_groups WHERE tenant_id = $1 AND id = $2)
		ON CONFLICT (group_id) DO UPDATE SET
			usb_storage_blocked=EXCLUDED.usb_storage_blocked,
			network_blocked=EXCLUDED.network_blocked,
			elevation_blocked=EXCLUDED.elevation_blocked,
			updated_at=now()
		WHERE device_controls.tenant_id = $1`,
		tenantID, groupID, c.USBStorageBlocked, c.NetworkBlocked, c.ElevationBlocked)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) GetControls(ctx context.Context, tenantID, groupID uuid.UUID) (DeviceControls, error) {
	var c DeviceControls
	err := s.pool.QueryRow(ctx,
		`SELECT usb_storage_blocked, network_blocked, elevation_blocked FROM device_controls WHERE tenant_id=$1 AND group_id=$2`,
		tenantID, groupID).Scan(&c.USBStorageBlocked, &c.NetworkBlocked, &c.ElevationBlocked)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	return c, err
}

// EffectiveControlsForDevice resolves each control as the device override if
// set, else the device's group value, else allow (nothing blocked).
func (s *Store) EffectiveControlsForDevice(ctx context.Context, tenantID, deviceID uuid.UUID) (DeviceControls, error) {
	var c DeviceControls
	err := s.pool.QueryRow(ctx, `
		SELECT COALESCE(o.usb_storage_blocked, dc.usb_storage_blocked, false),
		       COALESCE(o.network_blocked, dc.network_blocked, false),
		       COALESCE(o.elevation_blocked, dc.elevation_blocked, false)
		FROM devices d
		LEFT JOIN device_controls dc ON dc.group_id = d.group_id AND dc.tenant_id = d.tenant_id
		LEFT JOIN device_control_overrides o ON o.device_id = d.id
		WHERE d.tenant_id=$1 AND d.id=$2`, tenantID, deviceID).
		Scan(&c.USBStorageBlocked, &c.NetworkBlocked, &c.ElevationBlocked)
	if errors.Is(err, pgx.ErrNoRows) {
		return DeviceControls{}, ErrNotFound
	}
	return c, err
}
