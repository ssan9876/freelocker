package store

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type DeviceControls struct {
	USBStorageBlocked bool
}

func (s *Store) SetControls(ctx context.Context, tenantID, groupID uuid.UUID, c DeviceControls) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO device_controls (tenant_id, group_id, usb_storage_blocked, updated_at)
		VALUES ($1,$2,$3, now())
		ON CONFLICT (group_id) DO UPDATE SET usb_storage_blocked=EXCLUDED.usb_storage_blocked, updated_at=now()`,
		tenantID, groupID, c.USBStorageBlocked)
	return err
}

func (s *Store) GetControls(ctx context.Context, tenantID, groupID uuid.UUID) (DeviceControls, error) {
	var c DeviceControls
	err := s.pool.QueryRow(ctx, `SELECT usb_storage_blocked FROM device_controls WHERE tenant_id=$1 AND group_id=$2`,
		tenantID, groupID).Scan(&c.USBStorageBlocked)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	return c, err
}

// EffectiveControlsForDevice resolves controls via the device's group,
// defaulting to allow (nothing blocked) when the device has no group or
// the group has no controls row.
func (s *Store) EffectiveControlsForDevice(ctx context.Context, tenantID, deviceID uuid.UUID) (DeviceControls, error) {
	var c DeviceControls
	err := s.pool.QueryRow(ctx, `
		SELECT COALESCE(dc.usb_storage_blocked, false)
		FROM devices d
		LEFT JOIN device_controls dc ON dc.group_id = d.group_id AND dc.tenant_id = d.tenant_id
		WHERE d.tenant_id=$1 AND d.id=$2`, tenantID, deviceID).Scan(&c.USBStorageBlocked)
	if errors.Is(err, pgx.ErrNoRows) {
		return DeviceControls{}, ErrNotFound
	}
	return c, err
}
