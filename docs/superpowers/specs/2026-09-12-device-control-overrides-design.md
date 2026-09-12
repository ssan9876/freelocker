# Per-device control overrides — design

**Status:** approved 2026-09-12. Backlog item C (see the 2026-09-12 backlog
order: A edit/delete gaps ✔, B refresh inventory ✔, **C**, D signer rules, E
E2E MFA, F polish).

## Goal

Let an admin override a single device's device controls (USB storage,
network, elevation) independently of its group, so one kiosk laptop can allow
USB while its group blocks it, or one sensitive machine can block network
while its group allows it.

## Semantics

Each control is **tri-state per device**, independently:

| Device setting | Effect |
|---|---|
| Inherit (default) | follow the group's value; if no group or no group controls, Allow |
| Allow | not blocked, whatever the group says |
| Block | blocked, whatever the group says |

Effective value per control = device override if set, else group value, else
Allow. Overrides can both tighten and loosen a group.

## Data

Migration `0015_device_control_overrides.sql`:

```sql
CREATE TABLE device_control_overrides (
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    device_id uuid PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    usb_storage_blocked boolean,   -- NULL = inherit
    network_blocked     boolean,
    elevation_blocked   boolean,
    updated_at timestamptz NOT NULL DEFAULT now()
);
```

No row means inherit everything. A row whose three columns are all NULL is
never stored (the store deletes it instead), so "has overrides" is simply
"has a row".

## Store (`internal/server/store/controls.go`)

- `type DeviceControlOverrides struct { USBStorageBlocked, NetworkBlocked, ElevationBlocked *bool }`
- `GetDeviceOverrides(ctx, tenantID, deviceID) (DeviceControlOverrides, error)`
  — all-nil when no row; `ErrNotFound` when the device is not in the tenant.
- `SetDeviceOverrides(ctx, tenantID, deviceID, o)` — upsert; deletes the row
  when all three are nil; `ErrNotFound` when the device is not in the tenant.
- `EffectiveControlsForDevice` gains a `LEFT JOIN device_control_overrides`
  and resolves each column as `COALESCE(o.x, dc.x, false)` in one query.

## Agent path

Unchanged. `agentapi.GetControls` already returns
`EffectiveControlsForDevice`, so the agent applies an override on its next
controls poll (app-control tick, ≤ 5 min; or sooner via Refresh inventory).
No proto change; the Windows enforcers only ever see the effective set.

## Console API (admin role, audited `device.controls`)

- `GET /api/devices/{id}/controls` →
  `{"overrides": {"usb_storage_blocked": true|false|null, ...},
    "group": {"usb_storage_blocked": bool, ...},
    "effective": {"usb_storage_blocked": bool, ...}}`
  (`group` is all-false when the device has no group / group has no controls).
  GET is readable by any role, like the other GET routes.
- `POST /api/devices/{id}/controls` with the three keys, each
  `true|false|null` (null = inherit) → 204.
- A device in another tenant → 404.

## Console

Device detail page gets a **Device controls** panel: one Inherit / Allow /
Block select per control, with a hint showing the inherited value and its
source ("Inherits: Blocked (group Laptops)" / "Inherits: Allowed (no group
controls)"). Read-only admins see the values without the selects.

## Safety

No machine changes until an admin sets an override. Enforcement code and its
audit-mode/VM-only rules are untouched; the network enforcer still refuses to
block if it cannot keep the management channel.

## Testing (TDD)

- Store: resolution truth table (override × group value × no-group), the
  all-nil delete, cross-tenant `ErrNotFound`, cascade on device delete.
- httpapi: get/set round-trip with nulls, effective/group fields, 404
  cross-tenant, 403 for readonly on POST.
- agentapi: a device's `GetControls` reflects an override that loosens its
  group's block.

## Out of scope

Per-device policy (app-control) overrides; bulk override editing; showing
overrides in the device list.
