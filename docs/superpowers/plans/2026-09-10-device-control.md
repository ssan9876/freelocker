# Sub-project #4 — Device & Behavior Control Implementation Plan

> REQUIRED SUB-SKILL: superpowers:executing-plans. TDD, commit per task.

**Goal:** Per-group device controls the agent enforces. v1 ships **USB mass-storage control** (allow/block) end-to-end — the canonical "storage control" feature. The model is extensible; network restrictions and elevation control are declared as future controls (same enforce-on-VM pattern as WDAC).

**Architecture:** Controls are set per device group, resolved for a device by its group, and pulled by the agent via a `GetControls` RPC. A `controls.Enforcer` applies them (Windows: sets the USBSTOR service Start value in the registry; other: no-op). Default is **allow** — a control blocks only when explicitly set, and blocking USB storage is reversible. Server logic + resolution are unit-tested; the registry write is verified on a VM.

**Spec:** design roadmap item 4. **Depends on:** #1–#3 merged.

## Global constraints
- Default allow (usb_storage_blocked=false) everywhere; agent only blocks when told.
- tenant_id on the table; store calls take tenantID first.
- Applying is idempotent; unchanged controls do nothing.

## Tasks
1. store `controls.go` (migration 0005): `device_controls(tenant_id, group_id PK, usb_storage_blocked bool, updated_at)`. SetControls(group, blocked), GetControls(group)→ErrNotFound if unset, EffectiveControlsForDevice(device)→{USBStorageBlocked} (false when no group/row). Tests: set/get, effective resolution default-allow, tenant isolation.
2. proto `GetControls(GetControlsRequest) returns ControlsResponse{usb_storage_blocked}`; agentapi handler resolves via store; Deps gains nothing (uses store). Test: enrolled client in a group with USB blocked gets usb_storage_blocked=true.
3. agent `controls` pkg: `Controls{USBStorageBlocked bool}`, `Enforcer` iface Apply(Controls) + Noop; windows enforcer sets HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR Start (3=allow,4=block). Test (portable): Noop records last-applied; windows build compiles.
4. runner: on app-control tick, also GetControls + enforcer.Apply. Integration test with a recording controls enforcer: set USB blocked on the group, agent applies it.
5. httpapi: GET /api/groups/{id}/controls, POST /api/groups/{id}/controls {usb_storage_blocked} (admin). Console: controls toggle on a Groups detail/section. Tests + build.
6. finalize: vet, test, build, manual VM doc note, commit.

## Deferred
- Network restrictions (Windows Firewall rules), elevation control, per-device (not just per-group) overrides.
