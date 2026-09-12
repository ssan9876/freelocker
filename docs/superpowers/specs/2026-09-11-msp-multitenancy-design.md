# MSP Multi-Tenancy — Design & Phased Plan

**Status:** Design. The schema is already `tenant_id`-scoped throughout and
server keys are stored per tenant (`server_keys` keyed by `tenant_id`), so
the data model needs no change. What remains is rewiring the runtime, which
currently assumes exactly one tenant, and it touches the security core
(CA, enrollment, login) — so it is planned and executed as its own careful,
fully-tested pass rather than rushed alongside smaller features.

## Goal
Let one provider (an MSP) manage many client organizations from one server:
each tenant isolated — its own CA, devices, policies, admins, telemetry —
with a provider-level super-admin who can create and switch between tenants.

## What's already in place
- Every table carries `tenant_id`; every store method takes `tenantID` first.
- `bootstrap.Init` creates a tenant + its own CA + Ed25519 command/update keys,
  sealed in `server_keys` under that `tenant_id`. Running it per tenant already
  yields per-tenant CAs.
- `devices.DeviceAuthState` resolves a device to its `tenant_id` from the mTLS
  cert; install tokens carry `tenant_id`; policies/alerts/controls resolve by
  tenant. Device→tenant is already correct.

## What assumes a single tenant (the work)
1. **Runtime keys.** `httpapi.Runtime` and `agentapi.Deps` hold one `*bootstrap.Keys`.
   Replace with a `TenantKeys` provider: `Keys(ctx, tenantID) (*bootstrap.Keys, error)`
   that loads and caches per-tenant keys from `server_keys`.
2. **Enrollment.** `enroll.go` signs the device cert with the single runtime CA.
   Change to: token → `tenant_id` → that tenant's CA. (The token lookup already
   returns the tenant in `EnrollDevice`.)
3. **Agent stream / commands / policy / controls.** These sign commands and
   policies and resolve effective policy using the single Keys. Switch to the
   device's tenant keys via the `TenantKeys` provider (device→tenant is known).
4. **Login / tenant resolution.** The crux. Adopt the common SaaS model:
   **email is a global identity; each admin belongs to one tenant.** Add a
   global unique index on `lower(email)`, and resolve the tenant from the admin
   at login (`GetAdminByEmailGlobal(email) → admin, tenant_id`) instead of from
   a single runtime tenant. No tenant picker needed at the login box.
5. **Provider super-admin + tenant management.** A `provider` flag on the first
   tenant's owner. Provider-only API: create tenant (runs `bootstrap.Init` for a
   new tenant + creates its first owner), list tenants, suspend. Everything else
   stays tenant-scoped to the caller's tenant.
6. **Console.** A provider view listing tenants with a "manage" action that
   scopes the session to a tenant; ordinary admins see only their own tenant
   (no change to their experience).

## Phased plan (each phase ships green, no regression to single-tenant)
- **Phase 1 — per-tenant keys, no UX change.** Introduce `TenantKeys` and route
  enrollment, agent stream, commands, policy, and controls through it keyed by
  the token's/device's tenant. Single-tenant behavior is unchanged (one tenant
  in the cache). Pure refactor; existing tests must stay green, plus a test that
  two tenants with two CAs each enroll and operate in isolation.
- **Phase 2 — global-email login.** Add the global-unique-email migration and
  `GetAdminByEmailGlobal`; login resolves tenant from the admin. Test: two
  tenants, an admin in each, each logs into their own tenant; duplicate email
  across tenants is rejected at creation.
- **Phase 3 — provider tenant management.** `provider` owner flag; provider API
  to create/list tenants (each with its own CA via `bootstrap.Init`); audit.
  Test: provider creates tenant B, B's owner logs in, enrolls a device that gets
  B's CA (not A's).
- **Phase 4 — console provider view + tenant scoping.** UI to list tenants and
  manage one; ordinary admins unaffected.

## Risks & why it's isolated from the other work
- It changes the CA and auth paths that every feature relies on; a subtle error
  (e.g. signing with the wrong tenant's CA) is a cross-tenant security bug.
  Keeping it a dedicated pass with per-phase tests contains that risk.
- The global-email decision is a one-way door for the auth model; worth an
  explicit confirmation before Phase 2.

## Out of scope
- Per-tenant custom domains/branding; cross-tenant reporting/roll-ups;
  tenant data export/residency.
