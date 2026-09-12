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
- **Phase 1 — per-tenant application-layer keys. DONE.** Added
  `internal/server/keyset.Provider` (`For(ctx, tenantID)`, cached) and a
  `keyset.Func` resolver threaded through enrollment (device-cert signing +
  enrollment response), the agent stream (certificate renewal), commands
  (signing), and policy (compile/sign + effective/deny-all), keyed by the
  token's/device's tenant; `bootstrap.ProvisionTenant` creates a tenant with
  its own CA + keys. When no resolver is set the single `Keys` is used, so
  single-tenant behavior is unchanged (all existing tests green).
  `keyset.TestPerTenantKeyIsolation` proves two tenants get distinct CAs and
  that one tenant's key neither signs nor verifies another's policy.
- **Phase 1b — per-tenant transport. DONE.** `internal/server/agentapi.TenantTLS`
  builds the agent-facing mTLS: `GetCertificate` selects a per-tenant server
  cert by SNI — agents send their CA pin as `ServerName`, and the issued cert
  carries that pin in its SANs so an agent verifying the hostname (Connect uses
  `RootCAs` + `ServerName = pin`) accepts it; empty/unknown SNI falls back to the
  default (first) tenant. `GetConfigForClient` sets `ClientCAs` to the union of
  all tenant CAs with `VerifyClientCertIfGiven` (Enroll runs before the agent has
  a cert). Tenants/certs are resolved through `keyset.Provider` and cached with a
  30s TTL (`store.ListTenants`), so tenants added at runtime are picked up.
  Agents (sim + `agent/identity`, both `pinnedTLS` and `TLSConfig`) send the pin
  as SNI. Single-tenant is unchanged: the one agent sends the one pin and gets
  the one cert (or falls back). `agentapi.TestMultiTenantEnrollmentOverTheWire`
  proves two tenants each enroll and `GetPolicy` over one server via SNI, that
  each device is bound to its own tenant, and that tenant A's cert cannot ride
  tenant B's SNI + roots.
- **Phase 2 — global-email login. DONE.** Migration `0012_global_email.sql`
  adds a global unique index on `admins(email)`; `store.GetAdminByEmailGlobal`
  returns an admin and its tenant by email alone. `httpapi.login` now resolves
  the tenant from the email (no tenant hint in the form); an unknown email is
  rate-limited under the default tenant and runs the dummy password check, so
  timing/enumeration behavior is unchanged and there is no tenant leak. A
  cross-tenant duplicate email is rejected at creation (`ErrConflict` → 409) at
  both setup and the admin-create endpoint. Tests: `store.TestGlobalEmail`
  (global uniqueness + resolve-by-email) and
  `httpapi.TestLoginResolvesTenantFromEmail` (a second-tenant admin logs in with
  no hint and gets a tenant-B session; unknown email → 401).
- **Phase 3 — provider tenant management. DONE.** Migration `0013_provider.sql`
  adds a `provider` flag to `admins`; the setup owner is the provider (the MSP
  operator). New provider-only API (guarded by `requireProvider`): `POST
  /api/provider/tenants` (`app.ProvisionTenant` → `bootstrap.ProvisionTenant`
  creates the tenant with its own CA + keys, then its owner admin) and `GET
  /api/provider/tenants` (`store.ListTenantDetails`). Actions are audited under
  the provider's tenant (`provider.tenant.create`). `/api/me` now returns the
  `provider` flag (for the Phase 4 console). Test:
  `httpapi.TestProviderCreatesTenant` — a non-provider owner gets 403; the
  provider creates tenant Beta; Beta's owner logs in with no hint and is an
  owner but not a provider; Beta's CA differs from the default tenant's (so a
  device enrolling into Beta trusts Beta's CA); a duplicate owner email → 409.
- **Phase 4 — console provider view. DONE.** `/api/me` carries `provider`;
  `web/src/pages/Tenants.tsx` lists tenants and creates one (org + owner email +
  password) via the provider API. The "Tenants" nav item and the `/tenants`
  route are rendered only when `me.provider` is true, so ordinary admins never
  see them; a non-provider who reaches the API still gets 403 (Phase 3). The
  console typechecks and builds. E2E is unchanged: the existing Playwright smoke
  test stops at MFA enrollment (a browser cannot complete TOTP without the
  shared secret), so the provider flow is covered by the Go API test
  `httpapi.TestProviderCreatesTenant` rather than a click-through.

## Risks & why it's isolated from the other work
- It changes the CA and auth paths that every feature relies on; a subtle error
  (e.g. signing with the wrong tenant's CA) is a cross-tenant security bug.
  Keeping it a dedicated pass with per-phase tests contains that risk.
- The global-email decision is a one-way door for the auth model; worth an
  explicit confirmation before Phase 2.

## Out of scope
- Per-tenant custom domains/branding; cross-tenant reporting/roll-ups;
  tenant data export/residency.
