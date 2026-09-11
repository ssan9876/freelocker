# FreeLocker — Sub-project #1: Core Platform Design

**Date:** 2026-09-10
**Status:** Draft — awaiting review

## 1. Product context

FreeLocker is a ThreatLocker-style endpoint control platform: an agent on each Windows PC enforces
application allowlisting and device policy, managed from a central server that can run on-premises
or in the cloud, with telemetry flowing back for monitoring.

### Decisions already made
| Topic | Decision |
|---|---|
| Endpoint OS | Windows only (for now) |
| Enforcement | WDAC-based enforcement first, behind an `Enforcer` interface so a custom kernel driver backend can be added later |
| Tenancy | Single organization in v1; `tenant_id` present in every table and API call to allow MSP multi-tenancy later |
| Language | Go for agent and server; React + TypeScript console |
| Storage | PostgreSQL (+ TimescaleDB for metrics in sub-project #3) |
| Agent transport | gRPC over mutual TLS; agent always dials out |

### Roadmap (each sub-project gets its own spec → plan → build cycle)
1. **Core platform** (this document)
2. Application control: allowlist rules (hash/publisher/path), learning mode, WDAC policy compile + deploy, block reporting
3. Telemetry & monitoring: resource metrics, process/logon/network events, alert rules
4. Device & behavior control: USB storage, network restrictions, elevation control
5. Kernel driver `Enforcer` backend: real-time allow/deny with approval requests

## 2. Scope of sub-project #1

**In scope:** server skeleton, Postgres schema, admin authentication and RBAC, built-in CA, install
tokens, agent enrollment, persistent agent↔server stream with heartbeat and inventory, server→agent
commands, agent self-update, audit log, basic console, local and cloud deployment packaging.

**Out of scope:** any application blocking, telemetry beyond inventory, SSO, multiple tenants,
kernel-level tamper protection.

## 3. Architecture

```
Server (single Go binary "freelocker-server")
  ├─ gRPC API for agents (mTLS)
  ├─ REST/JSON API for console (HTTPS, session auth)
  ├─ Embedded React console (static assets)
  ├─ Built-in CA
  └─ PostgreSQL (tenant_id on every table)

Agent (Go Windows service "freelocker-agent", runs as SYSTEM)
  ├─ comms      — enrollment, gRPC stream, reconnect/backoff
  ├─ identity   — keypair (DPAPI machine scope), certificate, renewal
  ├─ inventory  — hostname, OS build, IPs, logged-on user, agent version
  ├─ commands   — executes signed server commands
  ├─ updater    — helper process for binary swap + rollback
  └─ enforcer   — interface only in #1 (no-op implementation)
```

Principles:
- **Outbound-only agents.** No inbound ports on endpoints; works behind NAT for local and cloud servers.
- **Deployment mode is configuration only.** Same binary and schema for local and cloud.
- **Offline-first.** Agent state (identity, config, later policies) is cached locally; agent functions
  without the server.
- **Identity from certificates.** The server derives device identity from the mTLS client cert,
  never from agent-supplied fields.

### Repository layout
```
cmd/server/          server entrypoint
cmd/agent/           agent entrypoint (Windows service)
cmd/agent-updater/   update helper
cmd/agent-sim/       fake-agent load/integration tool
internal/server/     api, enroll, devices, commands, auth, ca, audit, store
internal/agent/      comms, service, identity, inventory, commands, updater, enforcer
proto/               gRPC/protobuf definitions
web/                 React + TypeScript console (built output embedded via go:embed)
deploy/              docker-compose.yml, Dockerfile, MSI (WiX) build scripts
docs/                specs and plans
```

## 4. Enrollment

1. Admin creates an **install token** in the console with: optional expiry, optional max-uses, and a
   default device group. Tokens are random 32-byte values; only a SHA-256 hash is stored.
2. Agent MSI is installed with `SERVER_URL=<url> TOKEN=<token>` (supports GPO/Intune silent install).
3. On first start the agent generates an ECDSA P-256 keypair, protects the private key with DPAPI
   (machine scope), and calls `Enroll(token, csr, hardware_info)` over server-authenticated TLS.
4. Server validates token (exists, not expired, uses remaining, not revoked), signs the CSR with the
   internal CA (CN = new device UUID, 90-day validity), creates the device record, increments token
   use count, writes an audit entry, and returns the cert + CA chain.
5. All subsequent calls use mTLS. The server checks the cert against the device table on every
   connection; revoked devices are rejected immediately.

Failure handling: invalid/expired/exhausted token → agent logs a clear error to the Windows Event Log
and retries every 15 minutes (so a fixed token can be supplied via config without reinstall).

## 5. Agent ↔ server protocol

A single long-lived bidirectional gRPC stream `Connect`:
- **Agent → server:** `Heartbeat` every 30 s containing inventory (hostname, OS build, IP addresses,
  logged-on user, agent version, uptime); `CommandResult` messages.
- **Server → agent:** `Command` messages.
- Reconnect with exponential backoff (1 s → 5 min cap, with jitter).
- Clock skew tolerance: 5 minutes.
- Device is **online** if a heartbeat arrived within 90 s; otherwise **offline**.

### Commands (v1)
`Ping`, `RefreshInventory`, `RotateCertificate`, `Uninstall`, `UpdateAgent`.

Every command has a UUID, issued-at time, and expiry, and is signed with the server's command-signing
key (Ed25519; public key delivered at enrollment). The agent verifies the signature, rejects expired
or replayed IDs, executes, and returns a `CommandResult` (success/failure + message), which is
recorded in the audit log. Commands queued for offline devices are delivered on reconnect if not expired.

## 6. Certificates and keys

- Internal CA: ECDSA P-256, 10-year root, created by the first-run setup. Private key encrypted at rest
  with a key derived from a server master secret (env var or file); cloud installs may use a KMS instead.
- Device certs: 90-day validity; agent renews via `RenewCertificate` at 60 days (new CSR, authenticated
  by the current cert).
- Command-signing key and update-signing key: separate Ed25519 keys, stored the same way as the CA key.
- Public server TLS: operator-provided cert, Let's Encrypt (ACME), or TLS terminated at a load balancer.
  Agent mTLS always uses the internal CA; when behind a load balancer, the agent gRPC port must be
  TLS passthrough.

## 7. Agent lifecycle and self-protection

- Installed via MSI to `C:\Program Files\FreeLocker\`; data in `C:\ProgramData\FreeLocker\`. Both ACL'd
  to SYSTEM + Administrators only (data dir: SYSTEM only).
- Windows service recovery configured to restart on failure.
- **Uninstall requires a per-device uninstall code** (shown in console, verified by the agent against a
  hash delivered by the server) or a server-issued `Uninstall` command.
- Known limitation: a local administrator can stop the service. The server raises an
  "unexpectedly offline" indicator when a device drops without a clean shutdown message. Real tamper
  protection is deferred to sub-project #5.

### Updates
Server hosts agent release binaries with an Ed25519 signature. On `UpdateAgent`, the agent downloads
the binary, verifies SHA-256 and signature, launches `agent-updater`, which stops the service, swaps
binaries (keeping the previous version), starts the service, and rolls back if no successful
heartbeat occurs within 2 minutes.

## 8. Server

- **Auth:** local admin accounts; bcrypt password hashes; mandatory TOTP 2FA; server-side sessions in
  Postgres with HttpOnly, Secure, SameSite=Strict cookies; CSRF token on state-changing requests;
  login rate limiting.
- **RBAC:** Owner (everything incl. admin management), Admin (devices, tokens, commands),
  Read-only (view only).
- **Audit log:** append-only table recording actor, action, target, timestamp, source IP, and result for
  every admin action and every command result.
- **First-run setup wizard** (local installs): creates the tenant, the first Owner, and the CA/keys.
  Cloud installs may instead bootstrap via CLI: `freelocker-server init`.
- **Configuration:** YAML file overridable by environment variables (DB URL, listen addresses, TLS mode,
  master secret location).

### Data model (initial tables)
All tables include `tenant_id`.
- `tenants` (id, name, created_at)
- `admins` (id, email, password_hash, totp_secret_enc, role, disabled, created_at)
- `sessions` (id, admin_id, expires_at, ip, user_agent)
- `install_tokens` (id, token_hash, name, group_id, expires_at, max_uses, uses, revoked, created_by)
- `device_groups` (id, name)
- `devices` (id, hostname, group_id, cert_serial, cert_expires_at, os_build, agent_version, ips,
  logged_on_user, last_seen_at, status, revoked, uninstall_code_hash, enrolled_at)
- `commands` (id, device_id, type, payload, issued_by, issued_at, expires_at, state, result, completed_at)
- `audit_log` (id, actor, action, target_type, target_id, detail_json, ip, result, created_at)
- `agent_releases` (version, sha256, signature, uploaded_at)

Migrations managed with a Go migration library, applied automatically on server start.

## 9. Console (v1)

Login + TOTP enrollment; devices list (filter by group/status, online indicator); device detail
(inventory, command history, issue command, revoke, show uninstall code); install token management;
device groups; admin management (Owner only); audit log viewer.

## 10. Deployment

- **Local:** `docker-compose.yml` (server + Postgres), or a Windows service install of the server
  binary pointing at an existing Postgres.
- **Cloud:** container image; Postgres as a managed service; horizontal scaling of server instances is
  not required in v1 (single instance), but server state lives only in Postgres so it can be added later.

## 11. Testing

- Unit tests: token validation, CA/CSR signing, command signing/verification, RBAC checks, backoff.
- Integration tests: real Postgres via Docker; in-process agent client exercising
  enroll → heartbeat → command → revoke → rejected reconnect.
- `agent-sim`: simulates N agents for load testing (target: 1,000 concurrent agents on one server instance).
- Manual checklist on a Windows VM: MSI silent install, service recovery, uninstall-code enforcement,
  self-update and rollback.

## 12. Success criteria

- An admin can stand up the server locally with one `docker compose up`, complete setup, and create a token.
- A Windows PC installed with the MSI and token appears in the console as online within 60 s.
- Revoking a device disconnects it and prevents reconnection.
- Pushing `UpdateAgent` upgrades the agent, and a broken build rolls back automatically.
- All admin actions and command results appear in the audit log.
