# FreeLocker

A ThreatLocker-style endpoint control platform: an agent on each Windows PC
enforces application allowlisting and device policy and reports telemetry;
a central server manages everything and can run on-premises or in the
cloud; a web console drives it. Single Go binary for the server (with the
console embedded), a single Go binary for the agent.

## Architecture

```
Server (freelocker-server, one binary)
  gRPC (agents, mTLS) · REST + embedded React console · built-in CA
  PostgreSQL · policy compiler · alert engine        (tenant_id everywhere)
        ▲ agents always dial out (mTLS)      ▲ HTTPS
Agent (freelocker-agent, Windows service, SYSTEM)
  enroll · heartbeat/inventory · signed commands · cert auto-renew
  WDAC application control · learning · block reporting
  resource metrics · USB storage control · self-update · self-protection
Console (React SPA, embedded in the server)
  setup · login + TOTP · devices · policies · blocked programs · alerts
  install tokens · groups + controls · admins · agent releases · audit log
```

Design decision throughout: enforcement sits behind an `Enforcer`
interface, so WDAC today and a kernel driver later swap in without
touching the server or protocol.

## Status by sub-project

| # | Sub-project | Status |
|---|---|---|
| 1a | Server backend + agent protocol | **Built & tested** |
| 1b | Windows agent, updater, MSI | **Built & tested** (live service/MSI verified on a VM; agent verified enrolling on the dev box) |
| 1c | Web console | **Built & tested** (served by the single binary) |
| 2 | Application control (WDAC allowlisting) | **Built & tested**; live WDAC activation is audit-mode-default and verified on a VM |
| 3 | Telemetry & monitoring | **Built & tested** |
| 4 | Device control (USB storage) | **Built & tested**; live registry enforcement verified on a VM |
| 5 | Kernel driver (real-time allow/deny) | **Design only** — needs WDK, EV cert + attestation, kernel-debug VM (see `docs/superpowers/specs/2026-09-10-kernel-driver-design.md`) |

Beyond the sub-projects, the platform also has: **interactive approvals**
(a would-block becomes an approval request an admin approves as a hash or
path rule); **richer device controls** (network and elevation, not just
USB); **telemetry event streams** (process launches and logons on an
Activity page); **health/readiness probes** and **Let's Encrypt** console
TLS; **multi-instance safety** (the login rate-limiter and alert breach
state live in Postgres) and **time-series retention**; a **GitHub Actions
CI** pipeline (Go tests + Postgres, Windows cross-compile, console build,
Playwright E2E). **MSP multi-tenancy** is built end to end — per-tenant keys
and CAs, SNI-selected per-tenant transport, global-email login, a
provider tenant-management API, and a provider console view — see
`docs/superpowers/specs/2026-09-11-msp-multitenancy-design.md`.

Anything that could lock or destabilize a real machine (WDAC enforcement,
USB blocking, service install) **defaults to safe/audit mode and is
verified only on a disposable VM** — never against the dev machine. See the
`docs/*-manual-test.md` checklists.

## Run it locally

```
# 1. Start Postgres + the server (console embedded):
docker compose -f deploy/docker-compose.yml up -d --build
# 2. Open http://localhost:8080, complete setup (org + owner + TOTP).
# 3. Create an install token; build and install the agent MSI on a Windows VM:
deploy/msi/build.ps1 -Version 0.1.0
msiexec /i FreeLocker.msi /qn SERVERURL=<host>:8443 TOKEN=<token>
```

Development database for the test suite:
`docker compose -f deploy/docker-compose.dev.yml up -d` (Postgres on :55432),
then `go test ./...`. The web console builds with `npm --prefix web run build`.

## Layout
- `cmd/` — `server`, `agent`, `agent-updater`, `agent-sim` (load/test tool)
- `internal/server/` — store, CA, auth, gRPC agent API, REST API, app wiring
- `internal/agent/` — identity, runner, enforcer, controls, metrics, scan, service
- `internal/appcontrol/` — rule model + WDAC compiler
- `web/` — React + TypeScript console
- `proto/` — gRPC/protobuf; `deploy/` — Docker + MSI
- `docs/` — specs, plans, and manual-test checklists
