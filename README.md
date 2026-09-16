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
  ringfencing (per-program network/child-process containment)
  resource metrics · USB storage control · self-update (staged rollouts with pause/rollback) · self-protection
Console (React SPA, embedded in the server)
  setup · login + TOTP · devices · policies · blocked programs · alerts
  install tokens · groups + controls · admins · agent releases · audit log · email + webhook notifications
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

Beyond the sub-projects, the platform also has: **publisher (signer) rules**
— the agent reads a file's Authenticode certificate and verifies it with
Windows, so an admin can allow everything signed by a verified publisher and
the rule survives application updates (unverified signatures are shown but
can never become rules); **per-device control overrides** (each control is
Inherit / Allow / Block per device, layered over its group); **interactive approvals**
(a would-block becomes an approval request an admin approves as a hash, path
or publisher rule); **richer device controls** (network and elevation, not just
USB); **telemetry event streams** (process launches, logons and
elevations on an Activity page — an elevation being a process that received
a full administrator token); **download provenance** (the agent reads
Mark-of-the-Web, so the console distinguishes software fetched from the
internet from software that was installed; a hint for review, never a
security boundary, since a user can strip the mark from their own file); **health/readiness probes** and **Let's Encrypt** console
TLS; **multi-instance safety** (the login rate-limiter and alert breach
state live in Postgres) and **time-series retention**; **email, webhook and syslog
notifications** (a retrying outbox fans alert, approval and rollout events
out to per-tenant channels, with HMAC-signed webhook posts, RFC 5424 or CEF
syslog for SIEM ingestion, and a Test send from the console); **CSV export**
of the audit log, devices, blocked programs and ringfence events (the audit
export is itself audited) — see
`docs/superpowers/specs/2026-09-14-notifications-design.md`; a **GitHub Actions
CI** pipeline (Go tests + Postgres, Windows cross-compile, console build,
Playwright E2E). **MSP multi-tenancy** is built end to end — per-tenant keys
and CAs, SNI-selected per-tenant transport, global-email login, a
provider tenant-management API (create, rename, and reversibly suspend a
tenant), and a provider console view — see
`docs/superpowers/specs/2026-09-11-msp-multitenancy-design.md`.

**Ringfencing** constrains what an allowed application may do, independent of
whether it's allowed to run at all: per-program network blocking (enforced
with Windows Firewall rules) and Office/scripting child-process containment
(enforced through Windows Defender's six curated Attack Surface Reduction
rules, reported alongside whether Defender is even active on the device). A
ringfence starts in audit mode and is switched to enforce only behind a
confirmation dialog. Network and child-process containment are **built and
tested — the data model, protocol, agent diffing, parsers, firewall/ASR
enforcer, HTTP API and console are all covered by Go tests and a Playwright
console flow — but enforcement itself is not yet verified on a VM**; the Go
test suite proves the model, the API and the parsers behave correctly, not
that Windows Firewall or Defender ASR actually contain anything on a real
machine. See `docs/ringfence-manual-test.md` for the checklist that would
verify it. File and registry containment for ringfenced programs are not
implemented — they remain part of sub-project 5 (the kernel driver).

Anything that could lock or destabilize a real machine (WDAC enforcement,
USB blocking, service install, ringfence enforcement) **defaults to
safe/audit mode**, and live enforcement is **verified only on a disposable
VM** — never against the dev machine — for every capability except
ringfencing, where that VM verification is still outstanding (see above).
See the `docs/*-manual-test.md` checklists.

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
- `internal/appcontrol/` — rule model, WDAC compiler, Authenticode signature reader
- `web/` — React + TypeScript console
- `proto/` — gRPC/protobuf; `deploy/` — Docker + MSI
- `docs/` — specs, plans, and manual-test checklists

## Licence

Apache License 2.0 — see [LICENSE](LICENSE). You may use, modify and
distribute this, including commercially, provided you keep the notices; it
comes with no warranty of any kind.

FreeLocker changes how Windows decides what may run and what hardware may be
used. Test it on a disposable VM before any machine you care about.
