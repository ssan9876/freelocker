# Core Platform 1c — Web Console Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax.

**Goal:** A React + TypeScript admin console over the existing REST API — first-run setup, login + TOTP, device list/detail with commands and revoke, install tokens, groups, admins, audit log, and agent releases — built with Vite and embedded into the `freelocker-server` binary so a single binary serves both the API and the UI.

**Architecture:** SPA in `web/` (Vite, React Router, a thin typed `api.ts` fetch wrapper that sends the CSRF header and cookies). `vite build` emits `web/dist`, embedded via `go:embed` in `internal/server/webui`. The console HTTP handler serves `/api/*` and `/agent/*` as today and falls back to the embedded SPA (with `index.html` for unknown paths) for everything else.

**Tech Stack:** Vite 5, React 18, TypeScript, React Router 6, IBM Plex Sans/Mono (Google Fonts). No component library — hand-built, to keep the control-room aesthetic.

**Spec:** `docs/superpowers/specs/2026-09-10-core-platform-design.md` §9

**Depends on:** 1a (API) and 1b (releases API) — both merged.

## Global Constraints

- Node 24 / npm 11 (present). Module `freelocker`, Go floor 1.27.
- The API uses session cookies + a CSRF token returned by `/api/login`; the client stores the token in memory and sends it as `X-CSRF-Token` on every non-GET. `fetch` uses `credentials: "include"`. Dev server proxies `/api` and `/agent` to `:8080`.
- Design tokens exactly as in the plan header; theme-aware via `data-theme` + `prefers-color-scheme`; light is the default.
- The server serves the SPA only when `web/dist` is embedded; when absent (fresh checkout before a UI build), `webui.Enabled()` is false and the server logs a hint and serves a 404 for non-API routes. Tests must not require a UI build.
- No secrets in the bundle. The install token and uninstall code are shown only transiently in the UI as returned by the API.

## File Structure

```
web/package.json, tsconfig.json, vite.config.ts, index.html, .gitignore
web/src/main.tsx, App.tsx, api.ts, auth.tsx, styles.css
web/src/components/{Layout,StatusDot,DataTable,Field,Toast,Confirm}.tsx
web/src/pages/{Setup,Login,Mfa,Devices,DeviceDetail,Tokens,Groups,Admins,Audit,Releases}.tsx
internal/server/webui/webui.go          go:embed dist + SPA handler
internal/server/webui/dist/.gitkeep     ensures the embed path exists
internal/server/app/app.go              mount webui fallback (modify)
deploy/Dockerfile                       add a node build stage (modify)
```

## Tasks

### Task 1: Scaffold Vite app, design tokens, API client, auth context
- Create `web/` project; `npm install`; `vite.config.ts` with `/api`+`/agent` proxy to `http://localhost:8080`.
- `styles.css`: design tokens (light + dark), base layout, table, buttons, form, status colors.
- `api.ts`: `api.get/post`, CSRF handling, typed responses, `ApiError{status,message}`.
- `auth.tsx`: React context holding `{me, csrf}`; `login`, `logout`, `refresh`; bootstraps from `/api/me`.
- Verify: `npm run build` succeeds and emits `web/dist`.
- Commit.

### Task 2: App shell, routing, Setup + Login + MFA
- `App.tsx`: routes; redirect to `/setup` when uninitialized (`/api/setup/status`), to `/login` when unauthenticated, to `/mfa` when logged in but MFA not passed.
- `Layout.tsx`: sidebar nav (Devices, Tokens, Groups, Admins, Audit, Releases), top bar (org/email, theme toggle, sign out).
- `Setup.tsx`: org + owner email + password → `/api/setup`.
- `Login.tsx`: email/password → `/api/login`; on success route to `/mfa`.
- `Mfa.tsx`: if not enrolled, show `otpauth_url` as a QR (via a tiny inline QR or the secret in mono for manual entry) + verify; else just verify.
- Verify: build; manual smoke against a running server.
- Commit.

### Task 3: Devices list + detail
- `Devices.tsx`: table (hostname, status dot, agent version, last seen, group); filter by status; poll every 15 s.
- `DeviceDetail.tsx`: inventory facts; command buttons (Ping, Refresh inventory, Rotate certificate, Update agent picker, Uninstall) via `POST /api/devices/{id}/commands`; command history table; revoke (with confirm); uninstall code shown for admin+.
- Commit.

### Task 4: Tokens, Groups, Admins, Audit, Releases
- `Tokens.tsx`: list; create (name, group, expiry, max uses) → show the token once in a copy box; revoke.
- `Groups.tsx`: list + create.
- `Admins.tsx`: list; create (owner only); disable.
- `Audit.tsx`: paged table (actor, action, target, result, time), `before` cursor.
- `Releases.tsx`: list; upload (version + file) via multipart.
- Commit.

### Task 5: Embed in server + Docker build stage
- `internal/server/webui/webui.go`: `//go:embed all:dist`; `Enabled() bool`; `Handler() http.Handler` serving static assets and `index.html` SPA fallback.
- Wire into `app.go`: after building the API handler, wrap so unmatched non-`/api`,`/agent` GETs serve the SPA when enabled.
- `Dockerfile`: add `node:22` stage that runs `npm ci && npm run build` into `web/dist`, copied before `go build`.
- Verify: `npm run build`; `go build ./cmd/server`; run server; load `/` in a browser; full Go suite still green (no UI dependency).
- Commit.

## Notes / deferred
- QR rendering uses a minimal inline generator or shows the secret for manual entry; a full QR lib is optional.
- No automated frontend tests in this plan; correctness is by the typed API client + manual smoke. A Playwright suite is a follow-up.
