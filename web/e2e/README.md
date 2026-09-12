# Console E2E (Playwright)

Drives the real console served by the Go server against a fresh database —
no mocks.

- `smoke.spec.ts`: first-run setup → sign in → **MFA enrollment and
  verification** → the console, then group create/rename/delete, alert-rule
  create/edit/disable, and admin add/role-change/disable/enable. The
  enrollment screen shows the setup key, so the test reads it and computes the
  6-digit code itself (`totp.ts`) — no seeded secret or test-only endpoint.
- `totp.spec.ts`: checks that helper against the RFC 6238 test vector, so a
  broken code generator fails here rather than looking like a console bug.

Device-scoped screens (device controls, observed applications and their
publisher column) need an enrolled agent reporting data, so they stay in the
Go tests.

## Run locally
1. Start the dev Postgres: `docker compose -f ../deploy/docker-compose.dev.yml up -d`.
2. Create a fresh DB and start the server against it (from the repo root):
   ```
   docker compose -f deploy/docker-compose.dev.yml exec -T postgres psql -U freelocker -c "CREATE DATABASE freelocker_e2e"
   FREELOCKER_DATABASE_URL=postgres://freelocker:freelocker@localhost:55432/freelocker_e2e?sslmode=disable \
   FREELOCKER_INSECURE_COOKIES=true go run ./cmd/server serve
   ```
   (Build the console first with `npm run build` so it's embedded, or open the Vite dev server.)
3. In another shell: `cd web && npx playwright install chromium && E2E_BASE_URL=http://localhost:8080 npm run test:e2e`.
4. Drop the throwaway DB when done: `... psql -U freelocker -c "DROP DATABASE freelocker_e2e WITH (FORCE)"`.

CI runs this automatically (see `.github/workflows/ci.yml`) against a fresh
Postgres service, so each run starts uninitialized.
