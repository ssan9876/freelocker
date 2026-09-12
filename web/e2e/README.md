# Console E2E (Playwright)

Drives the real console served by the Go server against a fresh database —
no mocks. The one smoke test covers first-run setup → sign in → the MFA
enrollment screen (stopping before the TOTP code, which the server's Go
tests cover).

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
