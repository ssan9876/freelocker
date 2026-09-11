# Core Platform 1a — Server Backend & Agent Protocol Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `freelocker-server` (Postgres-backed, built-in CA, token enrollment, mTLS gRPC agent stream with heartbeats and signed commands, admin auth + REST API, audit log) plus `agent-sim`, a fake agent used for integration and load testing.

**Architecture:** One Go module `freelocker`. The server exposes a gRPC listener for agents (mTLS with an internal CA) and an HTTP listener for the console REST API (session cookies + TOTP). All state lives in PostgreSQL; every table carries `tenant_id`. `agent-sim` speaks the same gRPC protocol so the whole enrollment → heartbeat → command → revoke flow is testable without Windows.

**Tech Stack:** Go 1.27, gRPC + protobuf (buf for codegen), pgx/v5, goose/v3 migrations, chi/v5, golang.org/x/crypto (bcrypt, hkdf), pquerna/otp, google/uuid, yaml.v3.

**Spec:** `docs/superpowers/specs/2026-09-10-core-platform-design.md`

**Follow-on plans (not in this plan):** 1b — Windows agent service, MSI, updater, agent release hosting. 1c — React console.

## Global Constraints

- Go module path: `freelocker`. Go version floor: 1.27.
- Every table has `tenant_id uuid NOT NULL` (except `tenants` itself). Every store function that reads/writes tenant data takes `tenantID uuid.UUID` as its first argument after `ctx`.
- Device identity on the agent API comes only from the verified mTLS client cert (CN = device UUID) — never from request fields.
- Device keys/certs: ECDSA P-256. Device cert validity 90 days; renewal allowed from day 60. CA validity 10 years.
- Command-signing key and update-signing key: separate Ed25519 keys.
- Private keys at rest: AES-256-GCM with a key derived via HKDF-SHA256 from the server master secret (32+ random bytes in a file).
- Heartbeat interval 30 s; device is online if `last_seen_at` within 90 s. Clock-skew tolerance 5 min.
- Install tokens: 32 random bytes; only SHA-256 hash stored.
- Admin passwords: bcrypt (cost 12). TOTP mandatory. Sessions: HttpOnly, Secure, SameSite=Strict cookie; CSRF header on state-changing requests.
- Roles: `owner`, `admin`, `readonly`.
- `audit_log` is append-only (enforced by DB trigger).
- Test DB: Postgres from `deploy/docker-compose.dev.yml` on `localhost:55432`. **Docker Desktop must be running.** Override with env `FREELOCKER_TEST_DATABASE_URL`.

## Deliberate refinements of the spec (flag to reviewer)

1. **Enrollment trust bootstrap:** the install token string is `<secret>.<ca-pin>` where `<ca-pin>` is the first 16 bytes (hex) of SHA-256 over the CA cert DER. The agent pins the server's agent-TLS chain to that CA during `Enroll`, so enrollment is server-authenticated without a public cert.
2. **Uninstall code:** derived as `HMAC-SHA256(master-derived key, device_id)` (first 10 bytes, base32) instead of being stored. The console can always display it; the agent receives only its SHA-256 at enrollment. The `devices` table therefore has no `uninstall_code_hash` column.
3. **Console TLS:** 1a supports plain HTTP (for use behind a reverse proxy / localhost) or a cert+key file pair. ACME/Let's Encrypt is deferred.

## File Structure

```
go.mod / go.sum
buf.yaml, buf.gen.yaml
proto/freelocker/v1/agent.proto            protocol definitions
gen/freelocker/v1/*.pb.go                  generated (committed)
deploy/docker-compose.dev.yml              Postgres for dev/tests
deploy/docker-compose.yml                  server + Postgres (local install)
deploy/Dockerfile                          server image
internal/server/config/config.go           YAML + env config
internal/server/keys/sealer.go             AES-GCM sealing of secrets with HKDF-derived keys
internal/server/ca/ca.go                   internal CA: create, sign CSR, server cert, pin
internal/server/store/store.go             pool, migrations, ErrNotFound
internal/server/store/migrations/0001_init.sql
internal/server/store/tenants.go           tenants + server_keys
internal/server/store/tokens.go            install tokens + device groups
internal/server/store/devices.go           devices
internal/server/store/commands.go          command queue
internal/server/store/audit.go             audit log
internal/server/store/admins.go            admins + sessions
internal/server/store/storetest/storetest.go  per-test schema helper
internal/server/tokens/tokens.go           token generate/parse/hash
internal/server/bootstrap/bootstrap.go     init tenant, CA, signing keys; load them; uninstall codes
internal/server/hub/hub.go                 connected-agent registry (send, replace, disconnect)
internal/server/agentapi/server.go         Deps, agent TLS config, gRPC server construction
internal/server/agentapi/enroll.go         Enrollment service
internal/server/agentapi/auth.go           mTLS device identity interceptors
internal/server/agentapi/agent.go          Agent service (Connect stream, RenewCertificate)
internal/server/commands/sign.go           command signing/verification, type names
internal/server/commands/commands.go       issue, deliver pending, complete, expire
internal/server/auth/password.go           bcrypt, TOTP, roles
internal/server/auth/sessions.go           session cookies
internal/server/httpapi/api.go, json.go, limiter.go, authn.go   core, setup/login/MFA, middleware
internal/server/httpapi/routes.go, devices.go, tokens.go, admins.go, auditlog.go   resources
internal/server/app/app.go                 wires everything; Run(), Close()
cmd/server/main.go                         CLI: serve, init, create-admin
internal/sim/enroll.go, session.go         protocol-accurate fake agent client
internal/sim/backoff.go, runner.go         reconnect backoff + long-running fake agent
cmd/agent-sim/main.go                      N fake agents for load tests
test/integration/flow_test.go              end-to-end flow
```

Audit writes go straight through `store.AppendAudit` (no separate audit package).

---

### Task 1: Module scaffold and protocol definitions

**Files:**
- Create: `go.mod`, `buf.yaml`, `buf.gen.yaml`, `proto/freelocker/v1/agent.proto`, `gen/freelocker/v1/` (generated), `.gitignore`
- Test: `gen/freelocker/v1/roundtrip_test.go`

**Interfaces:**
- Produces: Go package `freelocker/gen/freelocker/v1` (import alias `flv1`) with messages `EnrollRequest`, `EnrollResponse`, `HardwareInfo`, `Inventory`, `Heartbeat`, `CommandResult`, `Goodbye`, `AgentMessage`, `Command`, `SignedCommand`, `ServerMessage`, `RenewRequest`, `RenewResponse`, enum `CommandType`, services `Enrollment` and `Agent` (`flv1.NewEnrollmentClient`, `flv1.RegisterEnrollmentServer`, `flv1.NewAgentClient`, `flv1.RegisterAgentServer`, `flv1.UnimplementedEnrollmentServer`, `flv1.UnimplementedAgentServer`, stream types `flv1.Agent_ConnectServer` / `flv1.Agent_ConnectClient`).

- [ ] **Step 1: Install codegen tools**

```powershell
go install github.com/bufbuild/buf/cmd/buf@latest
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
buf --version
```
Expected: a version prints. Ensure `$(go env GOPATH)\bin` is on PATH.

- [ ] **Step 2: Init module and config files**

```powershell
go mod init freelocker
```

`.gitignore`:
```
/bin/
*.exe
/web/node_modules/
/web/dist/
```

`buf.yaml`:
```yaml
version: v2
modules:
  - path: proto
```

`buf.gen.yaml`:
```yaml
version: v2
plugins:
  - local: protoc-gen-go
    out: gen
    opt: paths=source_relative
  - local: protoc-gen-go-grpc
    out: gen
    opt: paths=source_relative
inputs:
  - directory: proto
```

- [ ] **Step 3: Write the proto**

`proto/freelocker/v1/agent.proto`:
```proto
syntax = "proto3";

package freelocker.v1;

option go_package = "freelocker/gen/freelocker/v1;flv1";

// Enrollment is called over server-authenticated TLS (no client cert yet).
service Enrollment {
  rpc Enroll(EnrollRequest) returns (EnrollResponse);
}

// Agent requires mTLS with a device certificate issued at enrollment.
service Agent {
  rpc Connect(stream AgentMessage) returns (stream ServerMessage);
  rpc RenewCertificate(RenewRequest) returns (RenewResponse);
}

message HardwareInfo {
  string hostname = 1;
  string os_build = 2;
  string machine_guid = 3;
}

message EnrollRequest {
  string token_secret = 1; // secret part of the install token (before the ".")
  bytes csr_der = 2;
  HardwareInfo hardware = 3;
}

message EnrollResponse {
  string device_id = 1;
  bytes cert_der = 2;
  bytes ca_cert_der = 3;
  bytes command_signing_public_key = 4;
  bytes update_signing_public_key = 5;
  bytes uninstall_code_sha256 = 6;
}

message Inventory {
  string hostname = 1;
  string os_build = 2;
  repeated string ip_addresses = 3;
  string logged_on_user = 4;
  string agent_version = 5;
  int64 uptime_seconds = 6;
}

message Heartbeat {
  Inventory inventory = 1;
  int64 sent_at_unix = 2;
}

message CommandResult {
  string command_id = 1;
  bool success = 2;
  string message = 3;
}

// Goodbye is sent on clean service shutdown so the server can tell
// "stopped normally" from "went silent".
message Goodbye {
  string reason = 1;
}

message AgentMessage {
  oneof body {
    Heartbeat heartbeat = 1;
    CommandResult command_result = 2;
    Goodbye goodbye = 3;
  }
}

enum CommandType {
  COMMAND_TYPE_UNSPECIFIED = 0;
  COMMAND_TYPE_PING = 1;
  COMMAND_TYPE_REFRESH_INVENTORY = 2;
  COMMAND_TYPE_ROTATE_CERTIFICATE = 3;
  COMMAND_TYPE_UNINSTALL = 4;
  COMMAND_TYPE_UPDATE_AGENT = 5;
}

message Command {
  string id = 1;
  CommandType type = 2;
  string device_id = 3;
  int64 issued_at_unix = 4;
  int64 expires_at_unix = 5;
  bytes payload = 6;
}

// command is the deterministic serialization of Command; signature is
// Ed25519 over those exact bytes.
message SignedCommand {
  bytes command = 1;
  bytes signature = 2;
}

message ServerMessage {
  oneof body {
    SignedCommand command = 1;
  }
}

message RenewRequest {
  bytes csr_der = 1;
}

message RenewResponse {
  bytes cert_der = 1;
}
```

- [ ] **Step 4: Generate code and fetch deps**

```powershell
buf generate
go get google.golang.org/grpc google.golang.org/protobuf
go mod tidy
```
Expected: `gen/freelocker/v1/agent.pb.go` and `agent_grpc.pb.go` exist.

- [ ] **Step 5: Write roundtrip test**

`gen/freelocker/v1/roundtrip_test.go`:
```go
package flv1_test

import (
	"testing"

	flv1 "freelocker/gen/freelocker/v1"

	"google.golang.org/protobuf/proto"
)

func TestAgentMessageRoundtrip(t *testing.T) {
	in := &flv1.AgentMessage{Body: &flv1.AgentMessage_Heartbeat{Heartbeat: &flv1.Heartbeat{
		Inventory:  &flv1.Inventory{Hostname: "pc-01", IpAddresses: []string{"10.0.0.5"}},
		SentAtUnix: 1700000000,
	}}}
	b, err := proto.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	out := &flv1.AgentMessage{}
	if err := proto.Unmarshal(b, out); err != nil {
		t.Fatal(err)
	}
	if got := out.GetHeartbeat().GetInventory().GetHostname(); got != "pc-01" {
		t.Fatalf("hostname = %q, want pc-01", got)
	}
}
```

- [ ] **Step 6: Run test**

Run: `go test ./gen/...`
Expected: `ok  freelocker/gen/freelocker/v1`

- [ ] **Step 7: Commit**

```powershell
git add .gitignore go.mod go.sum buf.yaml buf.gen.yaml proto gen
git commit -m "feat: add module scaffold and agent protocol definitions"
```

---

### Task 2: Config, Postgres store, and schema

**Files:**
- Create: `deploy/docker-compose.dev.yml`, `internal/server/config/config.go`, `internal/server/store/store.go`, `internal/server/store/migrations/0001_init.sql`, `internal/server/store/tenants.go`, `internal/server/store/storetest/storetest.go`
- Test: `internal/server/config/config_test.go`, `internal/server/store/tenants_test.go`

**Interfaces:**
- Produces:
  - `config.Config{DatabaseURL, AgentListen, ConsoleListen string; PublicHostnames []string; MasterSecretFile, ConsoleTLSCert, ConsoleTLSKey string}`; `config.Load(path string) (config.Config, error)`
  - `store.Open(ctx, databaseURL string) (*store.Store, error)`, `(*Store).Migrate(ctx) error`, `(*Store).Close()`, `store.ErrNotFound`
  - `(*Store).CreateTenant(ctx, name string) (uuid.UUID, error)`, `(*Store).FirstTenant(ctx) (uuid.UUID, error)` (returns `ErrNotFound` if none)
  - `(*Store).PutServerKey(ctx, tenantID uuid.UUID, name string, publicDER, privateEnc []byte) error`, `(*Store).GetServerKey(ctx, tenantID uuid.UUID, name string) (publicDER, privateEnc []byte, err error)`
  - `storetest.New(t *testing.T) *store.Store` — fresh migrated schema per test.

- [ ] **Step 1: Dev Postgres compose file**

`deploy/docker-compose.dev.yml`:
```yaml
services:
  postgres:
    image: postgres:17
    environment:
      POSTGRES_USER: freelocker
      POSTGRES_PASSWORD: freelocker
      POSTGRES_DB: freelocker
    ports:
      - "55432:5432"
```
Run: `docker compose -f deploy/docker-compose.dev.yml up -d` (start Docker Desktop first).

- [ ] **Step 2: Write failing config test**

`internal/server/config/config_test.go`:
```go
package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadFileThenEnvOverrides(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "server.yaml")
	yaml := "database_url: postgres://file\nagent_listen: \":9443\"\npublic_hostnames: [a.example.com]\n"
	if err := os.WriteFile(p, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FREELOCKER_DATABASE_URL", "postgres://env")

	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.DatabaseURL != "postgres://env" {
		t.Errorf("DatabaseURL = %q, want env override", c.DatabaseURL)
	}
	if c.AgentListen != ":9443" {
		t.Errorf("AgentListen = %q", c.AgentListen)
	}
	if c.ConsoleListen != ":8080" {
		t.Errorf("ConsoleListen default = %q, want :8080", c.ConsoleListen)
	}
	if len(c.PublicHostnames) != 1 || c.PublicHostnames[0] != "a.example.com" {
		t.Errorf("PublicHostnames = %v", c.PublicHostnames)
	}
}

func TestLoadRequiresDatabaseURL(t *testing.T) {
	t.Setenv("FREELOCKER_DATABASE_URL", "")
	if _, err := Load(""); err == nil {
		t.Fatal("expected error when database_url missing")
	}
}
```

- [ ] **Step 3: Run it — expect FAIL** (`undefined: Load`)

Run: `go test ./internal/server/config/`

- [ ] **Step 4: Implement config**

`internal/server/config/config.go`:
```go
// Package config loads server configuration from an optional YAML file,
// with FREELOCKER_* environment variables taking precedence.
package config

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	DatabaseURL      string   `yaml:"database_url"`
	AgentListen      string   `yaml:"agent_listen"`
	ConsoleListen    string   `yaml:"console_listen"`
	PublicHostnames  []string `yaml:"public_hostnames"`
	MasterSecretFile string   `yaml:"master_secret_file"`
	ConsoleTLSCert   string   `yaml:"console_tls_cert"`
	ConsoleTLSKey    string   `yaml:"console_tls_key"`
}

func Load(path string) (Config, error) {
	c := Config{
		AgentListen:      ":8443",
		ConsoleListen:    ":8080",
		PublicHostnames:  []string{"localhost"},
		MasterSecretFile: "master.key",
	}
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return c, fmt.Errorf("read config: %w", err)
		}
		if err := yaml.Unmarshal(b, &c); err != nil {
			return c, fmt.Errorf("parse config: %w", err)
		}
	}
	envStr(&c.DatabaseURL, "FREELOCKER_DATABASE_URL")
	envStr(&c.AgentListen, "FREELOCKER_AGENT_LISTEN")
	envStr(&c.ConsoleListen, "FREELOCKER_CONSOLE_LISTEN")
	envStr(&c.MasterSecretFile, "FREELOCKER_MASTER_SECRET_FILE")
	envStr(&c.ConsoleTLSCert, "FREELOCKER_CONSOLE_TLS_CERT")
	envStr(&c.ConsoleTLSKey, "FREELOCKER_CONSOLE_TLS_KEY")
	if v := os.Getenv("FREELOCKER_PUBLIC_HOSTNAMES"); v != "" {
		c.PublicHostnames = strings.Split(v, ",")
	}
	if c.DatabaseURL == "" {
		return c, errors.New("database_url is required")
	}
	return c, nil
}

func envStr(dst *string, key string) {
	if v := os.Getenv(key); v != "" {
		*dst = v
	}
}
```
Run: `go get gopkg.in/yaml.v3`

- [ ] **Step 5: Run config tests — expect PASS**

Run: `go test ./internal/server/config/`

- [ ] **Step 6: Write schema migration**

`internal/server/store/migrations/0001_init.sql`:
```sql
-- +goose Up
CREATE TABLE tenants (
    id uuid PRIMARY KEY,
    name text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE server_keys (
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    name text NOT NULL,
    public_der bytea NOT NULL,
    private_enc bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, name)
);

CREATE TABLE admins (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    email text NOT NULL,
    password_hash text NOT NULL,
    totp_secret_enc bytea,
    totp_confirmed boolean NOT NULL DEFAULT false,
    role text NOT NULL CHECK (role IN ('owner', 'admin', 'readonly')),
    disabled boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, email)
);

CREATE TABLE sessions (
    id text PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    admin_id uuid NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
    csrf_token text NOT NULL,
    mfa_passed boolean NOT NULL DEFAULT false,
    expires_at timestamptz NOT NULL,
    ip text NOT NULL,
    user_agent text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE device_groups (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    name text NOT NULL,
    UNIQUE (tenant_id, name)
);

CREATE TABLE install_tokens (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    token_hash bytea NOT NULL UNIQUE,
    name text NOT NULL,
    group_id uuid REFERENCES device_groups(id),
    expires_at timestamptz,
    max_uses int,
    uses int NOT NULL DEFAULT 0,
    revoked boolean NOT NULL DEFAULT false,
    created_by uuid REFERENCES admins(id),
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE devices (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    hostname text NOT NULL,
    machine_guid text NOT NULL DEFAULT '',
    group_id uuid REFERENCES device_groups(id),
    cert_serial text NOT NULL,
    cert_expires_at timestamptz NOT NULL,
    os_build text NOT NULL DEFAULT '',
    agent_version text NOT NULL DEFAULT '',
    ips text[] NOT NULL DEFAULT '{}',
    logged_on_user text NOT NULL DEFAULT '',
    uptime_seconds bigint NOT NULL DEFAULT 0,
    last_seen_at timestamptz,
    clean_shutdown boolean NOT NULL DEFAULT false,
    revoked boolean NOT NULL DEFAULT false,
    enrolled_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE commands (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    device_id uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    type text NOT NULL,
    payload bytea NOT NULL DEFAULT '',
    issued_by uuid REFERENCES admins(id),
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    state text NOT NULL CHECK (state IN ('pending', 'sent', 'succeeded', 'failed', 'expired')),
    result text NOT NULL DEFAULT '',
    completed_at timestamptz
);
CREATE INDEX commands_open ON commands (device_id) WHERE state IN ('pending', 'sent');

CREATE TABLE audit_log (
    id bigserial PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    actor text NOT NULL,
    action text NOT NULL,
    target_type text NOT NULL DEFAULT '',
    target_id text NOT NULL DEFAULT '',
    detail_json jsonb NOT NULL DEFAULT '{}',
    ip text NOT NULL DEFAULT '',
    result text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

-- +goose StatementBegin
CREATE FUNCTION audit_log_immutable() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit_log is append-only';
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

CREATE TRIGGER audit_log_no_modify BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_immutable();

-- +goose Down
DROP TRIGGER audit_log_no_modify ON audit_log;
DROP FUNCTION audit_log_immutable();
DROP TABLE audit_log, commands, devices, install_tokens, device_groups, sessions, admins, server_keys, tenants;
```

- [ ] **Step 7: Implement store core, tenants, and test helper**

`internal/server/store/store.go`:
```go
// Package store is the PostgreSQL persistence layer for the server.
package store

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

//go:embed migrations/*.sql
var migrations embed.FS

var ErrNotFound = errors.New("not found")

type Store struct {
	pool *pgxpool.Pool
}

func Open(ctx context.Context, databaseURL string) (*Store, error) {
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, fmt.Errorf("open pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}
	return &Store{pool: pool}, nil
}

func (s *Store) Close() { s.pool.Close() }

func (s *Store) Migrate(ctx context.Context) error {
	fsys, err := fs.Sub(migrations, "migrations")
	if err != nil {
		return err
	}
	db := stdlib.OpenDBFromPool(s.pool)
	defer db.Close()
	p, err := goose.NewProvider(goose.DialectPostgres, db, fsys)
	if err != nil {
		return fmt.Errorf("migration provider: %w", err)
	}
	if _, err := p.Up(ctx); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	return nil
}
```

`internal/server/store/tenants.go`:
```go
package store

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func (s *Store) CreateTenant(ctx context.Context, name string) (uuid.UUID, error) {
	id := uuid.New()
	_, err := s.pool.Exec(ctx, `INSERT INTO tenants (id, name) VALUES ($1, $2)`, id, name)
	return id, err
}

// FirstTenant returns the oldest tenant. v1 is single-tenant.
func (s *Store) FirstTenant(ctx context.Context) (uuid.UUID, error) {
	var id uuid.UUID
	err := s.pool.QueryRow(ctx, `SELECT id FROM tenants ORDER BY created_at LIMIT 1`).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return id, ErrNotFound
	}
	return id, err
}

func (s *Store) PutServerKey(ctx context.Context, tenantID uuid.UUID, name string, publicDER, privateEnc []byte) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO server_keys (tenant_id, name, public_der, private_enc) VALUES ($1, $2, $3, $4)`,
		tenantID, name, publicDER, privateEnc)
	return err
}

func (s *Store) GetServerKey(ctx context.Context, tenantID uuid.UUID, name string) (publicDER, privateEnc []byte, err error) {
	err = s.pool.QueryRow(ctx,
		`SELECT public_der, private_enc FROM server_keys WHERE tenant_id = $1 AND name = $2`,
		tenantID, name).Scan(&publicDER, &privateEnc)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	return publicDER, privateEnc, err
}
```

`internal/server/store/storetest/storetest.go`:
```go
// Package storetest provides an isolated, migrated store per test.
package storetest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"freelocker/internal/server/store"

	"github.com/jackc/pgx/v5"
)

const defaultURL = "postgres://freelocker:freelocker@localhost:55432/freelocker?sslmode=disable"

func New(t *testing.T) *store.Store {
	t.Helper()
	ctx := context.Background()
	url := os.Getenv("FREELOCKER_TEST_DATABASE_URL")
	if url == "" {
		url = defaultURL
	}
	conn, err := pgx.Connect(ctx, url)
	if err != nil {
		t.Fatalf("connect test db (start it: docker compose -f deploy/docker-compose.dev.yml up -d): %v", err)
	}
	b := make([]byte, 8)
	rand.Read(b)
	schema := "t_" + hex.EncodeToString(b)
	if _, err := conn.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		conn.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
		conn.Close(context.Background())
	})

	sep := "?"
	if strings.Contains(url, "?") {
		sep = "&"
	}
	s, err := store.Open(ctx, url+sep+"search_path="+schema)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	return s
}
```

Run: `go get github.com/jackc/pgx/v5 github.com/pressly/goose/v3 github.com/google/uuid`

- [ ] **Step 8: Write tenant/key store test**

`internal/server/store/tenants_test.go`:
```go
package store_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"freelocker/internal/server/store"
	"freelocker/internal/server/store/storetest"
)

func TestTenantsAndServerKeys(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)

	if _, err := s.FirstTenant(ctx); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("FirstTenant on empty db err = %v, want ErrNotFound", err)
	}
	id, err := s.CreateTenant(ctx, "Acme")
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.FirstTenant(ctx)
	if err != nil || got != id {
		t.Fatalf("FirstTenant = %v, %v; want %v", got, err, id)
	}

	if err := s.PutServerKey(ctx, id, "ca", []byte("pub"), []byte("priv")); err != nil {
		t.Fatal(err)
	}
	pub, priv, err := s.GetServerKey(ctx, id, "ca")
	if err != nil || !bytes.Equal(pub, []byte("pub")) || !bytes.Equal(priv, []byte("priv")) {
		t.Fatalf("GetServerKey = %q %q %v", pub, priv, err)
	}
	if _, _, err := s.GetServerKey(ctx, id, "missing"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing key err = %v", err)
	}
	// Migrate must be idempotent.
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
}
```

- [ ] **Step 9: Run tests — expect PASS**

Run: `go mod tidy; go test ./internal/server/...`
Expected: `ok` for `config` and `store`.

- [ ] **Step 10: Commit**

```powershell
git add deploy internal/server/config internal/server/store go.mod go.sum
git commit -m "feat: add server config, Postgres store, and initial schema"
```

---

### Task 3: Secret sealing and internal CA

**Files:**
- Create: `internal/server/keys/sealer.go`, `internal/server/ca/ca.go`
- Test: `internal/server/keys/sealer_test.go`, `internal/server/ca/ca_test.go`

**Interfaces:**
- Produces:
  - `keys.LoadOrCreateMasterSecret(path string) ([]byte, error)` — creates a 32-byte random file (mode 0600) if missing.
  - `keys.Derive(master []byte, purpose string) ([]byte, error)` — 32-byte HKDF-SHA256 subkey.
  - `keys.NewSealer(master []byte, purpose string) (*keys.Sealer, error)`; `(*Sealer).Seal(plain []byte) []byte`; `(*Sealer).Open(sealed []byte) ([]byte, error)`
  - `ca.New(commonName string, now time.Time) (*ca.CA, error)`; `ca.Load(certDER, keyDER []byte) (*ca.CA, error)`
  - `(*CA).Cert *x509.Certificate` (field); `(*CA).MarshalKey() ([]byte, error)`; `(*CA).Pin() string` (32 hex chars)
  - `(*CA).SignDevice(csrDER []byte, deviceID uuid.UUID, now time.Time) (certDER []byte, serial string, notAfter time.Time, err error)`
  - `(*CA).IssueServerCert(hostnames []string, now time.Time) (tls.Certificate, error)`
  - `ca.DeviceCertValidity = 90*24*time.Hour`, `ca.RenewAfter = 60*24*time.Hour`, `ca.PinFromCert(der []byte) string`

- [ ] **Step 1: Write failing sealer tests**

`internal/server/keys/sealer_test.go`:
```go
package keys

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestSealerRoundtripAndPurposeIsolation(t *testing.T) {
	master := bytes.Repeat([]byte{7}, 32)
	a, err := NewSealer(master, "server-keys")
	if err != nil {
		t.Fatal(err)
	}
	sealed := a.Seal([]byte("secret"))
	got, err := a.Open(sealed)
	if err != nil || string(got) != "secret" {
		t.Fatalf("Open = %q, %v", got, err)
	}
	b, _ := NewSealer(master, "other-purpose")
	if _, err := b.Open(sealed); err == nil {
		t.Fatal("different purpose must not decrypt")
	}
	sealed[len(sealed)-1] ^= 1
	if _, err := a.Open(sealed); err == nil {
		t.Fatal("tampered ciphertext must fail")
	}
}

func TestNewSealerRejectsShortMaster(t *testing.T) {
	if _, err := NewSealer(make([]byte, 16), "x"); err == nil {
		t.Fatal("expected error for 16-byte master")
	}
}

func TestLoadOrCreateMasterSecret(t *testing.T) {
	p := filepath.Join(t.TempDir(), "master.key")
	first, err := LoadOrCreateMasterSecret(p)
	if err != nil || len(first) != 32 {
		t.Fatalf("create: len=%d err=%v", len(first), err)
	}
	second, err := LoadOrCreateMasterSecret(p)
	if err != nil || !bytes.Equal(first, second) {
		t.Fatal("second load must return same secret")
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatal(err)
	}
}
```

- [ ] **Step 2: Run — expect FAIL** (`undefined: NewSealer`)

Run: `go test ./internal/server/keys/`

- [ ] **Step 3: Implement sealer**

`internal/server/keys/sealer.go`:
```go
// Package keys protects server secrets at rest using keys derived from a
// single master secret held outside the database.
package keys

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
)

const masterLen = 32

func LoadOrCreateMasterSecret(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err == nil {
		if len(b) < masterLen {
			return nil, fmt.Errorf("master secret %s is shorter than %d bytes", path, masterLen)
		}
		return b, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	b = make([]byte, masterLen)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return nil, fmt.Errorf("write master secret: %w", err)
	}
	return b, nil
}

func Derive(master []byte, purpose string) ([]byte, error) {
	if len(master) < masterLen {
		return nil, fmt.Errorf("master secret must be at least %d bytes", masterLen)
	}
	return hkdf.Key(sha256.New, master, nil, purpose, 32)
}

type Sealer struct {
	aead cipher.AEAD
}

func NewSealer(master []byte, purpose string) (*Sealer, error) {
	k, err := Derive(master, purpose)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Sealer{aead: aead}, nil
}

// Seal returns nonce || ciphertext.
func (s *Sealer) Seal(plain []byte) []byte {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		panic(err) // crypto/rand never fails on supported platforms
	}
	return s.aead.Seal(nonce, nonce, plain, nil)
}

func (s *Sealer) Open(sealed []byte) ([]byte, error) {
	n := s.aead.NonceSize()
	if len(sealed) < n {
		return nil, errors.New("sealed value too short")
	}
	return s.aead.Open(nil, sealed[:n], sealed[n:], nil)
}
```

- [ ] **Step 4: Run sealer tests — expect PASS**

Run: `go test ./internal/server/keys/`

- [ ] **Step 5: Write failing CA tests**

`internal/server/ca/ca_test.go`:
```go
package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"

	"github.com/google/uuid"
)

func csr(t *testing.T, key any, cn string) []byte {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestSignDeviceProducesClientCertChainedToCA(t *testing.T) {
	now := time.Now()
	c, err := New("FreeLocker Test CA", now)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	id := uuid.New()

	der, serial, notAfter, err := c.SignDevice(csr(t, key, "ignored"), id, now)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != id.String() {
		t.Errorf("CN = %q, want device id (CSR CN must be ignored)", cert.Subject.CommonName)
	}
	if serial == "" || !notAfter.Equal(cert.NotAfter) {
		t.Errorf("serial=%q notAfter=%v cert.NotAfter=%v", serial, notAfter, cert.NotAfter)
	}
	if d := cert.NotAfter.Sub(now); d < DeviceCertValidity-time.Minute || d > DeviceCertValidity+time.Minute {
		t.Errorf("validity = %v", d)
	}
	pool := x509.NewCertPool()
	pool.AddCert(c.Cert)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestSignDeviceRejectsNonP256(t *testing.T) {
	c, _ := New("CA", time.Now())
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	if _, _, _, err := c.SignDevice(csr(t, rsaKey, "x"), uuid.New(), time.Now()); err == nil {
		t.Fatal("expected RSA CSR to be rejected")
	}
	if _, _, _, err := c.SignDevice([]byte("garbage"), uuid.New(), time.Now()); err == nil {
		t.Fatal("expected garbage CSR to be rejected")
	}
}

func TestServerCertAndReload(t *testing.T) {
	now := time.Now()
	c, _ := New("CA", now)
	tc, err := c.IssueServerCert([]string{"fl.example.com", "127.0.0.1"}, now)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(tc.Certificate[0])
	pool := x509.NewCertPool()
	pool.AddCert(c.Cert)
	for _, host := range []string{"fl.example.com", "127.0.0.1"} {
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: host}); err != nil {
			t.Errorf("verify %s: %v", host, err)
		}
	}

	keyDER, err := c.MarshalKey()
	if err != nil {
		t.Fatal(err)
	}
	c2, err := Load(c.Cert.Raw, keyDER)
	if err != nil {
		t.Fatal(err)
	}
	if c2.Pin() != c.Pin() || len(c.Pin()) != 32 {
		t.Errorf("pin mismatch or wrong length: %q vs %q", c2.Pin(), c.Pin())
	}
	if PinFromCert(c.Cert.Raw) != c.Pin() {
		t.Error("PinFromCert disagrees with Pin")
	}
}
```

- [ ] **Step 6: Run — expect FAIL** (`undefined: New`)

Run: `go test ./internal/server/ca/`

- [ ] **Step 7: Implement CA**

`internal/server/ca/ca.go`:
```go
// Package ca is the server's internal certificate authority. It issues
// device client certificates and the agent-facing server certificate.
package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net"
	"time"

	"github.com/google/uuid"
)

const (
	DeviceCertValidity = 90 * 24 * time.Hour
	RenewAfter         = 60 * 24 * time.Hour
	caValidity         = 10 * 365 * 24 * time.Hour
	serverCertValidity = 365 * 24 * time.Hour
	backdate           = 5 * time.Minute // clock-skew tolerance
)

type CA struct {
	Cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func New(commonName string, now time.Time) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          randSerial(),
		Subject:               pkix.Name{CommonName: commonName, Organization: []string{"FreeLocker"}},
		NotBefore:             now.Add(-backdate),
		NotAfter:              now.Add(caValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{Cert: cert, key: key}, nil
}

func Load(certDER, keyDER []byte) (*CA, error) {
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parse CA cert: %w", err)
	}
	k, err := x509.ParsePKCS8PrivateKey(keyDER)
	if err != nil {
		return nil, fmt.Errorf("parse CA key: %w", err)
	}
	ek, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("CA key is not ECDSA")
	}
	return &CA{Cert: cert, key: ek}, nil
}

func (c *CA) MarshalKey() ([]byte, error) { return x509.MarshalPKCS8PrivateKey(c.key) }

func (c *CA) Pin() string { return PinFromCert(c.Cert.Raw) }

// PinFromCert is the value embedded in install tokens so agents can
// authenticate the server before they hold any certificate.
func PinFromCert(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:16])
}

func (c *CA) SignDevice(csrDER []byte, deviceID uuid.UUID, now time.Time) ([]byte, string, time.Time, error) {
	req, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, "", time.Time{}, fmt.Errorf("parse CSR: %w", err)
	}
	if err := req.CheckSignature(); err != nil {
		return nil, "", time.Time{}, fmt.Errorf("CSR signature: %w", err)
	}
	pub, ok := req.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, "", time.Time{}, errors.New("CSR key must be ECDSA P-256")
	}
	serial := randSerial()
	notAfter := now.Add(DeviceCertValidity).Truncate(time.Second)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: deviceID.String()},
		NotBefore:    now.Add(-backdate),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.Cert, pub, c.key)
	if err != nil {
		return nil, "", time.Time{}, err
	}
	return der, serial.Text(16), notAfter, nil
}

func (c *CA) IssueServerCert(hostnames []string, now time.Time) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: randSerial(),
		Subject:      pkix.Name{CommonName: "freelocker-server"},
		NotBefore:    now.Add(-backdate),
		NotAfter:     now.Add(serverCertValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, h := range hostnames {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.Cert, &key.PublicKey, c.key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der, c.Cert.Raw}, PrivateKey: key}, nil
}

func randSerial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		panic(err)
	}
	return n
}
```

- [ ] **Step 8: Run — expect PASS**

Run: `go test ./internal/server/keys/ ./internal/server/ca/`

- [ ] **Step 9: Commit**

```powershell
git add internal/server/keys internal/server/ca go.mod go.sum
git commit -m "feat: add secret sealing and internal certificate authority"
```

---

### Task 4: Install tokens and device groups

**Files:**
- Create: `internal/server/tokens/tokens.go`, `internal/server/store/tokens.go`
- Test: `internal/server/tokens/tokens_test.go`, `internal/server/store/tokens_test.go`

**Interfaces:**
- Consumes: `storetest.New`, `(*Store).CreateTenant` (Task 2).
- Produces:
  - `tokens.Generate(caPin string) (full string, hash []byte, err error)`; `tokens.Parse(full string) (secret, caPin string, err error)`; `tokens.Hash(secret string) []byte`
  - `store.DeviceGroup{ID uuid.UUID; Name string}`; `(*Store).CreateDeviceGroup(ctx, tenantID uuid.UUID, name string) (uuid.UUID, error)`; `(*Store).ListDeviceGroups(ctx, tenantID uuid.UUID) ([]store.DeviceGroup, error)`
  - `store.InstallToken{ID uuid.UUID; Name string; GroupID *uuid.UUID; ExpiresAt *time.Time; MaxUses *int; Uses int; Revoked bool; CreatedBy *uuid.UUID; CreatedAt time.Time}`
  - `(*Store).CreateInstallToken(ctx, tenantID uuid.UUID, t store.InstallToken, hash []byte) (uuid.UUID, error)`; `(*Store).ListInstallTokens(ctx, tenantID uuid.UUID) ([]store.InstallToken, error)`; `(*Store).RevokeInstallToken(ctx, tenantID, id uuid.UUID) error` (ErrNotFound if absent)

- [ ] **Step 1: Write failing token tests**

`internal/server/tokens/tokens_test.go`:
```go
package tokens

import (
	"bytes"
	"strings"
	"testing"
)

func TestGenerateParseHash(t *testing.T) {
	pin := strings.Repeat("ab", 16)
	full, hash, err := Generate(pin)
	if err != nil {
		t.Fatal(err)
	}
	secret, gotPin, err := Parse(full)
	if err != nil {
		t.Fatal(err)
	}
	if gotPin != pin {
		t.Errorf("pin = %q", gotPin)
	}
	if len(secret) != 43 { // 32 bytes, base64url no padding
		t.Errorf("secret len = %d", len(secret))
	}
	if !bytes.Equal(Hash(secret), hash) {
		t.Error("Hash(secret) must equal hash from Generate")
	}
	other, _, _ := Generate(pin)
	if other == full {
		t.Error("tokens must be unique")
	}
}

func TestParseRejectsMalformed(t *testing.T) {
	for _, s := range []string{"", "nodot", "a.b.c", ".pin", "secret."} {
		if _, _, err := Parse(s); err == nil {
			t.Errorf("Parse(%q) should fail", s)
		}
	}
}
```

- [ ] **Step 2: Run — expect FAIL**

Run: `go test ./internal/server/tokens/`

- [ ] **Step 3: Implement tokens**

`internal/server/tokens/tokens.go`:
```go
// Package tokens creates and parses install tokens of the form
// "<secret>.<ca-pin>". Only SHA-256(secret) is ever stored.
package tokens

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
)

func Generate(caPin string) (full string, hash []byte, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", nil, err
	}
	secret := base64.RawURLEncoding.EncodeToString(b)
	return secret + "." + caPin, Hash(secret), nil
}

func Parse(full string) (secret, caPin string, err error) {
	parts := strings.Split(full, ".")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", errors.New("malformed install token")
	}
	return parts[0], parts[1], nil
}

func Hash(secret string) []byte {
	sum := sha256.Sum256([]byte(secret))
	return sum[:]
}
```

- [ ] **Step 4: Run — expect PASS**

Run: `go test ./internal/server/tokens/`

- [ ] **Step 5: Write failing store test**

`internal/server/store/tokens_test.go`:
```go
package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"freelocker/internal/server/store"
	"freelocker/internal/server/store/storetest"

	"github.com/google/uuid"
)

func TestInstallTokensAndGroups(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	tenant, _ := s.CreateTenant(ctx, "Acme")

	gid, err := s.CreateDeviceGroup(ctx, tenant, "Workstations")
	if err != nil {
		t.Fatal(err)
	}
	groups, err := s.ListDeviceGroups(ctx, tenant)
	if err != nil || len(groups) != 1 || groups[0].Name != "Workstations" {
		t.Fatalf("groups = %+v, %v", groups, err)
	}

	exp := time.Now().Add(24 * time.Hour).Truncate(time.Microsecond)
	max := 5
	id, err := s.CreateInstallToken(ctx, tenant, store.InstallToken{
		Name: "HQ rollout", GroupID: &gid, ExpiresAt: &exp, MaxUses: &max,
	}, []byte("hash-1"))
	if err != nil {
		t.Fatal(err)
	}
	list, err := s.ListInstallTokens(ctx, tenant)
	if err != nil || len(list) != 1 {
		t.Fatalf("list = %+v, %v", list, err)
	}
	got := list[0]
	if got.ID != id || got.Name != "HQ rollout" || *got.GroupID != gid || !got.ExpiresAt.Equal(exp) || *got.MaxUses != 5 || got.Revoked {
		t.Fatalf("token = %+v", got)
	}

	if err := s.RevokeInstallToken(ctx, tenant, id); err != nil {
		t.Fatal(err)
	}
	list, _ = s.ListInstallTokens(ctx, tenant)
	if !list[0].Revoked {
		t.Error("token should be revoked")
	}
	if err := s.RevokeInstallToken(ctx, tenant, uuid.New()); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("revoke missing err = %v", err)
	}
	other, _ := s.CreateTenant(ctx, "Other")
	if list, _ := s.ListInstallTokens(ctx, other); len(list) != 0 {
		t.Error("tokens must be tenant-scoped")
	}
}
```

- [ ] **Step 6: Run — expect FAIL**

Run: `go test ./internal/server/store/ -run TestInstallTokens`

- [ ] **Step 7: Implement store functions**

`internal/server/store/tokens.go`:
```go
package store

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type DeviceGroup struct {
	ID   uuid.UUID
	Name string
}

type InstallToken struct {
	ID        uuid.UUID
	Name      string
	GroupID   *uuid.UUID
	ExpiresAt *time.Time
	MaxUses   *int
	Uses      int
	Revoked   bool
	CreatedBy *uuid.UUID
	CreatedAt time.Time
}

func (s *Store) CreateDeviceGroup(ctx context.Context, tenantID uuid.UUID, name string) (uuid.UUID, error) {
	id := uuid.New()
	_, err := s.pool.Exec(ctx, `INSERT INTO device_groups (id, tenant_id, name) VALUES ($1, $2, $3)`, id, tenantID, name)
	return id, err
}

func (s *Store) ListDeviceGroups(ctx context.Context, tenantID uuid.UUID) ([]DeviceGroup, error) {
	rows, _ := s.pool.Query(ctx, `SELECT id, name FROM device_groups WHERE tenant_id = $1 ORDER BY name`, tenantID)
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (DeviceGroup, error) {
		var g DeviceGroup
		return g, r.Scan(&g.ID, &g.Name)
	})
}

func (s *Store) CreateInstallToken(ctx context.Context, tenantID uuid.UUID, t InstallToken, hash []byte) (uuid.UUID, error) {
	id := uuid.New()
	_, err := s.pool.Exec(ctx, `
		INSERT INTO install_tokens (id, tenant_id, token_hash, name, group_id, expires_at, max_uses, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		id, tenantID, hash, t.Name, t.GroupID, t.ExpiresAt, t.MaxUses, t.CreatedBy)
	return id, err
}

func (s *Store) ListInstallTokens(ctx context.Context, tenantID uuid.UUID) ([]InstallToken, error) {
	rows, _ := s.pool.Query(ctx, `
		SELECT id, name, group_id, expires_at, max_uses, uses, revoked, created_by, created_at
		FROM install_tokens WHERE tenant_id = $1 ORDER BY created_at DESC`, tenantID)
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (InstallToken, error) {
		var t InstallToken
		return t, r.Scan(&t.ID, &t.Name, &t.GroupID, &t.ExpiresAt, &t.MaxUses, &t.Uses, &t.Revoked, &t.CreatedBy, &t.CreatedAt)
	})
}

func (s *Store) RevokeInstallToken(ctx context.Context, tenantID, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `UPDATE install_tokens SET revoked = true WHERE tenant_id = $1 AND id = $2`, tenantID, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
```

- [ ] **Step 8: Run — expect PASS**

Run: `go test ./internal/server/tokens/ ./internal/server/store/`

- [ ] **Step 9: Commit**

```powershell
git add internal/server/tokens internal/server/store
git commit -m "feat: add install tokens and device groups"
```

---

### Task 5: Bootstrap — tenant, CA, and signing keys

**Files:**
- Create: `internal/server/bootstrap/bootstrap.go`
- Test: `internal/server/bootstrap/bootstrap_test.go`

**Interfaces:**
- Consumes: `keys.NewSealer`, `keys.Derive` (Task 3); `ca.New`, `ca.Load`, `(*CA).MarshalKey` (Task 3); `(*Store).CreateTenant`, `FirstTenant`, `PutServerKey`, `GetServerKey` (Task 2).
- Produces:
  - `bootstrap.ErrAlreadyInitialized`
  - `bootstrap.Init(ctx, s *store.Store, master []byte, tenantName string, now time.Time) (uuid.UUID, error)`
  - `bootstrap.Keys{TenantID uuid.UUID; CA *ca.CA; CommandKey ed25519.PrivateKey; UpdateKey ed25519.PrivateKey}`; `bootstrap.Load(ctx, s *store.Store, master []byte) (*bootstrap.Keys, error)`
  - `(*Keys).UninstallCode(deviceID uuid.UUID) string` (16 base32 chars); `(*Keys).UninstallCodeHash(deviceID uuid.UUID) []byte` (SHA-256 of the code)

- [ ] **Step 1: Write failing test**

`internal/server/bootstrap/bootstrap_test.go`:
```go
package bootstrap

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"freelocker/internal/server/store/storetest"

	"github.com/google/uuid"
)

func TestInitThenLoad(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	master := bytes.Repeat([]byte{1}, 32)

	tenant, err := Init(ctx, s, master, "Acme", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Init(ctx, s, master, "Acme", time.Now()); !errors.Is(err, ErrAlreadyInitialized) {
		t.Fatalf("second Init err = %v, want ErrAlreadyInitialized", err)
	}

	k, err := Load(ctx, s, master)
	if err != nil {
		t.Fatal(err)
	}
	if k.TenantID != tenant || !k.CA.Cert.IsCA {
		t.Fatalf("keys = %+v", k)
	}
	msg := []byte("hello")
	if !ed25519.Verify(k.CommandKey.Public().(ed25519.PublicKey), msg, ed25519.Sign(k.CommandKey, msg)) {
		t.Error("command key unusable")
	}
	if bytes.Equal(k.CommandKey, k.UpdateKey) {
		t.Error("command and update keys must differ")
	}

	dev := uuid.New()
	code := k.UninstallCode(dev)
	if len(code) != 16 || code != k.UninstallCode(dev) || code == k.UninstallCode(uuid.New()) {
		t.Errorf("uninstall code %q not stable/unique", code)
	}
	sum := sha256.Sum256([]byte(code))
	if !bytes.Equal(k.UninstallCodeHash(dev), sum[:]) {
		t.Error("UninstallCodeHash mismatch")
	}

	if _, err := Load(ctx, s, bytes.Repeat([]byte{2}, 32)); err == nil {
		t.Error("Load with wrong master secret must fail")
	}
}
```

- [ ] **Step 2: Run — expect FAIL**

Run: `go test ./internal/server/bootstrap/`

- [ ] **Step 3: Implement bootstrap**

`internal/server/bootstrap/bootstrap.go`:
```go
// Package bootstrap performs first-run initialization (tenant, CA,
// signing keys) and loads those keys at server start.
package bootstrap

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"fmt"
	"time"

	"freelocker/internal/server/ca"
	"freelocker/internal/server/keys"
	"freelocker/internal/server/store"

	"github.com/google/uuid"
)

var ErrAlreadyInitialized = errors.New("server already initialized")

const (
	sealPurpose      = "server-keys"
	uninstallPurpose = "uninstall-code"
	keyCA            = "ca"
	keyCommand       = "command-signing"
	keyUpdate        = "update-signing"
)

type Keys struct {
	TenantID     uuid.UUID
	CA           *ca.CA
	CommandKey   ed25519.PrivateKey
	UpdateKey    ed25519.PrivateKey
	uninstallKey []byte
}

func Init(ctx context.Context, s *store.Store, master []byte, tenantName string, now time.Time) (uuid.UUID, error) {
	if _, err := s.FirstTenant(ctx); err == nil {
		return uuid.Nil, ErrAlreadyInitialized
	} else if !errors.Is(err, store.ErrNotFound) {
		return uuid.Nil, err
	}
	sealer, err := keys.NewSealer(master, sealPurpose)
	if err != nil {
		return uuid.Nil, err
	}
	tenant, err := s.CreateTenant(ctx, tenantName)
	if err != nil {
		return uuid.Nil, err
	}

	authority, err := ca.New(tenantName+" FreeLocker CA", now)
	if err != nil {
		return uuid.Nil, err
	}
	caKey, err := authority.MarshalKey()
	if err != nil {
		return uuid.Nil, err
	}
	if err := s.PutServerKey(ctx, tenant, keyCA, authority.Cert.Raw, sealer.Seal(caKey)); err != nil {
		return uuid.Nil, err
	}
	for _, name := range []string{keyCommand, keyUpdate} {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return uuid.Nil, err
		}
		if err := s.PutServerKey(ctx, tenant, name, pub, sealer.Seal(priv)); err != nil {
			return uuid.Nil, err
		}
	}
	return tenant, nil
}

func Load(ctx context.Context, s *store.Store, master []byte) (*Keys, error) {
	tenant, err := s.FirstTenant(ctx)
	if err != nil {
		return nil, fmt.Errorf("load tenant (run `freelocker-server init` first?): %w", err)
	}
	sealer, err := keys.NewSealer(master, sealPurpose)
	if err != nil {
		return nil, err
	}
	open := func(name string) (pub, priv []byte, err error) {
		pub, sealed, err := s.GetServerKey(ctx, tenant, name)
		if err != nil {
			return nil, nil, fmt.Errorf("load key %s: %w", name, err)
		}
		priv, err = sealer.Open(sealed)
		if err != nil {
			return nil, nil, fmt.Errorf("decrypt key %s (wrong master secret?): %w", name, err)
		}
		return pub, priv, nil
	}

	certDER, caKey, err := open(keyCA)
	if err != nil {
		return nil, err
	}
	authority, err := ca.Load(certDER, caKey)
	if err != nil {
		return nil, err
	}
	_, cmdKey, err := open(keyCommand)
	if err != nil {
		return nil, err
	}
	_, updKey, err := open(keyUpdate)
	if err != nil {
		return nil, err
	}
	uk, err := keys.Derive(master, uninstallPurpose)
	if err != nil {
		return nil, err
	}
	return &Keys{
		TenantID:     tenant,
		CA:           authority,
		CommandKey:   ed25519.PrivateKey(cmdKey),
		UpdateKey:    ed25519.PrivateKey(updKey),
		uninstallKey: uk,
	}, nil
}

// UninstallCode is derived, not stored, so the console can always show it.
func (k *Keys) UninstallCode(deviceID uuid.UUID) string {
	m := hmac.New(sha256.New, k.uninstallKey)
	m.Write(deviceID[:])
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(m.Sum(nil)[:10])
}

func (k *Keys) UninstallCodeHash(deviceID uuid.UUID) []byte {
	sum := sha256.Sum256([]byte(k.UninstallCode(deviceID)))
	return sum[:]
}
```

- [ ] **Step 4: Run — expect PASS**

Run: `go test ./internal/server/bootstrap/`

- [ ] **Step 5: Commit**

```powershell
git add internal/server/bootstrap
git commit -m "feat: add first-run bootstrap of tenant, CA, and signing keys"
```

---

### Task 6: Audit log store

**Files:**
- Create: `internal/server/store/audit.go`
- Modify: `internal/server/store/storetest/storetest.go` (add `NewWithSQL`)
- Test: `internal/server/store/audit_test.go`

**Interfaces:**
- Consumes: `storetest.New`, `(*Store).CreateTenant` (Task 2).
- Produces:
  - `store.AuditEntry{ID int64; Actor, Action, TargetType, TargetID string; Detail map[string]any; IP, Result string; CreatedAt time.Time}`
  - `(*Store).AppendAudit(ctx, tenantID uuid.UUID, e store.AuditEntry) error`
  - `(*Store).ListAudit(ctx, tenantID uuid.UUID, limit int, beforeID int64) ([]store.AuditEntry, error)` — newest first; `beforeID == 0` means "from the latest".
  - `storetest.NewWithSQL(t) (*store.Store, func(sql string, args ...any) error)` — the func runs raw SQL in the test schema.
  - Actor string convention used by all later tasks: `"admin:<email>"`, `"device:<uuid>"`, `"system"`. Result values: `"success"`, `"failure"`.

- [ ] **Step 1: Replace storetest with a version that also exposes raw SQL**

`internal/server/store/storetest/storetest.go` (full replacement):
```go
// Package storetest provides an isolated, migrated store per test.
package storetest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"freelocker/internal/server/store"

	"github.com/jackc/pgx/v5"
)

const defaultURL = "postgres://freelocker:freelocker@localhost:55432/freelocker?sslmode=disable"

func New(t *testing.T) *store.Store {
	s, _ := NewWithSQL(t)
	return s
}

// NewWithSQL also returns a function that executes raw SQL inside the
// test's schema, for asserting database-level guarantees.
func NewWithSQL(t *testing.T) (*store.Store, func(sql string, args ...any) error) {
	t.Helper()
	ctx := context.Background()
	url := os.Getenv("FREELOCKER_TEST_DATABASE_URL")
	if url == "" {
		url = defaultURL
	}
	conn, err := pgx.Connect(ctx, url)
	if err != nil {
		t.Fatalf("connect test db (start it: docker compose -f deploy/docker-compose.dev.yml up -d): %v", err)
	}
	b := make([]byte, 8)
	rand.Read(b)
	schema := "t_" + hex.EncodeToString(b)
	if _, err := conn.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, "SET search_path TO "+schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		conn.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
		conn.Close(context.Background())
	})

	sep := "?"
	if strings.Contains(url, "?") {
		sep = "&"
	}
	s, err := store.Open(ctx, url+sep+"search_path="+schema)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	exec := func(sql string, args ...any) error {
		_, err := conn.Exec(ctx, sql, args...)
		return err
	}
	return s, exec
}
```

- [ ] **Step 2: Write failing audit test**

`internal/server/store/audit_test.go`:
```go
package store_test

import (
	"context"
	"testing"

	"freelocker/internal/server/store"
	"freelocker/internal/server/store/storetest"
)

func TestAuditAppendListAndImmutability(t *testing.T) {
	ctx := context.Background()
	s, execSQL := storetest.NewWithSQL(t)
	tenant, _ := s.CreateTenant(ctx, "Acme")

	for _, action := range []string{"a1", "a2", "a3"} {
		err := s.AppendAudit(ctx, tenant, store.AuditEntry{
			Actor: "admin:x@example.com", Action: action, TargetType: "device", TargetID: "d1",
			Detail: map[string]any{"k": "v"}, IP: "10.0.0.1", Result: "success",
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	page, err := s.ListAudit(ctx, tenant, 2, 0)
	if err != nil || len(page) != 2 || page[0].Action != "a3" || page[1].Action != "a2" {
		t.Fatalf("page1 = %+v, %v", page, err)
	}
	if page[0].Detail["k"] != "v" || page[0].IP != "10.0.0.1" || page[0].CreatedAt.IsZero() {
		t.Errorf("entry fields = %+v", page[0])
	}
	next, _ := s.ListAudit(ctx, tenant, 2, page[1].ID)
	if len(next) != 1 || next[0].Action != "a1" {
		t.Fatalf("page2 = %+v", next)
	}

	if err := execSQL("UPDATE audit_log SET action = 'tampered'"); err == nil {
		t.Error("UPDATE on audit_log must fail")
	}
	if err := execSQL("DELETE FROM audit_log"); err == nil {
		t.Error("DELETE on audit_log must fail")
	}
}
```

- [ ] **Step 3: Run — expect FAIL** (`s.AppendAudit undefined`)

Run: `go test ./internal/server/store/ -run TestAudit`

- [ ] **Step 4: Implement audit store**

`internal/server/store/audit.go`:
```go
package store

import (
	"context"
	"math"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type AuditEntry struct {
	ID         int64
	Actor      string
	Action     string
	TargetType string
	TargetID   string
	Detail     map[string]any
	IP         string
	Result     string
	CreatedAt  time.Time
}

func (s *Store) AppendAudit(ctx context.Context, tenantID uuid.UUID, e AuditEntry) error {
	if e.Detail == nil {
		e.Detail = map[string]any{}
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO audit_log (tenant_id, actor, action, target_type, target_id, detail_json, ip, result)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		tenantID, e.Actor, e.Action, e.TargetType, e.TargetID, e.Detail, e.IP, e.Result)
	return err
}

func (s *Store) ListAudit(ctx context.Context, tenantID uuid.UUID, limit int, beforeID int64) ([]AuditEntry, error) {
	if beforeID == 0 {
		beforeID = math.MaxInt64
	}
	rows, _ := s.pool.Query(ctx, `
		SELECT id, actor, action, target_type, target_id, detail_json, ip, result, created_at
		FROM audit_log WHERE tenant_id = $1 AND id < $2 ORDER BY id DESC LIMIT $3`,
		tenantID, beforeID, limit)
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (AuditEntry, error) {
		var e AuditEntry
		return e, r.Scan(&e.ID, &e.Actor, &e.Action, &e.TargetType, &e.TargetID, &e.Detail, &e.IP, &e.Result, &e.CreatedAt)
	})
}
```

- [ ] **Step 5: Run — expect PASS**

Run: `go test ./internal/server/store/`

- [ ] **Step 6: Commit**

```powershell
git add internal/server/store
git commit -m "feat: add append-only audit log store"
```

---

### Task 7: Device store — enrollment transaction, heartbeat, status, revoke

**Files:**
- Create: `internal/server/store/devices.go`
- Test: `internal/server/store/devices_test.go`

**Interfaces:**
- Consumes: `CreateTenant`, `CreateDeviceGroup`, `CreateInstallToken`, `ListInstallTokens` (Tasks 2, 4).
- Produces:
  - `store.ErrTokenInvalid`
  - `store.NewDevice{ID uuid.UUID; Hostname, MachineGUID, OSBuild, CertSerial string; CertExpiresAt time.Time}`
  - `store.Device{ID uuid.UUID; Hostname, MachineGUID string; GroupID *uuid.UUID; CertSerial string; CertExpiresAt time.Time; OSBuild, AgentVersion string; IPs []string; LoggedOnUser string; UptimeSeconds int64; LastSeenAt *time.Time; CleanShutdown, Revoked bool; EnrolledAt time.Time}`
  - `store.Inventory{Hostname, OSBuild string; IPs []string; LoggedOnUser, AgentVersion string; UptimeSeconds int64}`
  - `store.OnlineWindow = 90 * time.Second`; `(store.Device).Status(now time.Time) string` → one of `"online"`, `"offline"`, `"unexpected_offline"`, `"revoked"`, `"never_seen"`
  - `(*Store).EnrollDevice(ctx, tokenHash []byte, now time.Time, build func(tenantID uuid.UUID) (store.NewDevice, error)) (tenantID uuid.UUID, err error)` — atomic: validate + lock token, call `build`, insert device (group from token), increment uses. If `build` errors, nothing is written and that error is returned.
  - `(*Store).GetDevice(ctx, tenantID, id uuid.UUID) (store.Device, error)`; `(*Store).ListDevices(ctx, tenantID uuid.UUID) ([]store.Device, error)`
  - `(*Store).DeviceAuthState(ctx, id uuid.UUID) (tenantID uuid.UUID, certSerial string, revoked bool, err error)` — lookup by globally unique device ID (the agent API does not yet know the tenant).
  - `(*Store).RecordHeartbeat(ctx, tenantID, id uuid.UUID, inv store.Inventory, now time.Time) error` — also sets `clean_shutdown = false`
  - `(*Store).MarkCleanShutdown(ctx, tenantID, id uuid.UUID) error`
  - `(*Store).RevokeDevice(ctx, tenantID, id uuid.UUID) error`
  - `(*Store).UpdateDeviceCert(ctx, tenantID, id uuid.UUID, serial string, expiresAt time.Time) error`
  - All single-row mutations return `ErrNotFound` when no row matches.

- [ ] **Step 1: Write failing tests**

`internal/server/store/devices_test.go`:
```go
package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"freelocker/internal/server/store"
	"freelocker/internal/server/store/storetest"

	"github.com/google/uuid"
)

func newDev(id uuid.UUID) store.NewDevice {
	return store.NewDevice{ID: id, Hostname: "pc-01", MachineGUID: "guid", OSBuild: "26100",
		CertSerial: "abc", CertExpiresAt: time.Now().Add(90 * 24 * time.Hour).Truncate(time.Second)}
}

func TestEnrollDeviceConsumesTokenAndInheritsGroup(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	tenant, _ := s.CreateTenant(ctx, "Acme")
	gid, _ := s.CreateDeviceGroup(ctx, tenant, "Laptops")
	max := 1
	s.CreateInstallToken(ctx, tenant, store.InstallToken{Name: "t", GroupID: &gid, MaxUses: &max}, []byte("h"))

	id := uuid.New()
	got, err := s.EnrollDevice(ctx, []byte("h"), time.Now(), func(tid uuid.UUID) (store.NewDevice, error) {
		if tid != tenant {
			t.Errorf("build got tenant %v", tid)
		}
		return newDev(id), nil
	})
	if err != nil || got != tenant {
		t.Fatalf("EnrollDevice = %v, %v", got, err)
	}
	d, err := s.GetDevice(ctx, tenant, id)
	if err != nil || d.Hostname != "pc-01" || d.GroupID == nil || *d.GroupID != gid || d.Status(time.Now()) != "never_seen" {
		t.Fatalf("device = %+v, %v", d, err)
	}
	toks, _ := s.ListInstallTokens(ctx, tenant)
	if toks[0].Uses != 1 {
		t.Errorf("uses = %d", toks[0].Uses)
	}
	// max_uses = 1 is now exhausted
	_, err = s.EnrollDevice(ctx, []byte("h"), time.Now(), func(uuid.UUID) (store.NewDevice, error) { return newDev(uuid.New()), nil })
	if !errors.Is(err, store.ErrTokenInvalid) {
		t.Errorf("exhausted token err = %v", err)
	}
}

func TestEnrollDeviceRejectsBadTokensAndRollsBack(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	tenant, _ := s.CreateTenant(ctx, "Acme")
	past := time.Now().Add(-time.Hour)
	s.CreateInstallToken(ctx, tenant, store.InstallToken{Name: "expired", ExpiresAt: &past}, []byte("expired"))
	rid, _ := s.CreateInstallToken(ctx, tenant, store.InstallToken{Name: "revoked"}, []byte("revoked"))
	s.RevokeInstallToken(ctx, tenant, rid)
	s.CreateInstallToken(ctx, tenant, store.InstallToken{Name: "ok"}, []byte("ok"))

	build := func(uuid.UUID) (store.NewDevice, error) { return newDev(uuid.New()), nil }
	for _, h := range []string{"expired", "revoked", "unknown"} {
		if _, err := s.EnrollDevice(ctx, []byte(h), time.Now(), build); !errors.Is(err, store.ErrTokenInvalid) {
			t.Errorf("%s: err = %v", h, err)
		}
	}

	boom := errors.New("bad csr")
	_, err := s.EnrollDevice(ctx, []byte("ok"), time.Now(), func(uuid.UUID) (store.NewDevice, error) { return store.NewDevice{}, boom })
	if !errors.Is(err, boom) {
		t.Fatalf("build error not propagated: %v", err)
	}
	for _, tok := range mustTokens(t, s, tenant) {
		if tok.Name == "ok" && tok.Uses != 0 {
			t.Error("failed build must not consume the token")
		}
	}
	if devs, _ := s.ListDevices(ctx, tenant); len(devs) != 0 {
		t.Errorf("devices = %d, want 0", len(devs))
	}
}

func mustTokens(t *testing.T, s *store.Store, tenant uuid.UUID) []store.InstallToken {
	t.Helper()
	toks, err := s.ListInstallTokens(context.Background(), tenant)
	if err != nil {
		t.Fatal(err)
	}
	return toks
}

func TestHeartbeatStatusRevokeAndCert(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	tenant, _ := s.CreateTenant(ctx, "Acme")
	s.CreateInstallToken(ctx, tenant, store.InstallToken{Name: "t"}, []byte("h"))
	id := uuid.New()
	s.EnrollDevice(ctx, []byte("h"), time.Now(), func(uuid.UUID) (store.NewDevice, error) { return newDev(id), nil })

	now := time.Now()
	inv := store.Inventory{Hostname: "pc-renamed", OSBuild: "26200", IPs: []string{"10.0.0.9"}, LoggedOnUser: "ACME\\bob", AgentVersion: "0.1.0", UptimeSeconds: 42}
	if err := s.RecordHeartbeat(ctx, tenant, id, inv, now); err != nil {
		t.Fatal(err)
	}
	d, _ := s.GetDevice(ctx, tenant, id)
	if d.Hostname != "pc-renamed" || d.IPs[0] != "10.0.0.9" || d.LoggedOnUser != `ACME\bob` || d.UptimeSeconds != 42 {
		t.Fatalf("inventory not stored: %+v", d)
	}
	if st := d.Status(now); st != "online" {
		t.Errorf("status now = %s", st)
	}
	if st := d.Status(now.Add(2 * time.Minute)); st != "unexpected_offline" {
		t.Errorf("status later = %s", st)
	}
	s.MarkCleanShutdown(ctx, tenant, id)
	d, _ = s.GetDevice(ctx, tenant, id)
	if st := d.Status(now.Add(2 * time.Minute)); st != "offline" {
		t.Errorf("status after goodbye = %s", st)
	}

	exp := time.Now().Add(200 * time.Hour).Truncate(time.Second)
	if err := s.UpdateDeviceCert(ctx, tenant, id, "new-serial", exp); err != nil {
		t.Fatal(err)
	}
	tid, serial, revoked, err := s.DeviceAuthState(ctx, id)
	if err != nil || tid != tenant || serial != "new-serial" || revoked {
		t.Fatalf("auth state = %v %q %v %v", tid, serial, revoked, err)
	}

	if err := s.RevokeDevice(ctx, tenant, id); err != nil {
		t.Fatal(err)
	}
	_, _, revoked, _ = s.DeviceAuthState(ctx, id)
	d, _ = s.GetDevice(ctx, tenant, id)
	if !revoked || d.Status(now) != "revoked" {
		t.Error("device should be revoked")
	}

	other, _ := s.CreateTenant(ctx, "Other")
	if _, err := s.GetDevice(ctx, other, id); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("cross-tenant GetDevice err = %v", err)
	}
	if err := s.RevokeDevice(ctx, other, id); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("cross-tenant RevokeDevice err = %v", err)
	}
	if _, _, _, err := s.DeviceAuthState(ctx, uuid.New()); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("unknown device auth state err = %v", err)
	}
}
```

- [ ] **Step 2: Run — expect FAIL**

Run: `go test ./internal/server/store/ -run 'TestEnroll|TestHeartbeat'`

- [ ] **Step 3: Implement device store**

`internal/server/store/devices.go`:
```go
package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

var ErrTokenInvalid = errors.New("install token invalid, expired, revoked, or exhausted")

const OnlineWindow = 90 * time.Second

type NewDevice struct {
	ID            uuid.UUID
	Hostname      string
	MachineGUID   string
	OSBuild       string
	CertSerial    string
	CertExpiresAt time.Time
}

type Device struct {
	ID            uuid.UUID
	Hostname      string
	MachineGUID   string
	GroupID       *uuid.UUID
	CertSerial    string
	CertExpiresAt time.Time
	OSBuild       string
	AgentVersion  string
	IPs           []string
	LoggedOnUser  string
	UptimeSeconds int64
	LastSeenAt    *time.Time
	CleanShutdown bool
	Revoked       bool
	EnrolledAt    time.Time
}

type Inventory struct {
	Hostname      string
	OSBuild       string
	IPs           []string
	LoggedOnUser  string
	AgentVersion  string
	UptimeSeconds int64
}

func (d Device) Status(now time.Time) string {
	switch {
	case d.Revoked:
		return "revoked"
	case d.LastSeenAt == nil:
		return "never_seen"
	case now.Sub(*d.LastSeenAt) <= OnlineWindow:
		return "online"
	case d.CleanShutdown:
		return "offline"
	default:
		return "unexpected_offline"
	}
}

const deviceCols = `id, hostname, machine_guid, group_id, cert_serial, cert_expires_at, os_build,
	agent_version, ips, logged_on_user, uptime_seconds, last_seen_at, clean_shutdown, revoked, enrolled_at`

func scanDevice(r pgx.Row) (Device, error) {
	var d Device
	err := r.Scan(&d.ID, &d.Hostname, &d.MachineGUID, &d.GroupID, &d.CertSerial, &d.CertExpiresAt, &d.OSBuild,
		&d.AgentVersion, &d.IPs, &d.LoggedOnUser, &d.UptimeSeconds, &d.LastSeenAt, &d.CleanShutdown, &d.Revoked, &d.EnrolledAt)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	return d, err
}

func (s *Store) EnrollDevice(ctx context.Context, tokenHash []byte, now time.Time, build func(tenantID uuid.UUID) (NewDevice, error)) (uuid.UUID, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	defer tx.Rollback(ctx)

	var (
		tokenID, tenantID uuid.UUID
		groupID           *uuid.UUID
		expiresAt         *time.Time
		maxUses           *int
		uses              int
		revoked           bool
	)
	err = tx.QueryRow(ctx, `
		SELECT id, tenant_id, group_id, expires_at, max_uses, uses, revoked
		FROM install_tokens WHERE token_hash = $1 FOR UPDATE`, tokenHash).
		Scan(&tokenID, &tenantID, &groupID, &expiresAt, &maxUses, &uses, &revoked)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, ErrTokenInvalid
	}
	if err != nil {
		return uuid.Nil, err
	}
	if revoked || (expiresAt != nil && !now.Before(*expiresAt)) || (maxUses != nil && uses >= *maxUses) {
		return uuid.Nil, ErrTokenInvalid
	}

	d, err := build(tenantID)
	if err != nil {
		return uuid.Nil, err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO devices (id, tenant_id, hostname, machine_guid, group_id, cert_serial, cert_expires_at, os_build)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		d.ID, tenantID, d.Hostname, d.MachineGUID, groupID, d.CertSerial, d.CertExpiresAt, d.OSBuild); err != nil {
		return uuid.Nil, err
	}
	if _, err := tx.Exec(ctx, `UPDATE install_tokens SET uses = uses + 1 WHERE id = $1`, tokenID); err != nil {
		return uuid.Nil, err
	}
	return tenantID, tx.Commit(ctx)
}

func (s *Store) GetDevice(ctx context.Context, tenantID, id uuid.UUID) (Device, error) {
	return scanDevice(s.pool.QueryRow(ctx, `SELECT `+deviceCols+` FROM devices WHERE tenant_id = $1 AND id = $2`, tenantID, id))
}

func (s *Store) ListDevices(ctx context.Context, tenantID uuid.UUID) ([]Device, error) {
	rows, _ := s.pool.Query(ctx, `SELECT `+deviceCols+` FROM devices WHERE tenant_id = $1 ORDER BY hostname`, tenantID)
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Device, error) { return scanDevice(r) })
}

func (s *Store) DeviceAuthState(ctx context.Context, id uuid.UUID) (uuid.UUID, string, bool, error) {
	var (
		tenantID uuid.UUID
		serial   string
		revoked  bool
	)
	err := s.pool.QueryRow(ctx, `SELECT tenant_id, cert_serial, revoked FROM devices WHERE id = $1`, id).
		Scan(&tenantID, &serial, &revoked)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	return tenantID, serial, revoked, err
}

func (s *Store) RecordHeartbeat(ctx context.Context, tenantID, id uuid.UUID, inv Inventory, now time.Time) error {
	if inv.IPs == nil {
		inv.IPs = []string{}
	}
	return oneRow(s.pool.Exec(ctx, `
		UPDATE devices SET hostname = $3, os_build = $4, ips = $5, logged_on_user = $6, agent_version = $7,
			uptime_seconds = $8, last_seen_at = $9, clean_shutdown = false
		WHERE tenant_id = $1 AND id = $2`,
		tenantID, id, inv.Hostname, inv.OSBuild, inv.IPs, inv.LoggedOnUser, inv.AgentVersion, inv.UptimeSeconds, now))
}

func (s *Store) MarkCleanShutdown(ctx context.Context, tenantID, id uuid.UUID) error {
	return oneRow(s.pool.Exec(ctx, `UPDATE devices SET clean_shutdown = true WHERE tenant_id = $1 AND id = $2`, tenantID, id))
}

func (s *Store) RevokeDevice(ctx context.Context, tenantID, id uuid.UUID) error {
	return oneRow(s.pool.Exec(ctx, `UPDATE devices SET revoked = true WHERE tenant_id = $1 AND id = $2`, tenantID, id))
}

func (s *Store) UpdateDeviceCert(ctx context.Context, tenantID, id uuid.UUID, serial string, expiresAt time.Time) error {
	return oneRow(s.pool.Exec(ctx, `UPDATE devices SET cert_serial = $3, cert_expires_at = $4 WHERE tenant_id = $1 AND id = $2`,
		tenantID, id, serial, expiresAt))
}

// oneRow converts "no rows affected" into ErrNotFound.
func oneRow(tag pgconn.CommandTag, err error) error {
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
```

- [ ] **Step 4: Refactor `RevokeInstallToken` to use `oneRow`** (DRY)

In `internal/server/store/tokens.go` replace the body of `RevokeInstallToken` with:
```go
	return oneRow(s.pool.Exec(ctx, `UPDATE install_tokens SET revoked = true WHERE tenant_id = $1 AND id = $2`, tenantID, id))
```

- [ ] **Step 5: Run — expect PASS**

Run: `go test ./internal/server/store/`

- [ ] **Step 6: Commit**

```powershell
git add internal/server/store
git commit -m "feat: add device store with atomic token-consuming enrollment"
```

---

### Task 8: Agent gRPC server — TLS, Enrollment service, and sim enrollment client

**Files:**
- Create: `internal/server/agentapi/server.go`, `internal/server/agentapi/enroll.go`, `internal/sim/enroll.go`
- Test: `internal/server/agentapi/testserver_test.go`, `internal/server/agentapi/enroll_test.go`

**Interfaces:**
- Consumes: `bootstrap.Init/Load/Keys` (Task 5); `(*CA).IssueServerCert`, `(*CA).SignDevice`, `ca.PinFromCert` (Task 3); `tokens.Generate/Parse/Hash` (Task 4); `(*Store).EnrollDevice`, `AppendAudit`, `CreateInstallToken` (Tasks 4, 6, 7); proto types (Task 1).
- Produces:
  - `agentapi.Deps{Store *store.Store; Keys *bootstrap.Keys; Now func() time.Time; Log *slog.Logger}` — Task 9 adds `Hub *hub.Hub` and `Commands agentapi.CommandSink`.
  - `agentapi.TLSConfig(k *bootstrap.Keys, hostnames []string, now time.Time) (*tls.Config, error)`
  - `agentapi.NewGRPCServer(d agentapi.Deps, tlsCfg *tls.Config) *grpc.Server`
  - `sim.Identity{DeviceID string; CertDER, KeyDER, CADER []byte; CommandPub ed25519.PublicKey; UninstallHash []byte}`
  - `sim.Enroll(ctx, addr, installToken string, hw *flv1.HardwareInfo) (*sim.Identity, error)`
  - `(*sim.Identity).TLSConfig() (*tls.Config, error)` — mTLS client config trusting only the enrolled CA.
  - Audit action names: `device.enroll`.

- [ ] **Step 1: Implement server construction (Enrollment only for now)**

`internal/server/agentapi/server.go`:
```go
// Package agentapi implements the gRPC services that agents talk to.
package agentapi

import (
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"time"

	flv1 "freelocker/gen/freelocker/v1"
	"freelocker/internal/server/bootstrap"
	"freelocker/internal/server/store"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
)

type Deps struct {
	Store *store.Store
	Keys  *bootstrap.Keys
	Now   func() time.Time
	Log   *slog.Logger
}

// TLSConfig issues a fresh agent-facing server certificate from the
// internal CA. Client certs are optional at the TLS layer because
// Enroll is called before the agent has one; the Agent service
// enforces them in an interceptor.
func TLSConfig(k *bootstrap.Keys, hostnames []string, now time.Time) (*tls.Config, error) {
	cert, err := k.CA.IssueServerCert(hostnames, now)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(k.CA.Cert)
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    pool,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

func NewGRPCServer(d Deps, tlsCfg *tls.Config) *grpc.Server {
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Log == nil {
		d.Log = slog.Default()
	}
	srv := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(tlsCfg)),
		grpc.KeepaliveParams(keepalive.ServerParameters{Time: 60 * time.Second, Timeout: 20 * time.Second}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{MinTime: 20 * time.Second, PermitWithoutStream: true}),
	)
	flv1.RegisterEnrollmentServer(srv, &enrollService{d: d})
	return srv
}
```
Note: Tasks 9 and 10 add `Hub` and `Commands` fields to `Deps` and register the Agent service here.

- [ ] **Step 2: Implement Enrollment service**

`internal/server/agentapi/enroll.go`:
```go
package agentapi

import (
	"context"
	"crypto/ed25519"
	"errors"

	flv1 "freelocker/gen/freelocker/v1"
	"freelocker/internal/server/store"
	"freelocker/internal/server/tokens"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type enrollService struct {
	flv1.UnimplementedEnrollmentServer
	d Deps
}

var errBadCSR = errors.New("bad CSR")

func (s *enrollService) Enroll(ctx context.Context, req *flv1.EnrollRequest) (*flv1.EnrollResponse, error) {
	if req.GetTokenSecret() == "" || len(req.GetCsrDer()) == 0 || req.GetHardware().GetHostname() == "" {
		return nil, status.Error(codes.InvalidArgument, "token_secret, csr_der and hardware.hostname are required")
	}
	now := s.d.Now()
	deviceID := uuid.New()
	var certDER []byte

	tenantID, err := s.d.Store.EnrollDevice(ctx, tokens.Hash(req.GetTokenSecret()), now, func(uuid.UUID) (store.NewDevice, error) {
		der, serial, notAfter, err := s.d.Keys.CA.SignDevice(req.GetCsrDer(), deviceID, now)
		if err != nil {
			return store.NewDevice{}, errors.Join(errBadCSR, err)
		}
		certDER = der
		hw := req.GetHardware()
		return store.NewDevice{
			ID: deviceID, Hostname: hw.GetHostname(), MachineGUID: hw.GetMachineGuid(), OSBuild: hw.GetOsBuild(),
			CertSerial: serial, CertExpiresAt: notAfter,
		}, nil
	})
	switch {
	case errors.Is(err, store.ErrTokenInvalid):
		s.d.Log.Warn("enrollment rejected", "reason", "token", "hostname", req.GetHardware().GetHostname())
		return nil, status.Error(codes.PermissionDenied, store.ErrTokenInvalid.Error())
	case errors.Is(err, errBadCSR):
		return nil, status.Error(codes.InvalidArgument, err.Error())
	case err != nil:
		s.d.Log.Error("enrollment failed", "err", err)
		return nil, status.Error(codes.Internal, "enrollment failed")
	}

	if err := s.d.Store.AppendAudit(ctx, tenantID, store.AuditEntry{
		Actor: "device:" + deviceID.String(), Action: "device.enroll", TargetType: "device", TargetID: deviceID.String(),
		Detail: map[string]any{"hostname": req.GetHardware().GetHostname()}, Result: "success",
	}); err != nil {
		s.d.Log.Error("audit write failed", "err", err)
	}

	return &flv1.EnrollResponse{
		DeviceId:                deviceID.String(),
		CertDer:                 certDER,
		CaCertDer:               s.d.Keys.CA.Cert.Raw,
		CommandSigningPublicKey: s.d.Keys.CommandKey.Public().(ed25519.PublicKey),
		UpdateSigningPublicKey:  s.d.Keys.UpdateKey.Public().(ed25519.PublicKey),
		UninstallCodeSha256:     s.d.Keys.UninstallCodeHash(deviceID),
	}, nil
}
```

- [ ] **Step 3: Implement the sim enrollment client**

`internal/sim/enroll.go`:
```go
// Package sim is a protocol-accurate fake agent used by integration tests
// and the agent-sim load tool.
package sim

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"

	flv1 "freelocker/gen/freelocker/v1"
	"freelocker/internal/server/ca"
	"freelocker/internal/server/tokens"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type Identity struct {
	DeviceID      string
	CertDER       []byte
	KeyDER        []byte
	CADER         []byte
	CommandPub    ed25519.PublicKey
	UninstallHash []byte
}

// pinnedTLS trusts the server only if its chain ends in the CA whose pin
// is embedded in the install token.
func pinnedTLS(pin string) *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, // replaced by VerifyPeerCertificate below
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) < 2 {
				return errors.New("server did not present a CA chain")
			}
			caDER := raw[len(raw)-1]
			if ca.PinFromCert(caDER) != pin {
				return errors.New("server CA does not match install token pin")
			}
			caCert, err := x509.ParseCertificate(caDER)
			if err != nil {
				return err
			}
			leaf, err := x509.ParseCertificate(raw[0])
			if err != nil {
				return err
			}
			roots := x509.NewCertPool()
			roots.AddCert(caCert)
			_, err = leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
			return err
		},
	}
}

func Enroll(ctx context.Context, addr, installToken string, hw *flv1.HardwareInfo) (*Identity, error) {
	secret, pin, err := tokens.Parse(installToken)
	if err != nil {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: hw.GetHostname()}}, key)
	if err != nil {
		return nil, err
	}
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(credentials.NewTLS(pinnedTLS(pin))))
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	resp, err := flv1.NewEnrollmentClient(conn).Enroll(ctx, &flv1.EnrollRequest{TokenSecret: secret, CsrDer: csr, Hardware: hw})
	if err != nil {
		return nil, fmt.Errorf("enroll: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return &Identity{
		DeviceID: resp.GetDeviceId(), CertDER: resp.GetCertDer(), KeyDER: keyDER, CADER: resp.GetCaCertDer(),
		CommandPub: resp.GetCommandSigningPublicKey(), UninstallHash: resp.GetUninstallCodeSha256(),
	}, nil
}

func (id *Identity) TLSConfig() (*tls.Config, error) {
	key, err := x509.ParsePKCS8PrivateKey(id.KeyDER)
	if err != nil {
		return nil, err
	}
	caCert, err := x509.ParseCertificate(id.CADER)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		RootCAs:      roots,
		Certificates: []tls.Certificate{{Certificate: [][]byte{id.CertDER}, PrivateKey: key}},
	}, nil
}
```
Note: `TLSConfig` leaves `ServerName` empty; gRPC fills it from the dial address host, which must be one of the server's `public_hostnames`.

- [ ] **Step 4: Write the shared test server helper**

`internal/server/agentapi/testserver_test.go`:
```go
package agentapi_test

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"freelocker/internal/server/agentapi"
	"freelocker/internal/server/bootstrap"
	"freelocker/internal/server/store"
	"freelocker/internal/server/store/storetest"
	"freelocker/internal/server/tokens"
)

type testServer struct {
	Addr  string
	Deps  agentapi.Deps
	Token string // valid unlimited install token
}

func startServer(t *testing.T) *testServer {
	t.Helper()
	ctx := context.Background()
	s := storetest.New(t)
	master := bytes.Repeat([]byte{9}, 32)
	if _, err := bootstrap.Init(ctx, s, master, "Acme", time.Now()); err != nil {
		t.Fatal(err)
	}
	k, err := bootstrap.Load(ctx, s, master)
	if err != nil {
		t.Fatal(err)
	}
	full, hash, _ := tokens.Generate(k.CA.Pin())
	if _, err := s.CreateInstallToken(ctx, k.TenantID, store.InstallToken{Name: "test"}, hash); err != nil {
		t.Fatal(err)
	}

	d := newDeps(s, k)
	tlsCfg, err := agentapi.TLSConfig(k, []string{"127.0.0.1"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := agentapi.NewGRPCServer(d, tlsCfg)
	go srv.Serve(lis)
	t.Cleanup(srv.Stop)
	return &testServer{Addr: lis.Addr().String(), Deps: d, Token: full}
}

// newDeps is extended in Tasks 9 and 10 as Deps gains fields.
func newDeps(s *store.Store, k *bootstrap.Keys) agentapi.Deps {
	return agentapi.Deps{Store: s, Keys: k}
}
```

- [ ] **Step 5: Write failing enrollment tests**

`internal/server/agentapi/enroll_test.go`:
```go
package agentapi_test

import (
	"context"
	"crypto/sha256"
	"strings"
	"testing"

	flv1 "freelocker/gen/freelocker/v1"
	"freelocker/internal/server/store"
	"freelocker/internal/server/tokens"
	"freelocker/internal/sim"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var hw = &flv1.HardwareInfo{Hostname: "pc-01", OsBuild: "26100", MachineGuid: "g-1"}

func TestEnrollSuccess(t *testing.T) {
	ctx := context.Background()
	ts := startServer(t)

	id, err := sim.Enroll(ctx, ts.Addr, ts.Token, hw)
	if err != nil {
		t.Fatal(err)
	}
	devID := uuid.MustParse(id.DeviceID)
	d, err := ts.Deps.Store.GetDevice(ctx, ts.Deps.Keys.TenantID, devID)
	if err != nil || d.Hostname != "pc-01" || d.MachineGUID != "g-1" {
		t.Fatalf("device = %+v, %v", d, err)
	}
	sum := sha256.Sum256([]byte(ts.Deps.Keys.UninstallCode(devID)))
	if string(id.UninstallHash) != string(sum[:]) || len(id.CommandPub) != 32 {
		t.Error("enroll response missing uninstall hash or command key")
	}
	entries, _ := ts.Deps.Store.ListAudit(ctx, ts.Deps.Keys.TenantID, 10, 0)
	if len(entries) != 1 || entries[0].Action != "device.enroll" || entries[0].TargetID != id.DeviceID {
		t.Errorf("audit = %+v", entries)
	}
}

func TestEnrollRejectsBadToken(t *testing.T) {
	ts := startServer(t)
	_, pin, _ := tokens.Parse(ts.Token)
	bad, _, _ := tokens.Generate(pin) // right pin, unknown secret
	_, err := sim.Enroll(context.Background(), ts.Addr, bad, hw)
	if status.Code(unwrap(err)) != codes.PermissionDenied {
		t.Fatalf("err = %v, want PermissionDenied", err)
	}
}

func TestEnrollRejectsWrongServerPin(t *testing.T) {
	ts := startServer(t)
	secret, _, _ := tokens.Parse(ts.Token)
	_, err := sim.Enroll(context.Background(), ts.Addr, secret+"."+strings.Repeat("0", 32), hw)
	if err == nil || !strings.Contains(err.Error(), "pin") {
		t.Fatalf("err = %v, want pin mismatch", err)
	}
}

func TestEnrollHonorsMaxUses(t *testing.T) {
	ctx := context.Background()
	ts := startServer(t)
	one := 1
	full, hash, _ := tokens.Generate(ts.Deps.Keys.CA.Pin())
	ts.Deps.Store.CreateInstallToken(ctx, ts.Deps.Keys.TenantID, store.InstallToken{Name: "once", MaxUses: &one}, hash)

	if _, err := sim.Enroll(ctx, ts.Addr, full, hw); err != nil {
		t.Fatal(err)
	}
	if _, err := sim.Enroll(ctx, ts.Addr, full, hw); status.Code(unwrap(err)) != codes.PermissionDenied {
		t.Fatalf("second enroll err = %v", err)
	}
}

// unwrap digs the gRPC status out of sim's fmt.Errorf wrapping.
func unwrap(err error) error {
	for err != nil {
		if _, ok := status.FromError(err); ok {
			return err
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return err
		}
		err = u.Unwrap()
	}
	return err
}
```

- [ ] **Step 6: Run — expect PASS**

Run: `go mod tidy; go test ./internal/server/agentapi/ ./internal/sim/`
Expected: all four enrollment tests pass. If `TestEnrollRejectsBadToken` reports `codes.Unknown`, `status.FromError` already unwraps wrapped errors in recent grpc-go — replace `status.Code(unwrap(err))` with `status.Code(err)` and delete `unwrap`.

- [ ] **Step 7: Commit**

```powershell
git add internal/server/agentapi internal/sim go.mod go.sum
git commit -m "feat: add agent gRPC server with token enrollment and sim client"
```

---

### Task 9: Agent stream — mTLS auth, hub, Connect, heartbeat, renew, revoke

**Files:**
- Create: `internal/server/hub/hub.go`, `internal/server/agentapi/auth.go`, `internal/server/agentapi/agent.go`, `internal/sim/session.go`
- Modify: `internal/server/agentapi/server.go` (Deps fields, interceptors, register Agent service), `internal/server/agentapi/testserver_test.go` (`newDeps`)
- Test: `internal/server/hub/hub_test.go`, `internal/server/agentapi/agent_test.go`

**Interfaces:**
- Consumes: Task 7 device store (`DeviceAuthState`, `RecordHeartbeat`, `MarkCleanShutdown`, `UpdateDeviceCert`, `RevokeDevice`, `GetDevice`); Task 8 `Deps`, `NewGRPCServer`, `sim.Identity`, `sim.Enroll`.
- Produces:
  - `hub.New() *hub.Hub`; `(*Hub).Register(id uuid.UUID, cancel context.CancelCauseFunc) *hub.Conn`; `(*Hub).Unregister(id uuid.UUID, c *hub.Conn)`; `(*Hub).Send(id uuid.UUID, m *flv1.ServerMessage) bool`; `(*Hub).Disconnect(id uuid.UUID, cause error)`; `(*Hub).Connected(id uuid.UUID) bool`; `hub.Conn.Send <-chan`-readable field `Send chan *flv1.ServerMessage`; `hub.ErrReplaced`
  - `agentapi.CommandSink` interface: `DeliverPending(ctx, tenantID, deviceID uuid.UUID) error` and `Complete(ctx, tenantID, deviceID uuid.UUID, r *flv1.CommandResult) error`
  - `agentapi.Deps` gains `Hub *hub.Hub` and `Commands agentapi.CommandSink` (may be nil).
  - `agentapi.RevokedError() error` — the gRPC status used when disconnecting a revoked device.
  - `sim.Connect(ctx, addr string, id *sim.Identity) (*sim.Session, error)`; `(*Session).Heartbeat(inv *flv1.Inventory) error`; `(*Session).SendResult(r *flv1.CommandResult) error`; `(*Session).Goodbye(reason string) error`; `(*Session).Commands() <-chan *flv1.SignedCommand`; `(*Session).Done() <-chan error` (receives the terminal stream error once); `(*Session).Close() error`
  - `sim.Renew(ctx, addr string, id *sim.Identity) (*sim.Identity, error)`
  - Audit action names: `device.cert_renew`.

- [ ] **Step 1: Write failing hub test**

`internal/server/hub/hub_test.go`:
```go
package hub

import (
	"context"
	"errors"
	"testing"

	flv1 "freelocker/gen/freelocker/v1"

	"github.com/google/uuid"
)

func TestRegisterSendReplaceDisconnect(t *testing.T) {
	h := New()
	id := uuid.New()
	if h.Send(id, &flv1.ServerMessage{}) || h.Connected(id) {
		t.Fatal("unknown device must not be connected")
	}

	ctx1, cancel1 := context.WithCancelCause(context.Background())
	c1 := h.Register(id, cancel1)
	if !h.Connected(id) || !h.Send(id, &flv1.ServerMessage{}) || len(c1.Send) != 1 {
		t.Fatal("send to registered conn failed")
	}

	ctx2, cancel2 := context.WithCancelCause(context.Background())
	c2 := h.Register(id, cancel2)
	if !errors.Is(context.Cause(ctx1), ErrReplaced) {
		t.Errorf("old conn cause = %v, want ErrReplaced", context.Cause(ctx1))
	}
	h.Unregister(id, c1) // stale unregister must not remove the new conn
	if !h.Connected(id) {
		t.Fatal("stale Unregister removed the new connection")
	}

	boom := errors.New("revoked")
	h.Disconnect(id, boom)
	if !errors.Is(context.Cause(ctx2), boom) {
		t.Errorf("cause = %v", context.Cause(ctx2))
	}
	h.Unregister(id, c2)
	if h.Connected(id) {
		t.Error("still connected after Unregister")
	}
}
```

- [ ] **Step 2: Run — expect FAIL**

Run: `go test ./internal/server/hub/`

- [ ] **Step 3: Implement hub**

`internal/server/hub/hub.go`:
```go
// Package hub tracks the live stream for each connected agent so other
// parts of the server can push messages to it or cut it off.
package hub

import (
	"context"
	"errors"
	"sync"

	flv1 "freelocker/gen/freelocker/v1"

	"github.com/google/uuid"
)

var ErrReplaced = errors.New("replaced by a newer connection from the same device")

const sendBuffer = 64

type Conn struct {
	Send   chan *flv1.ServerMessage
	cancel context.CancelCauseFunc
}

type Hub struct {
	mu    sync.Mutex
	conns map[uuid.UUID]*Conn
}

func New() *Hub { return &Hub{conns: map[uuid.UUID]*Conn{}} }

// Register adds a connection, cancelling any previous one for the device.
func (h *Hub) Register(id uuid.UUID, cancel context.CancelCauseFunc) *Conn {
	c := &Conn{Send: make(chan *flv1.ServerMessage, sendBuffer), cancel: cancel}
	h.mu.Lock()
	old := h.conns[id]
	h.conns[id] = c
	h.mu.Unlock()
	if old != nil {
		old.cancel(ErrReplaced)
	}
	return c
}

func (h *Hub) Unregister(id uuid.UUID, c *Conn) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.conns[id] == c {
		delete(h.conns, id)
	}
}

// Send is non-blocking; it reports false if the device is not connected
// or its buffer is full (the message stays pending in the database).
func (h *Hub) Send(id uuid.UUID, m *flv1.ServerMessage) bool {
	h.mu.Lock()
	c := h.conns[id]
	h.mu.Unlock()
	if c == nil {
		return false
	}
	select {
	case c.Send <- m:
		return true
	default:
		return false
	}
}

func (h *Hub) Disconnect(id uuid.UUID, cause error) {
	h.mu.Lock()
	c := h.conns[id]
	h.mu.Unlock()
	if c != nil {
		c.cancel(cause)
	}
}

func (h *Hub) Connected(id uuid.UUID) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.conns[id] != nil
}
```

- [ ] **Step 4: Run hub test — expect PASS**

Run: `go test ./internal/server/hub/`

- [ ] **Step 5: Implement the auth interceptors**

`internal/server/agentapi/auth.go`:
```go
package agentapi

import (
	"context"
	"errors"
	"strings"

	"freelocker/internal/server/store"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

const agentServicePrefix = "/freelocker.v1.Agent/"

type deviceKey struct{}

type device struct {
	ID       uuid.UUID
	TenantID uuid.UUID
}

func deviceFrom(ctx context.Context) device { return ctx.Value(deviceKey{}).(device) }

func RevokedError() error { return status.Error(codes.Unauthenticated, "device revoked") }

// authenticate derives the device from the verified client certificate
// and checks it is the device's current, unrevoked certificate.
func (d Deps) authenticate(ctx context.Context) (context.Context, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "no peer")
	}
	ti, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(ti.State.VerifiedChains) == 0 || len(ti.State.VerifiedChains[0]) == 0 {
		return nil, status.Error(codes.Unauthenticated, "client certificate required")
	}
	leaf := ti.State.VerifiedChains[0][0]
	id, err := uuid.Parse(leaf.Subject.CommonName)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "certificate is not a device certificate")
	}
	tenantID, serial, revoked, err := d.Store.DeviceAuthState(ctx, id)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return nil, status.Error(codes.Unauthenticated, "unknown device")
	case err != nil:
		return nil, status.Error(codes.Internal, "auth lookup failed")
	case revoked:
		return nil, RevokedError()
	case serial != leaf.SerialNumber.Text(16):
		return nil, status.Error(codes.Unauthenticated, "certificate superseded")
	}
	return context.WithValue(ctx, deviceKey{}, device{ID: id, TenantID: tenantID}), nil
}

func (d Deps) unaryAuth(ctx context.Context, req any, info *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
	if !strings.HasPrefix(info.FullMethod, agentServicePrefix) {
		return h(ctx, req)
	}
	ctx, err := d.authenticate(ctx)
	if err != nil {
		return nil, err
	}
	return h(ctx, req)
}

func (d Deps) streamAuth(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, h grpc.StreamHandler) error {
	if !strings.HasPrefix(info.FullMethod, agentServicePrefix) {
		return h(srv, ss)
	}
	ctx, err := d.authenticate(ss.Context())
	if err != nil {
		return err
	}
	return h(srv, &authedStream{ServerStream: ss, ctx: ctx})
}

type authedStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *authedStream) Context() context.Context { return s.ctx }
```

- [ ] **Step 6: Implement the Agent service**

`internal/server/agentapi/agent.go`:
```go
package agentapi

import (
	"context"
	"errors"
	"io"
	"time"

	flv1 "freelocker/gen/freelocker/v1"
	"freelocker/internal/server/hub"
	"freelocker/internal/server/store"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const clockSkew = 5 * time.Minute

type CommandSink interface {
	DeliverPending(ctx context.Context, tenantID, deviceID uuid.UUID) error
	Complete(ctx context.Context, tenantID, deviceID uuid.UUID, r *flv1.CommandResult) error
}

type agentService struct {
	flv1.UnimplementedAgentServer
	d Deps
}

func (s *agentService) Connect(stream flv1.Agent_ConnectServer) error {
	dev := deviceFrom(stream.Context())
	ctx, cancel := context.WithCancelCause(stream.Context())
	defer cancel(nil)
	c := s.d.Hub.Register(dev.ID, cancel)
	defer s.d.Hub.Unregister(dev.ID, c)
	s.d.Log.Info("agent connected", "device", dev.ID)

	if s.d.Commands != nil {
		if err := s.d.Commands.DeliverPending(ctx, dev.TenantID, dev.ID); err != nil {
			s.d.Log.Error("deliver pending commands", "device", dev.ID, "err", err)
		}
	}

	recvErr := make(chan error, 1)
	go func() {
		for {
			m, err := stream.Recv()
			if err != nil {
				recvErr <- err
				return
			}
			s.handle(ctx, dev, m)
		}
	}()

	for {
		select {
		case <-ctx.Done():
			cause := context.Cause(ctx)
			if errors.Is(cause, hub.ErrReplaced) {
				return status.Error(codes.Aborted, cause.Error())
			}
			if st, ok := status.FromError(cause); ok {
				return st.Err()
			}
			return status.FromContextError(cause).Err()
		case err := <-recvErr:
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		case m := <-c.Send:
			if err := stream.Send(m); err != nil {
				return err
			}
		}
	}
}

func (s *agentService) handle(ctx context.Context, dev device, m *flv1.AgentMessage) {
	now := s.d.Now()
	switch b := m.GetBody().(type) {
	case *flv1.AgentMessage_Heartbeat:
		if skew := now.Sub(time.Unix(b.Heartbeat.GetSentAtUnix(), 0)); skew > clockSkew || skew < -clockSkew {
			s.d.Log.Warn("agent clock skew", "device", dev.ID, "skew", skew)
		}
		inv := b.Heartbeat.GetInventory()
		err := s.d.Store.RecordHeartbeat(ctx, dev.TenantID, dev.ID, store.Inventory{
			Hostname: inv.GetHostname(), OSBuild: inv.GetOsBuild(), IPs: inv.GetIpAddresses(),
			LoggedOnUser: inv.GetLoggedOnUser(), AgentVersion: inv.GetAgentVersion(), UptimeSeconds: inv.GetUptimeSeconds(),
		}, now)
		if err != nil {
			s.d.Log.Error("record heartbeat", "device", dev.ID, "err", err)
		}
	case *flv1.AgentMessage_CommandResult:
		if s.d.Commands == nil {
			return
		}
		if err := s.d.Commands.Complete(ctx, dev.TenantID, dev.ID, b.CommandResult); err != nil {
			s.d.Log.Warn("command result rejected", "device", dev.ID, "command", b.CommandResult.GetCommandId(), "err", err)
		}
	case *flv1.AgentMessage_Goodbye:
		if err := s.d.Store.MarkCleanShutdown(ctx, dev.TenantID, dev.ID); err != nil {
			s.d.Log.Error("mark clean shutdown", "device", dev.ID, "err", err)
		}
	}
}

func (s *agentService) RenewCertificate(ctx context.Context, req *flv1.RenewRequest) (*flv1.RenewResponse, error) {
	dev := deviceFrom(ctx)
	now := s.d.Now()
	der, serial, notAfter, err := s.d.Keys.CA.SignDevice(req.GetCsrDer(), dev.ID, now)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if err := s.d.Store.UpdateDeviceCert(ctx, dev.TenantID, dev.ID, serial, notAfter); err != nil {
		return nil, status.Error(codes.Internal, "store certificate")
	}
	if err := s.d.Store.AppendAudit(ctx, dev.TenantID, store.AuditEntry{
		Actor: "device:" + dev.ID.String(), Action: "device.cert_renew", TargetType: "device",
		TargetID: dev.ID.String(), Detail: map[string]any{"serial": serial}, Result: "success",
	}); err != nil {
		s.d.Log.Error("audit write failed", "err", err)
	}
	return &flv1.RenewResponse{CertDer: der}, nil
}
```

- [ ] **Step 7: Update server.go — Deps fields, interceptors, Agent registration**

In `internal/server/agentapi/server.go`:

Replace the `Deps` struct with:
```go
type Deps struct {
	Store    *store.Store
	Keys     *bootstrap.Keys
	Hub      *hub.Hub
	Commands CommandSink // optional
	Now      func() time.Time
	Log      *slog.Logger
}
```
Add import `"freelocker/internal/server/hub"`.

Replace the `grpc.NewServer(...)` call and registration lines in `NewGRPCServer` with:
```go
	srv := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(tlsCfg)),
		grpc.ChainUnaryInterceptor(d.unaryAuth),
		grpc.ChainStreamInterceptor(d.streamAuth),
		grpc.KeepaliveParams(keepalive.ServerParameters{Time: 60 * time.Second, Timeout: 20 * time.Second}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{MinTime: 20 * time.Second, PermitWithoutStream: true}),
	)
	flv1.RegisterEnrollmentServer(srv, &enrollService{d: d})
	flv1.RegisterAgentServer(srv, &agentService{d: d})
	return srv
```
Also add at the top of `NewGRPCServer`, after the `Log` default:
```go
	if d.Hub == nil {
		d.Hub = hub.New()
	}
```

- [ ] **Step 8: Implement the sim session and renewal**

`internal/sim/session.go`:
```go
package sim

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"time"

	flv1 "freelocker/gen/freelocker/v1"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type Session struct {
	conn     *grpc.ClientConn
	stream   flv1.Agent_ConnectClient
	commands chan *flv1.SignedCommand
	done     chan error
}

func dial(addr string, id *Identity) (*grpc.ClientConn, error) {
	cfg, err := id.TLSConfig()
	if err != nil {
		return nil, err
	}
	return grpc.NewClient(addr, grpc.WithTransportCredentials(credentials.NewTLS(cfg)))
}

func Connect(ctx context.Context, addr string, id *Identity) (*Session, error) {
	conn, err := dial(addr, id)
	if err != nil {
		return nil, err
	}
	stream, err := flv1.NewAgentClient(conn).Connect(ctx)
	if err != nil {
		conn.Close()
		return nil, err
	}
	s := &Session{conn: conn, stream: stream, commands: make(chan *flv1.SignedCommand, 64), done: make(chan error, 1)}
	go func() {
		for {
			m, err := stream.Recv()
			if err != nil {
				s.done <- err
				close(s.commands)
				return
			}
			if c := m.GetCommand(); c != nil {
				s.commands <- c
			}
		}
	}()
	return s, nil
}

func (s *Session) Heartbeat(inv *flv1.Inventory) error {
	return s.stream.Send(&flv1.AgentMessage{Body: &flv1.AgentMessage_Heartbeat{Heartbeat: &flv1.Heartbeat{
		Inventory: inv, SentAtUnix: time.Now().Unix(),
	}}})
}

func (s *Session) SendResult(r *flv1.CommandResult) error {
	return s.stream.Send(&flv1.AgentMessage{Body: &flv1.AgentMessage_CommandResult{CommandResult: r}})
}

func (s *Session) Goodbye(reason string) error {
	if err := s.stream.Send(&flv1.AgentMessage{Body: &flv1.AgentMessage_Goodbye{Goodbye: &flv1.Goodbye{Reason: reason}}}); err != nil {
		return err
	}
	return s.stream.CloseSend()
}

func (s *Session) Commands() <-chan *flv1.SignedCommand { return s.commands }
func (s *Session) Done() <-chan error                   { return s.done }
func (s *Session) Close() error                         { return s.conn.Close() }

// Renew obtains a new certificate with a fresh key and returns the
// updated identity; the old certificate stops working immediately.
func Renew(ctx context.Context, addr string, id *Identity) (*Identity, error) {
	conn, err := dial(addr, id)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: id.DeviceID}}, key)
	if err != nil {
		return nil, err
	}
	resp, err := flv1.NewAgentClient(conn).RenewCertificate(ctx, &flv1.RenewRequest{CsrDer: csr})
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	next := *id
	next.CertDER, next.KeyDER = resp.GetCertDer(), keyDER
	return &next, nil
}
```

- [ ] **Step 9: Update `newDeps` in the test helper**

In `internal/server/agentapi/testserver_test.go` replace `newDeps` with:
```go
// newDeps is extended in Task 10 with the command service.
func newDeps(s *store.Store, k *bootstrap.Keys) agentapi.Deps {
	return agentapi.Deps{Store: s, Keys: k, Hub: hub.New()}
}
```
and add import `"freelocker/internal/server/hub"`.

- [ ] **Step 10: Write failing stream tests**

`internal/server/agentapi/agent_test.go`:
```go
package agentapi_test

import (
	"context"
	"crypto/tls"
	"testing"
	"time"

	flv1 "freelocker/gen/freelocker/v1"
	"freelocker/internal/server/agentapi"
	"freelocker/internal/sim"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func waitDone(t *testing.T, s *sim.Session) error {
	t.Helper()
	select {
	case err := <-s.Done():
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("stream did not end")
		return nil
	}
}

func enrollAndConnect(t *testing.T, ts *testServer) (*sim.Identity, *sim.Session) {
	t.Helper()
	id, err := sim.Enroll(context.Background(), ts.Addr, ts.Token, hw)
	if err != nil {
		t.Fatal(err)
	}
	sess, err := sim.Connect(context.Background(), ts.Addr, id)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sess.Close() })
	return id, sess
}

func TestHeartbeatUpdatesInventoryAndGoodbyeMarksCleanShutdown(t *testing.T) {
	ctx := context.Background()
	ts := startServer(t)
	id, sess := enrollAndConnect(t, ts)
	devID := uuid.MustParse(id.DeviceID)

	if err := sess.Heartbeat(&flv1.Inventory{Hostname: "pc-01", IpAddresses: []string{"10.1.1.1"}, AgentVersion: "0.1.0"}); err != nil {
		t.Fatal(err)
	}
	eventually(t, "device online", func() bool {
		d, _ := ts.Deps.Store.GetDevice(ctx, ts.Deps.Keys.TenantID, devID)
		return d.Status(time.Now()) == "online" && d.AgentVersion == "0.1.0"
	})
	if !ts.Deps.Hub.Connected(devID) {
		t.Error("hub should report connected")
	}

	sess.Goodbye("service stopping")
	eventually(t, "clean shutdown", func() bool {
		d, _ := ts.Deps.Store.GetDevice(ctx, ts.Deps.Keys.TenantID, devID)
		return d.CleanShutdown
	})
	eventually(t, "hub unregistered", func() bool { return !ts.Deps.Hub.Connected(devID) })
}

func TestAgentServiceRequiresClientCert(t *testing.T) {
	ts := startServer(t)
	conn, err := grpc.NewClient(ts.Addr, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{InsecureSkipVerify: true})))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, err = flv1.NewAgentClient(conn).RenewCertificate(context.Background(), &flv1.RenewRequest{})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("err = %v, want Unauthenticated", err)
	}
}

func TestRevokeDisconnectsAndBlocksReconnect(t *testing.T) {
	ctx := context.Background()
	ts := startServer(t)
	id, sess := enrollAndConnect(t, ts)
	devID := uuid.MustParse(id.DeviceID)
	eventually(t, "connected", func() bool { return ts.Deps.Hub.Connected(devID) })

	if err := ts.Deps.Store.RevokeDevice(ctx, ts.Deps.Keys.TenantID, devID); err != nil {
		t.Fatal(err)
	}
	ts.Deps.Hub.Disconnect(devID, agentapi.RevokedError())
	if err := waitDone(t, sess); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("live stream ended with %v, want Unauthenticated", err)
	}

	again, err := sim.Connect(ctx, ts.Addr, id)
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	if err := waitDone(t, again); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("reconnect ended with %v, want Unauthenticated", err)
	}
}

func TestRenewSupersedesOldCertificate(t *testing.T) {
	ctx := context.Background()
	ts := startServer(t)
	id, sess := enrollAndConnect(t, ts)
	sess.Close()

	renewed, err := sim.Renew(ctx, ts.Addr, id)
	if err != nil {
		t.Fatal(err)
	}
	good, err := sim.Connect(ctx, ts.Addr, renewed)
	if err != nil {
		t.Fatal(err)
	}
	defer good.Close()
	devID := uuid.MustParse(id.DeviceID)
	eventually(t, "renewed cert connects", func() bool { return ts.Deps.Hub.Connected(devID) })

	old, _ := sim.Connect(ctx, ts.Addr, id)
	defer old.Close()
	if err := waitDone(t, old); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("old cert: %v, want Unauthenticated", err)
	}
	entries, _ := ts.Deps.Store.ListAudit(ctx, ts.Deps.Keys.TenantID, 1, 0)
	if entries[0].Action != "device.cert_renew" {
		t.Errorf("latest audit = %s", entries[0].Action)
	}
}

func TestSecondConnectionReplacesFirst(t *testing.T) {
	ts := startServer(t)
	id, first := enrollAndConnect(t, ts)
	eventually(t, "first connected", func() bool { return ts.Deps.Hub.Connected(uuid.MustParse(id.DeviceID)) })
	second, err := sim.Connect(context.Background(), ts.Addr, id)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if err := waitDone(t, first); status.Code(err) != codes.Aborted {
		t.Fatalf("first stream ended with %v, want Aborted", err)
	}
}
```

- [ ] **Step 11: Run — expect PASS**

Run: `go test ./internal/server/... ./internal/sim/ -race`
Expected: all pass, no races. (`-race` needs cgo; if a C compiler is unavailable on Windows, run without `-race`.)

- [ ] **Step 12: Commit**

```powershell
git add internal/server/hub internal/server/agentapi internal/sim
git commit -m "feat: add authenticated agent stream with heartbeat, renew, and revoke"
```

---

### Task 10: Signed commands — issue, deliver, complete, expire

**Files:**
- Create: `internal/server/store/commands.go`, `internal/server/commands/commands.go`, `internal/server/commands/sign.go`
- Modify: `internal/server/agentapi/testserver_test.go` (`newDeps` wires the command service)
- Test: `internal/server/store/commands_test.go`, `internal/server/commands/sign_test.go`, `internal/server/agentapi/commands_test.go`

**Interfaces:**
- Consumes: `hub.Hub` (Task 9); `bootstrap.Keys.CommandKey` (Task 5); `agentapi.CommandSink` (Task 9); device store (Task 7); audit store (Task 6).
- Produces:
  - `store.Command{ID, DeviceID uuid.UUID; Type string; Payload []byte; IssuedBy *uuid.UUID; IssuedAt, ExpiresAt time.Time; State, Result string; CompletedAt *time.Time}`
  - `(*Store).CreateCommand(ctx, tenantID uuid.UUID, c store.Command) error` (inserts with `state = 'pending'`)
  - `(*Store).OpenCommands(ctx, tenantID, deviceID uuid.UUID, now time.Time) ([]store.Command, error)` — state `pending` or `sent`, not expired, oldest first
  - `(*Store).MarkCommandSent(ctx, tenantID, id uuid.UUID) error` (only from `pending`)
  - `(*Store).CompleteCommand(ctx, tenantID, deviceID, id uuid.UUID, success bool, result string, now time.Time) error` — only from `pending`/`sent` and only for the owning device; else `ErrNotFound`
  - `(*Store).ListDeviceCommands(ctx, tenantID, deviceID uuid.UUID, limit int) ([]store.Command, error)` — newest first
  - `(*Store).ExpireCommands(ctx, now time.Time) (int64, error)` — all tenants
  - `commands.Sign(key ed25519.PrivateKey, c *flv1.Command) (*flv1.SignedCommand, error)`
  - `commands.Verify(pub ed25519.PublicKey, sc *flv1.SignedCommand, deviceID string, now time.Time) (*flv1.Command, error)` — checks signature, device, and expiry (5 min skew). Replay (duplicate ID) detection is the agent's job (plan 1b); redelivery of unacknowledged `sent` commands is by design.
  - `commands.ParseType(name string) (flv1.CommandType, error)`; `commands.TypeName(t flv1.CommandType) string` — names: `ping`, `refresh_inventory`, `rotate_certificate`, `uninstall`, `update_agent`
  - `commands.DefaultTTL = 24 * time.Hour`
  - `commands.Service{Store *store.Store; Keys *bootstrap.Keys; Hub *hub.Hub; Now func() time.Time; Log *slog.Logger}` implementing `agentapi.CommandSink`, plus `(*Service).Issue(ctx, tenantID, deviceID uuid.UUID, typ flv1.CommandType, payload []byte, issuedBy *uuid.UUID, actor string) (uuid.UUID, error)` and `(*Service).ExpireStale(ctx) (int64, error)`
  - Audit action names: `command.issue`, `command.result`.

- [ ] **Step 1: Write failing sign tests**

`internal/server/commands/sign_test.go`:
```go
package commands

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	flv1 "freelocker/gen/freelocker/v1"
)

func TestSignVerify(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	c := &flv1.Command{Id: "c1", Type: flv1.CommandType_COMMAND_TYPE_PING, DeviceId: "dev-1",
		IssuedAtUnix: now.Unix(), ExpiresAtUnix: now.Add(time.Hour).Unix()}
	sc, err := Sign(priv, c)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Verify(pub, sc, "dev-1", now)
	if err != nil || got.GetId() != "c1" {
		t.Fatalf("Verify = %v, %v", got, err)
	}
	if _, err := Verify(pub, sc, "dev-2", now); err == nil {
		t.Error("wrong device must fail")
	}
	if _, err := Verify(pub, sc, "dev-1", now.Add(2*time.Hour)); err == nil {
		t.Error("expired command must fail")
	}
	sc.Command[0] ^= 1
	if _, err := Verify(pub, sc, "dev-1", now); err == nil {
		t.Error("tampered command must fail")
	}
}

func TestTypeNames(t *testing.T) {
	for _, name := range []string{"ping", "refresh_inventory", "rotate_certificate", "uninstall", "update_agent"} {
		typ, err := ParseType(name)
		if err != nil || TypeName(typ) != name {
			t.Errorf("%s: %v %v", name, typ, err)
		}
	}
	if _, err := ParseType("format_c"); err == nil {
		t.Error("unknown type must fail")
	}
}
```

- [ ] **Step 2: Run — expect FAIL**

Run: `go test ./internal/server/commands/`

- [ ] **Step 3: Implement signing**

`internal/server/commands/sign.go`:
```go
package commands

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"

	flv1 "freelocker/gen/freelocker/v1"

	"google.golang.org/protobuf/proto"
)

const clockSkew = 5 * time.Minute

var typeNames = map[flv1.CommandType]string{
	flv1.CommandType_COMMAND_TYPE_PING:               "ping",
	flv1.CommandType_COMMAND_TYPE_REFRESH_INVENTORY:  "refresh_inventory",
	flv1.CommandType_COMMAND_TYPE_ROTATE_CERTIFICATE: "rotate_certificate",
	flv1.CommandType_COMMAND_TYPE_UNINSTALL:          "uninstall",
	flv1.CommandType_COMMAND_TYPE_UPDATE_AGENT:       "update_agent",
}

func TypeName(t flv1.CommandType) string { return typeNames[t] }

func ParseType(name string) (flv1.CommandType, error) {
	for t, n := range typeNames {
		if n == name {
			return t, nil
		}
	}
	return flv1.CommandType_COMMAND_TYPE_UNSPECIFIED, fmt.Errorf("unknown command type %q", name)
}

func Sign(key ed25519.PrivateKey, c *flv1.Command) (*flv1.SignedCommand, error) {
	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(c)
	if err != nil {
		return nil, err
	}
	return &flv1.SignedCommand{Command: b, Signature: ed25519.Sign(key, b)}, nil
}

func Verify(pub ed25519.PublicKey, sc *flv1.SignedCommand, deviceID string, now time.Time) (*flv1.Command, error) {
	if !ed25519.Verify(pub, sc.GetCommand(), sc.GetSignature()) {
		return nil, errors.New("bad command signature")
	}
	c := &flv1.Command{}
	if err := proto.Unmarshal(sc.GetCommand(), c); err != nil {
		return nil, err
	}
	if c.GetDeviceId() != deviceID {
		return nil, errors.New("command addressed to another device")
	}
	if now.After(time.Unix(c.GetExpiresAtUnix(), 0).Add(clockSkew)) {
		return nil, errors.New("command expired")
	}
	return c, nil
}
```

- [ ] **Step 4: Run sign tests — expect PASS**

Run: `go test ./internal/server/commands/`

- [ ] **Step 5: Write failing command store test**

`internal/server/store/commands_test.go`:
```go
package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"freelocker/internal/server/store"
	"freelocker/internal/server/store/storetest"

	"github.com/google/uuid"
)

func TestCommandLifecycle(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	tenant, _ := s.CreateTenant(ctx, "Acme")
	s.CreateInstallToken(ctx, tenant, store.InstallToken{Name: "t"}, []byte("h"))
	dev := uuid.New()
	s.EnrollDevice(ctx, []byte("h"), time.Now(), func(uuid.UUID) (store.NewDevice, error) { return newDev(dev), nil })

	now := time.Now().Truncate(time.Microsecond)
	live := store.Command{ID: uuid.New(), DeviceID: dev, Type: "ping", IssuedAt: now, ExpiresAt: now.Add(time.Hour)}
	stale := store.Command{ID: uuid.New(), DeviceID: dev, Type: "ping", IssuedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Hour)}
	for _, c := range []store.Command{live, stale} {
		if err := s.CreateCommand(ctx, tenant, c); err != nil {
			t.Fatal(err)
		}
	}

	open, err := s.OpenCommands(ctx, tenant, dev, now)
	if err != nil || len(open) != 1 || open[0].ID != live.ID || open[0].State != "pending" {
		t.Fatalf("open = %+v, %v", open, err)
	}
	if err := s.MarkCommandSent(ctx, tenant, live.ID); err != nil {
		t.Fatal(err)
	}
	if open, _ := s.OpenCommands(ctx, tenant, dev, now); len(open) != 1 || open[0].State != "sent" {
		t.Fatalf("sent command must stay open for redelivery: %+v", open)
	}

	if err := s.CompleteCommand(ctx, tenant, uuid.New(), live.ID, true, "pong", now); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("completion by another device err = %v", err)
	}
	if err := s.CompleteCommand(ctx, tenant, dev, live.ID, true, "pong", now); err != nil {
		t.Fatal(err)
	}
	if err := s.CompleteCommand(ctx, tenant, dev, live.ID, true, "again", now); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("double completion err = %v", err)
	}

	n, err := s.ExpireCommands(ctx, now)
	if err != nil || n != 1 {
		t.Fatalf("expired = %d, %v", n, err)
	}
	hist, _ := s.ListDeviceCommands(ctx, tenant, dev, 10)
	states := map[uuid.UUID]string{}
	for _, c := range hist {
		states[c.ID] = c.State
	}
	if states[live.ID] != "succeeded" || states[stale.ID] != "expired" {
		t.Errorf("states = %v", states)
	}
	if hist[0].ID != live.ID || hist[0].Result != "pong" || hist[0].CompletedAt == nil {
		t.Errorf("newest = %+v", hist[0])
	}
}
```

- [ ] **Step 6: Run — expect FAIL**

Run: `go test ./internal/server/store/ -run TestCommandLifecycle`

- [ ] **Step 7: Implement command store**

`internal/server/store/commands.go`:
```go
package store

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type Command struct {
	ID          uuid.UUID
	DeviceID    uuid.UUID
	Type        string
	Payload     []byte
	IssuedBy    *uuid.UUID
	IssuedAt    time.Time
	ExpiresAt   time.Time
	State       string
	Result      string
	CompletedAt *time.Time
}

const commandCols = `id, device_id, type, payload, issued_by, issued_at, expires_at, state, result, completed_at`

func collectCommands(rows pgx.Rows) ([]Command, error) {
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Command, error) {
		var c Command
		return c, r.Scan(&c.ID, &c.DeviceID, &c.Type, &c.Payload, &c.IssuedBy, &c.IssuedAt, &c.ExpiresAt, &c.State, &c.Result, &c.CompletedAt)
	})
}

func (s *Store) CreateCommand(ctx context.Context, tenantID uuid.UUID, c Command) error {
	if c.Payload == nil {
		c.Payload = []byte{}
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO commands (id, tenant_id, device_id, type, payload, issued_by, issued_at, expires_at, state)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'pending')`,
		c.ID, tenantID, c.DeviceID, c.Type, c.Payload, c.IssuedBy, c.IssuedAt, c.ExpiresAt)
	return err
}

func (s *Store) OpenCommands(ctx context.Context, tenantID, deviceID uuid.UUID, now time.Time) ([]Command, error) {
	rows, _ := s.pool.Query(ctx, `SELECT `+commandCols+` FROM commands
		WHERE tenant_id = $1 AND device_id = $2 AND state IN ('pending', 'sent') AND expires_at > $3
		ORDER BY issued_at`, tenantID, deviceID, now)
	return collectCommands(rows)
}

func (s *Store) MarkCommandSent(ctx context.Context, tenantID, id uuid.UUID) error {
	return oneRow(s.pool.Exec(ctx, `UPDATE commands SET state = 'sent' WHERE tenant_id = $1 AND id = $2 AND state = 'pending'`, tenantID, id))
}

func (s *Store) CompleteCommand(ctx context.Context, tenantID, deviceID, id uuid.UUID, success bool, result string, now time.Time) error {
	state := "failed"
	if success {
		state = "succeeded"
	}
	return oneRow(s.pool.Exec(ctx, `
		UPDATE commands SET state = $4, result = $5, completed_at = $6
		WHERE tenant_id = $1 AND device_id = $2 AND id = $3 AND state IN ('pending', 'sent')`,
		tenantID, deviceID, id, state, result, now))
}

func (s *Store) ListDeviceCommands(ctx context.Context, tenantID, deviceID uuid.UUID, limit int) ([]Command, error) {
	rows, _ := s.pool.Query(ctx, `SELECT `+commandCols+` FROM commands
		WHERE tenant_id = $1 AND device_id = $2 ORDER BY issued_at DESC LIMIT $3`, tenantID, deviceID, limit)
	return collectCommands(rows)
}

func (s *Store) ExpireCommands(ctx context.Context, now time.Time) (int64, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE commands SET state = 'expired'
		WHERE state IN ('pending', 'sent') AND expires_at <= $1`, now)
	return tag.RowsAffected(), err
}
```

- [ ] **Step 8: Implement command service**

`internal/server/commands/commands.go`:
```go
// Package commands issues signed commands to agents and records results.
package commands

import (
	"context"
	"log/slog"
	"time"

	flv1 "freelocker/gen/freelocker/v1"
	"freelocker/internal/server/bootstrap"
	"freelocker/internal/server/hub"
	"freelocker/internal/server/store"

	"github.com/google/uuid"
)

const DefaultTTL = 24 * time.Hour

type Service struct {
	Store *store.Store
	Keys  *bootstrap.Keys
	Hub   *hub.Hub
	Now   func() time.Time
	Log   *slog.Logger
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Service) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

func (s *Service) Issue(ctx context.Context, tenantID, deviceID uuid.UUID, typ flv1.CommandType, payload []byte, issuedBy *uuid.UUID, actor string) (uuid.UUID, error) {
	now := s.now()
	c := store.Command{
		ID: uuid.New(), DeviceID: deviceID, Type: TypeName(typ), Payload: payload, IssuedBy: issuedBy,
		IssuedAt: now, ExpiresAt: now.Add(DefaultTTL),
	}
	if err := s.Store.CreateCommand(ctx, tenantID, c); err != nil {
		return uuid.Nil, err
	}
	if err := s.Store.AppendAudit(ctx, tenantID, store.AuditEntry{
		Actor: actor, Action: "command.issue", TargetType: "device", TargetID: deviceID.String(),
		Detail: map[string]any{"command_id": c.ID.String(), "type": c.Type}, Result: "success",
	}); err != nil {
		s.log().Error("audit write failed", "err", err)
	}
	s.deliver(ctx, tenantID, c)
	return c.ID, nil
}

// DeliverPending pushes every open command; called when an agent connects.
func (s *Service) DeliverPending(ctx context.Context, tenantID, deviceID uuid.UUID) error {
	open, err := s.Store.OpenCommands(ctx, tenantID, deviceID, s.now())
	if err != nil {
		return err
	}
	for _, c := range open {
		s.deliver(ctx, tenantID, c)
	}
	return nil
}

func (s *Service) deliver(ctx context.Context, tenantID uuid.UUID, c store.Command) {
	typ, err := ParseType(c.Type)
	if err != nil {
		s.log().Error("stored command has unknown type", "command", c.ID, "type", c.Type)
		return
	}
	sc, err := Sign(s.Keys.CommandKey, &flv1.Command{
		Id: c.ID.String(), Type: typ, DeviceId: c.DeviceID.String(),
		IssuedAtUnix: c.IssuedAt.Unix(), ExpiresAtUnix: c.ExpiresAt.Unix(), Payload: c.Payload,
	})
	if err != nil {
		s.log().Error("sign command", "command", c.ID, "err", err)
		return
	}
	if !s.Hub.Send(c.DeviceID, &flv1.ServerMessage{Body: &flv1.ServerMessage_Command{Command: sc}}) {
		return // stays pending; delivered on next connect
	}
	if c.State == "" || c.State == "pending" {
		if err := s.Store.MarkCommandSent(ctx, tenantID, c.ID); err != nil {
			s.log().Warn("mark command sent", "command", c.ID, "err", err)
		}
	}
}

func (s *Service) Complete(ctx context.Context, tenantID, deviceID uuid.UUID, r *flv1.CommandResult) error {
	id, err := uuid.Parse(r.GetCommandId())
	if err != nil {
		return err
	}
	if err := s.Store.CompleteCommand(ctx, tenantID, deviceID, id, r.GetSuccess(), r.GetMessage(), s.now()); err != nil {
		return err
	}
	result := "failure"
	if r.GetSuccess() {
		result = "success"
	}
	return s.Store.AppendAudit(ctx, tenantID, store.AuditEntry{
		Actor: "device:" + deviceID.String(), Action: "command.result", TargetType: "command", TargetID: id.String(),
		Detail: map[string]any{"message": r.GetMessage()}, Result: result,
	})
}

func (s *Service) ExpireStale(ctx context.Context) (int64, error) {
	return s.Store.ExpireCommands(ctx, s.now())
}
```

- [ ] **Step 9: Wire the command service into the test helper**

In `internal/server/agentapi/testserver_test.go` replace `newDeps` with:
```go
func newDeps(s *store.Store, k *bootstrap.Keys) agentapi.Deps {
	h := hub.New()
	return agentapi.Deps{Store: s, Keys: k, Hub: h, Commands: &commands.Service{Store: s, Keys: k, Hub: h}}
}
```
and add import `"freelocker/internal/server/commands"`.

- [ ] **Step 10: Write failing end-to-end command tests**

`internal/server/agentapi/commands_test.go`:
```go
package agentapi_test

import (
	"context"
	"testing"
	"time"

	flv1 "freelocker/gen/freelocker/v1"
	"freelocker/internal/server/commands"
	"freelocker/internal/sim"

	"github.com/google/uuid"
)

func recvCommand(t *testing.T, s *sim.Session) *flv1.SignedCommand {
	t.Helper()
	select {
	case c := <-s.Commands():
		return c
	case <-time.After(5 * time.Second):
		t.Fatal("no command received")
		return nil
	}
}

func TestLiveCommandDeliveredSignedAndResultRecorded(t *testing.T) {
	ctx := context.Background()
	ts := startServer(t)
	id, sess := enrollAndConnect(t, ts)
	devID := uuid.MustParse(id.DeviceID)
	eventually(t, "connected", func() bool { return ts.Deps.Hub.Connected(devID) })
	svc := ts.Deps.Commands.(*commands.Service)

	cmdID, err := svc.Issue(ctx, ts.Deps.Keys.TenantID, devID, flv1.CommandType_COMMAND_TYPE_PING, nil, nil, "admin:test@example.com")
	if err != nil {
		t.Fatal(err)
	}
	cmd, err := commands.Verify(id.CommandPub, recvCommand(t, sess), id.DeviceID, time.Now())
	if err != nil || cmd.GetId() != cmdID.String() || cmd.GetType() != flv1.CommandType_COMMAND_TYPE_PING {
		t.Fatalf("verify = %+v, %v", cmd, err)
	}

	sess.SendResult(&flv1.CommandResult{CommandId: cmd.GetId(), Success: true, Message: "pong"})
	eventually(t, "command succeeded", func() bool {
		hist, _ := ts.Deps.Store.ListDeviceCommands(ctx, ts.Deps.Keys.TenantID, devID, 1)
		return len(hist) == 1 && hist[0].State == "succeeded" && hist[0].Result == "pong"
	})
}

func TestCommandQueuedWhileOfflineDeliveredOnConnect(t *testing.T) {
	ctx := context.Background()
	ts := startServer(t)
	id, err := sim.Enroll(ctx, ts.Addr, ts.Token, hw)
	if err != nil {
		t.Fatal(err)
	}
	devID := uuid.MustParse(id.DeviceID)
	svc := ts.Deps.Commands.(*commands.Service)
	cmdID, _ := svc.Issue(ctx, ts.Deps.Keys.TenantID, devID, flv1.CommandType_COMMAND_TYPE_REFRESH_INVENTORY, nil, nil, "system")

	sess, err := sim.Connect(ctx, ts.Addr, id)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	cmd, err := commands.Verify(id.CommandPub, recvCommand(t, sess), id.DeviceID, time.Now())
	if err != nil || cmd.GetId() != cmdID.String() {
		t.Fatalf("queued command = %+v, %v", cmd, err)
	}
}
```

- [ ] **Step 11: Run — expect PASS**

Run: `go test ./internal/server/... ./internal/sim/`

- [ ] **Step 12: Commit**

```powershell
git add internal/server/store internal/server/commands internal/server/agentapi
git commit -m "feat: add signed agent commands with queued delivery and results"
```

---

### Task 11: Admin accounts, sessions, passwords, and TOTP

**Files:**
- Create: `internal/server/store/admins.go`, `internal/server/auth/password.go`, `internal/server/auth/sessions.go`
- Modify: `internal/server/store/store.go` (add `ErrConflict` + `conflict` helper)
- Test: `internal/server/store/admins_test.go`, `internal/server/auth/password_test.go`, `internal/server/auth/sessions_test.go`

**Interfaces:**
- Consumes: store core (Task 2), `storetest.New` (Task 6).
- Produces:
  - `store.ErrConflict` (unique-constraint violation); internal helper `conflict(err error) error`
  - `store.Admin{ID uuid.UUID; Email, PasswordHash string; TOTPSecretEnc []byte; TOTPConfirmed bool; Role string; Disabled bool; CreatedAt time.Time}`
  - `(*Store).CreateAdmin(ctx, tenantID uuid.UUID, a store.Admin) (uuid.UUID, error)` (email lower-cased; `ErrConflict` on duplicate)
  - `(*Store).GetAdmin(ctx, tenantID, id uuid.UUID) (store.Admin, error)`; `(*Store).GetAdminByEmail(ctx, tenantID uuid.UUID, email string) (store.Admin, error)`; `(*Store).ListAdmins(ctx, tenantID uuid.UUID) ([]store.Admin, error)`
  - `(*Store).SetAdminTOTP(ctx, tenantID, id uuid.UUID, secretEnc []byte, confirmed bool) error`; `(*Store).SetAdminDisabled(ctx, tenantID, id uuid.UUID, disabled bool) error`
  - `store.Session{ID string; TenantID, AdminID uuid.UUID; CSRFToken string; MFAPassed bool; ExpiresAt time.Time; IP, UserAgent string}`
  - `(*Store).CreateSession(ctx, s store.Session) error`; `(*Store).GetSession(ctx, id string, now time.Time) (store.Session, error)` (`ErrNotFound` if missing/expired); `(*Store).MarkSessionMFA(ctx, id string) error`; `(*Store).DeleteSession(ctx, id string) error`; `(*Store).DeleteAdminSessions(ctx, tenantID, adminID uuid.UUID) error`
  - `auth.MinPasswordLen = 12`; `auth.HashPassword(pw string) (string, error)`; `auth.CheckPassword(hash, pw string) bool`; `auth.CheckPasswordOrDummy(hash *string, pw string) bool` (constant work when the user does not exist)
  - `auth.NewTOTPSecret(email string) (secret, otpauthURL string, err error)`; `auth.ValidateTOTP(secret, code string, now time.Time) bool`
  - `auth.Roles = []string{"owner","admin","readonly"}`; `auth.Allows(role, required string) bool`
  - `auth.CookieName = "fl_session"`; `auth.SessionTTL = 12 * time.Hour`
  - `auth.Sessions{Store *store.Store; Now func() time.Time; Secure bool}`; `(*Sessions).Create(ctx, w http.ResponseWriter, r *http.Request, tenantID, adminID uuid.UUID) (store.Session, error)`; `(*Sessions).Load(ctx, r *http.Request) (store.Session, error)`; `(*Sessions).Destroy(ctx, w http.ResponseWriter, r *http.Request)`
  - Session IDs in the DB are `hex(SHA-256(cookie token))`; the raw token only lives in the cookie.

- [ ] **Step 1: Add `ErrConflict` to store.go**

In `internal/server/store/store.go`, add to the `var` block and file:
```go
var ErrConflict = errors.New("already exists")

// conflict maps a unique-constraint violation to ErrConflict.
func conflict(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return ErrConflict
	}
	return err
}
```
Add import `"github.com/jackc/pgx/v5/pgconn"`.

- [ ] **Step 2: Write failing admin/session store test**

`internal/server/store/admins_test.go`:
```go
package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"freelocker/internal/server/store"
	"freelocker/internal/server/store/storetest"
)

func TestAdminsAndSessions(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	tenant, _ := s.CreateTenant(ctx, "Acme")

	id, err := s.CreateAdmin(ctx, tenant, store.Admin{Email: "Owner@Example.com", PasswordHash: "h", Role: "owner"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateAdmin(ctx, tenant, store.Admin{Email: "owner@example.com", PasswordHash: "h", Role: "admin"}); !errors.Is(err, store.ErrConflict) {
		t.Errorf("duplicate email err = %v", err)
	}
	a, err := s.GetAdminByEmail(ctx, tenant, "OWNER@example.com")
	if err != nil || a.ID != id || a.Email != "owner@example.com" || a.TOTPConfirmed {
		t.Fatalf("GetAdminByEmail = %+v, %v", a, err)
	}
	if err := s.SetAdminTOTP(ctx, tenant, id, []byte("enc"), true); err != nil {
		t.Fatal(err)
	}
	a, _ = s.GetAdmin(ctx, tenant, id)
	if string(a.TOTPSecretEnc) != "enc" || !a.TOTPConfirmed {
		t.Errorf("totp not stored: %+v", a)
	}

	now := time.Now()
	sess := store.Session{ID: "sid", TenantID: tenant, AdminID: id, CSRFToken: "csrf", ExpiresAt: now.Add(time.Hour), IP: "1.2.3.4", UserAgent: "ua"}
	if err := s.CreateSession(ctx, sess); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetSession(ctx, "sid", now)
	if err != nil || got.AdminID != id || got.MFAPassed || got.CSRFToken != "csrf" {
		t.Fatalf("GetSession = %+v, %v", got, err)
	}
	s.MarkSessionMFA(ctx, "sid")
	got, _ = s.GetSession(ctx, "sid", now)
	if !got.MFAPassed {
		t.Error("MFA flag not set")
	}
	if _, err := s.GetSession(ctx, "sid", now.Add(2*time.Hour)); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("expired session err = %v", err)
	}

	s.CreateSession(ctx, store.Session{ID: "sid2", TenantID: tenant, AdminID: id, CSRFToken: "c", ExpiresAt: now.Add(time.Hour)})
	if err := s.SetAdminDisabled(ctx, tenant, id, true); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteAdminSessions(ctx, tenant, id); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetSession(ctx, "sid2", now); !errors.Is(err, store.ErrNotFound) {
		t.Error("admin sessions should be deleted")
	}
	list, _ := s.ListAdmins(ctx, tenant)
	if len(list) != 1 || !list[0].Disabled {
		t.Errorf("admins = %+v", list)
	}
}
```

- [ ] **Step 3: Run — expect FAIL**

Run: `go test ./internal/server/store/ -run TestAdmins`

- [ ] **Step 4: Implement admin and session store**

`internal/server/store/admins.go`:
```go
package store

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type Admin struct {
	ID            uuid.UUID
	Email         string
	PasswordHash  string
	TOTPSecretEnc []byte
	TOTPConfirmed bool
	Role          string
	Disabled      bool
	CreatedAt     time.Time
}

type Session struct {
	ID        string
	TenantID  uuid.UUID
	AdminID   uuid.UUID
	CSRFToken string
	MFAPassed bool
	ExpiresAt time.Time
	IP        string
	UserAgent string
}

const adminCols = `id, email, password_hash, totp_secret_enc, totp_confirmed, role, disabled, created_at`

func scanAdmin(r pgx.Row) (Admin, error) {
	var a Admin
	err := r.Scan(&a.ID, &a.Email, &a.PasswordHash, &a.TOTPSecretEnc, &a.TOTPConfirmed, &a.Role, &a.Disabled, &a.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	return a, err
}

func (s *Store) CreateAdmin(ctx context.Context, tenantID uuid.UUID, a Admin) (uuid.UUID, error) {
	id := uuid.New()
	_, err := s.pool.Exec(ctx, `INSERT INTO admins (id, tenant_id, email, password_hash, role) VALUES ($1, $2, $3, $4, $5)`,
		id, tenantID, strings.ToLower(a.Email), a.PasswordHash, a.Role)
	return id, conflict(err)
}

func (s *Store) GetAdmin(ctx context.Context, tenantID, id uuid.UUID) (Admin, error) {
	return scanAdmin(s.pool.QueryRow(ctx, `SELECT `+adminCols+` FROM admins WHERE tenant_id = $1 AND id = $2`, tenantID, id))
}

func (s *Store) GetAdminByEmail(ctx context.Context, tenantID uuid.UUID, email string) (Admin, error) {
	return scanAdmin(s.pool.QueryRow(ctx, `SELECT `+adminCols+` FROM admins WHERE tenant_id = $1 AND email = $2`,
		tenantID, strings.ToLower(email)))
}

func (s *Store) ListAdmins(ctx context.Context, tenantID uuid.UUID) ([]Admin, error) {
	rows, _ := s.pool.Query(ctx, `SELECT `+adminCols+` FROM admins WHERE tenant_id = $1 ORDER BY email`, tenantID)
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Admin, error) { return scanAdmin(r) })
}

func (s *Store) SetAdminTOTP(ctx context.Context, tenantID, id uuid.UUID, secretEnc []byte, confirmed bool) error {
	return oneRow(s.pool.Exec(ctx, `UPDATE admins SET totp_secret_enc = $3, totp_confirmed = $4 WHERE tenant_id = $1 AND id = $2`,
		tenantID, id, secretEnc, confirmed))
}

func (s *Store) SetAdminDisabled(ctx context.Context, tenantID, id uuid.UUID, disabled bool) error {
	return oneRow(s.pool.Exec(ctx, `UPDATE admins SET disabled = $3 WHERE tenant_id = $1 AND id = $2`, tenantID, id, disabled))
}

func (s *Store) CreateSession(ctx context.Context, sess Session) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO sessions (id, tenant_id, admin_id, csrf_token, mfa_passed, expires_at, ip, user_agent)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		sess.ID, sess.TenantID, sess.AdminID, sess.CSRFToken, sess.MFAPassed, sess.ExpiresAt, sess.IP, sess.UserAgent)
	return err
}

func (s *Store) GetSession(ctx context.Context, id string, now time.Time) (Session, error) {
	var sess Session
	err := s.pool.QueryRow(ctx, `
		SELECT id, tenant_id, admin_id, csrf_token, mfa_passed, expires_at, ip, user_agent
		FROM sessions WHERE id = $1 AND expires_at > $2`, id, now).
		Scan(&sess.ID, &sess.TenantID, &sess.AdminID, &sess.CSRFToken, &sess.MFAPassed, &sess.ExpiresAt, &sess.IP, &sess.UserAgent)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	return sess, err
}

func (s *Store) MarkSessionMFA(ctx context.Context, id string) error {
	return oneRow(s.pool.Exec(ctx, `UPDATE sessions SET mfa_passed = true WHERE id = $1`, id))
}

func (s *Store) DeleteSession(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE id = $1`, id)
	return err
}

func (s *Store) DeleteAdminSessions(ctx context.Context, tenantID, adminID uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE tenant_id = $1 AND admin_id = $2`, tenantID, adminID)
	return err
}
```

- [ ] **Step 5: Run store test — expect PASS**

Run: `go test ./internal/server/store/`

- [ ] **Step 6: Write failing auth tests**

`internal/server/auth/password_test.go`:
```go
package auth

import (
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

func TestPasswordHashing(t *testing.T) {
	if _, err := HashPassword("short"); err == nil {
		t.Error("short password must be rejected")
	}
	h, err := HashPassword("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if !CheckPassword(h, "correct horse battery") || CheckPassword(h, "wrong password!!") {
		t.Error("CheckPassword wrong")
	}
	if CheckPasswordOrDummy(nil, "anything at all") {
		t.Error("missing user must never authenticate")
	}
	if !CheckPasswordOrDummy(&h, "correct horse battery") {
		t.Error("existing user with right password must authenticate")
	}
}

func TestTOTP(t *testing.T) {
	secret, url, err := NewTOTPSecret("bob@example.com")
	if err != nil || !strings.HasPrefix(url, "otpauth://totp/") {
		t.Fatalf("NewTOTPSecret = %q, %v", url, err)
	}
	now := time.Now()
	code, _ := totp.GenerateCode(secret, now)
	if !ValidateTOTP(secret, code, now) {
		t.Error("current code must validate")
	}
	if ValidateTOTP(secret, code, now.Add(5*time.Minute)) {
		t.Error("code from 5 minutes ago must not validate")
	}
}

func TestAllows(t *testing.T) {
	cases := []struct {
		role, required string
		want           bool
	}{
		{"owner", "admin", true}, {"admin", "admin", true}, {"readonly", "admin", false},
		{"admin", "owner", false}, {"readonly", "readonly", true}, {"bogus", "readonly", false},
	}
	for _, c := range cases {
		if got := Allows(c.role, c.required); got != c.want {
			t.Errorf("Allows(%s, %s) = %v", c.role, c.required, got)
		}
	}
}
```

`internal/server/auth/sessions_test.go`:
```go
package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"freelocker/internal/server/store"
	"freelocker/internal/server/store/storetest"
)

func TestSessionCreateLoadDestroy(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	tenant, _ := s.CreateTenant(ctx, "Acme")
	admin, _ := s.CreateAdmin(ctx, tenant, store.Admin{Email: "a@example.com", PasswordHash: "h", Role: "owner"})
	m := &Sessions{Store: s, Secure: true}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/login", nil)
	sess, err := m.Create(ctx, rec, req, tenant, admin)
	if err != nil || sess.CSRFToken == "" {
		t.Fatalf("Create = %+v, %v", sess, err)
	}
	cookie := rec.Result().Cookies()[0]
	if cookie.Name != CookieName || !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteStrictMode {
		t.Errorf("cookie flags wrong: %+v", cookie)
	}
	if cookie.Value == sess.ID {
		t.Error("DB session id must be a hash, not the cookie token")
	}

	req2 := httptest.NewRequest("GET", "/api/me", nil)
	req2.AddCookie(cookie)
	got, err := m.Load(ctx, req2)
	if err != nil || got.AdminID != admin {
		t.Fatalf("Load = %+v, %v", got, err)
	}

	m.Destroy(ctx, httptest.NewRecorder(), req2)
	if _, err := m.Load(ctx, req2); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("after destroy err = %v", err)
	}
	if _, err := m.Load(ctx, httptest.NewRequest("GET", "/", nil)); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("no cookie err = %v", err)
	}
}
```

- [ ] **Step 7: Run — expect FAIL**

Run: `go test ./internal/server/auth/`

- [ ] **Step 8: Implement auth helpers**

`internal/server/auth/password.go`:
```go
// Package auth holds console authentication primitives: passwords, TOTP,
// sessions, and role checks.
package auth

import (
	"fmt"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

const (
	MinPasswordLen = 12
	bcryptCost     = 12
)

// dummyHash lets login spend bcrypt time even for unknown users.
var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("freelocker-dummy-password"), bcryptCost)

func HashPassword(pw string) (string, error) {
	if len(pw) < MinPasswordLen {
		return "", fmt.Errorf("password must be at least %d characters", MinPasswordLen)
	}
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcryptCost)
	return string(h), err
}

func CheckPassword(hash, pw string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(pw)) == nil
}

func CheckPasswordOrDummy(hash *string, pw string) bool {
	if hash == nil {
		bcrypt.CompareHashAndPassword(dummyHash, []byte(pw))
		return false
	}
	return CheckPassword(*hash, pw)
}

func NewTOTPSecret(email string) (secret, otpauthURL string, err error) {
	k, err := totp.Generate(totp.GenerateOpts{Issuer: "FreeLocker", AccountName: email})
	if err != nil {
		return "", "", err
	}
	return k.Secret(), k.URL(), nil
}

func ValidateTOTP(secret, code string, now time.Time) bool {
	ok, err := totp.ValidateCustom(code, secret, now, totp.ValidateOpts{
		Period: 30, Skew: 1, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
	})
	return err == nil && ok
}

var Roles = []string{"owner", "admin", "readonly"}

var roleRank = map[string]int{"readonly": 1, "admin": 2, "owner": 3}

func Allows(role, required string) bool {
	r, ok := roleRank[role]
	return ok && r >= roleRank[required]
}
```

`internal/server/auth/sessions.go`:
```go
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net"
	"net/http"
	"time"

	"freelocker/internal/server/store"

	"github.com/google/uuid"
)

const (
	CookieName = "fl_session"
	SessionTTL = 12 * time.Hour
)

type Sessions struct {
	Store  *store.Store
	Now    func() time.Time
	Secure bool
}

func (m *Sessions) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

func randToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func hashToken(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(sum[:])
}

func ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (m *Sessions) Create(ctx context.Context, w http.ResponseWriter, r *http.Request, tenantID, adminID uuid.UUID) (store.Session, error) {
	tok := randToken()
	sess := store.Session{
		ID: hashToken(tok), TenantID: tenantID, AdminID: adminID, CSRFToken: randToken(),
		ExpiresAt: m.now().Add(SessionTTL), IP: ClientIP(r), UserAgent: r.UserAgent(),
	}
	if err := m.Store.CreateSession(ctx, sess); err != nil {
		return store.Session{}, err
	}
	http.SetCookie(w, &http.Cookie{
		Name: CookieName, Value: tok, Path: "/", Expires: sess.ExpiresAt,
		HttpOnly: true, Secure: m.Secure, SameSite: http.SameSiteStrictMode,
	})
	return sess, nil
}

func (m *Sessions) Load(ctx context.Context, r *http.Request) (store.Session, error) {
	c, err := r.Cookie(CookieName)
	if err != nil || c.Value == "" {
		return store.Session{}, store.ErrNotFound
	}
	return m.Store.GetSession(ctx, hashToken(c.Value), m.now())
}

func (m *Sessions) Destroy(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(CookieName); err == nil {
		m.Store.DeleteSession(ctx, hashToken(c.Value))
	}
	http.SetCookie(w, &http.Cookie{Name: CookieName, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: m.Secure, SameSite: http.SameSiteStrictMode})
}
```
Also export `auth.ClientIP(r *http.Request) string` (used by the HTTP API for audit IPs).

Run: `go get github.com/pquerna/otp golang.org/x/crypto`

- [ ] **Step 9: Run — expect PASS**

Run: `go mod tidy; go test ./internal/server/auth/ ./internal/server/store/`

- [ ] **Step 10: Commit**

```powershell
git add internal/server/store internal/server/auth go.mod go.sum
git commit -m "feat: add admin accounts, sessions, bcrypt passwords, and TOTP"
```

---

### Task 12: Console HTTP API — setup, login, MFA, middleware

**Files:**
- Create: `internal/server/httpapi/api.go`, `internal/server/httpapi/json.go`, `internal/server/httpapi/limiter.go`, `internal/server/httpapi/authn.go`
- Test: `internal/server/httpapi/helpers_test.go`, `internal/server/httpapi/authn_test.go`, `internal/server/httpapi/limiter_test.go`

**Interfaces:**
- Consumes: `auth.*` and admin/session store (Task 11); `bootstrap.Keys` (Task 5); `commands.Service` (Task 10); `hub.Hub` (Task 9); `keys.Sealer` (Task 3).
- Produces:
  - `httpapi.Runtime{Keys *bootstrap.Keys; Commands *commands.Service}`
  - `httpapi.API{Store *store.Store; Runtime func() *httpapi.Runtime; Setup func(ctx context.Context, org, email, password string) error; Hub *hub.Hub; TOTPSealer *keys.Sealer; Sessions *auth.Sessions; Now func() time.Time; Log *slog.Logger}`
  - `(*API).Handler() http.Handler` — Task 13 adds resource routes inside `routes(r chi.Router)`.
  - Internal: `principal{Admin store.Admin; Session store.Session; TenantID uuid.UUID}`, `principalFrom(r) principal`, `(*API).requireRole(role string) func(http.Handler) http.Handler`, `(*API).audit(r *http.Request, p principal, action, targetType, targetID string, detail map[string]any, result string)`, `writeJSON(w, code int, v any)`, `writeErr(w, code int, msg string)`, `readJSON(w, r, v any) bool`.
  - Endpoints: `GET /api/setup/status` → `{"initialized":bool}`; `POST /api/setup` `{org_name,email,password}` → 201; `POST /api/login` `{email,password}` → `{"csrf_token","mfa_enrolled"}`; `POST /api/logout`; `POST /api/mfa/setup` → `{"secret","otpauth_url"}`; `POST /api/mfa/verify` `{code}`; `GET /api/me` → `{"id","email","role"}`.
  - Error body shape everywhere: `{"error":"<message>"}`. Status codes: 400 bad input, 401 not logged in / bad credentials, 403 forbidden / `mfa_required` / bad CSRF, 404, 409 conflict, 429 rate-limited, 503 `not initialized`.
  - CSRF: every non-GET request behind a session needs header `X-CSRF-Token` equal to the session's token.
  - Audit action names: `setup.complete` (written by the Setup func in Task 14), `admin.login` (success and failure).

- [ ] **Step 1: Write failing limiter test**

`internal/server/httpapi/limiter_test.go`:
```go
package httpapi

import (
	"testing"
	"time"
)

func TestLoginLimiter(t *testing.T) {
	l := newLoginLimiter()
	now := time.Now()
	for i := 0; i < maxFailures; i++ {
		if !l.allow("k", now) {
			t.Fatalf("attempt %d blocked early", i)
		}
		l.fail("k", now)
	}
	if l.allow("k", now) {
		t.Fatal("should be blocked after max failures")
	}
	if !l.allow("other", now) {
		t.Fatal("other keys unaffected")
	}
	if !l.allow("k", now.Add(failWindow+time.Second)) {
		t.Fatal("should unblock after window")
	}
	l.fail("k", now)
	l.reset("k")
	if !l.allow("k", now) {
		t.Fatal("reset should clear failures")
	}
}
```

- [ ] **Step 2: Implement limiter and JSON helpers**

`internal/server/httpapi/limiter.go`:
```go
package httpapi

import (
	"sync"
	"time"
)

const (
	maxFailures = 5
	failWindow  = 15 * time.Minute
)

// loginLimiter is an in-memory sliding-window failure counter. It is
// per-process; a multi-instance deployment would move this to Postgres.
type loginLimiter struct {
	mu    sync.Mutex
	fails map[string][]time.Time
}

func newLoginLimiter() *loginLimiter { return &loginLimiter{fails: map[string][]time.Time{}} }

func (l *loginLimiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	recent := l.fails[key][:0]
	for _, t := range l.fails[key] {
		if now.Sub(t) < failWindow {
			recent = append(recent, t)
		}
	}
	l.fails[key] = recent
	return len(recent) < maxFailures
}

func (l *loginLimiter) fail(key string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.fails[key] = append(l.fails[key], now)
}

func (l *loginLimiter) reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.fails, key)
}
```

`internal/server/httpapi/json.go`:
```go
package httpapi

import (
	"encoding/json"
	"net/http"
)

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	if v != nil {
		json.NewEncoder(w).Encode(v)
	}
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

// readJSON decodes a size-limited body with unknown fields rejected. It
// writes a 400 and returns false on failure.
func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return false
	}
	return true
}
```

- [ ] **Step 3: Run limiter test — expect PASS**

Run: `go test ./internal/server/httpapi/ -run TestLoginLimiter`

- [ ] **Step 4: Implement API core and authentication endpoints**

`internal/server/httpapi/api.go`:
```go
// Package httpapi is the console's REST/JSON API.
package httpapi

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"freelocker/internal/server/auth"
	"freelocker/internal/server/bootstrap"
	"freelocker/internal/server/commands"
	"freelocker/internal/server/hub"
	"freelocker/internal/server/keys"
	"freelocker/internal/server/store"

	"github.com/go-chi/chi/v5"
)

type Runtime struct {
	Keys     *bootstrap.Keys
	Commands *commands.Service
}

type API struct {
	Store      *store.Store
	Runtime    func() *Runtime // nil until the server is initialized
	Setup      func(ctx context.Context, org, email, password string) error
	Hub        *hub.Hub
	TOTPSealer *keys.Sealer
	Sessions   *auth.Sessions
	Now        func() time.Time
	Log        *slog.Logger

	limiter *loginLimiter
}

func (a *API) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

func (a *API) Handler() http.Handler {
	if a.Log == nil {
		a.Log = slog.Default()
	}
	a.limiter = newLoginLimiter()
	r := chi.NewRouter()
	r.Get("/api/setup/status", a.setupStatus)
	r.Post("/api/setup", a.setup)
	r.Group(func(r chi.Router) {
		r.Use(a.requireRuntime)
		r.Post("/api/login", a.login)
		r.Group(func(r chi.Router) {
			r.Use(a.withSession(false))
			r.Post("/api/logout", a.logout)
			r.Post("/api/mfa/setup", a.mfaSetup)
			r.Post("/api/mfa/verify", a.mfaVerify)
		})
		r.Group(func(r chi.Router) {
			r.Use(a.withSession(true))
			r.Get("/api/me", a.me)
			a.routes(r)
		})
	})
	return r
}

// routes registers resource endpoints; filled in by Task 13.
func (a *API) routes(r chi.Router) {}

func (a *API) requireRuntime(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.Runtime() == nil {
			writeErr(w, http.StatusServiceUnavailable, "not initialized")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *API) audit(r *http.Request, p principal, action, targetType, targetID string, detail map[string]any, result string) {
	err := a.Store.AppendAudit(r.Context(), p.TenantID, store.AuditEntry{
		Actor: "admin:" + p.Admin.Email, Action: action, TargetType: targetType, TargetID: targetID,
		Detail: detail, IP: auth.ClientIP(r), Result: result,
	})
	if err != nil {
		a.Log.Error("audit write failed", "action", action, "err", err)
	}
}
```

`internal/server/httpapi/authn.go`:
```go
package httpapi

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"

	"freelocker/internal/server/auth"
	"freelocker/internal/server/bootstrap"
	"freelocker/internal/server/store"

	"github.com/google/uuid"
)

type principalKey struct{}

type principal struct {
	Admin    store.Admin
	Session  store.Session
	TenantID uuid.UUID
}

func principalFrom(r *http.Request) principal { return r.Context().Value(principalKey{}).(principal) }

func (a *API) withSession(requireMFA bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sess, err := a.Sessions.Load(r.Context(), r)
			if err != nil {
				writeErr(w, http.StatusUnauthorized, "not logged in")
				return
			}
			admin, err := a.Store.GetAdmin(r.Context(), sess.TenantID, sess.AdminID)
			if err != nil || admin.Disabled {
				writeErr(w, http.StatusUnauthorized, "not logged in")
				return
			}
			if r.Method != http.MethodGet &&
				subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(sess.CSRFToken)) != 1 {
				writeErr(w, http.StatusForbidden, "bad CSRF token")
				return
			}
			if requireMFA && !sess.MFAPassed {
				writeErr(w, http.StatusForbidden, "mfa_required")
				return
			}
			p := principal{Admin: admin, Session: sess, TenantID: sess.TenantID}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), principalKey{}, p)))
		})
	}
}

func (a *API) requireRole(role string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !auth.Allows(principalFrom(r).Admin.Role, role) {
				writeErr(w, http.StatusForbidden, "requires role "+role)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func (a *API) setupStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]bool{"initialized": a.Runtime() != nil})
}

func (a *API) setup(w http.ResponseWriter, r *http.Request) {
	var req struct {
		OrgName  string `json:"org_name"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if a.Runtime() != nil {
		writeErr(w, http.StatusConflict, "already initialized")
		return
	}
	if strings.TrimSpace(req.OrgName) == "" || !strings.Contains(req.Email, "@") || len(req.Password) < auth.MinPasswordLen {
		writeErr(w, http.StatusBadRequest, "org_name, a valid email, and a password of at least 12 characters are required")
		return
	}
	err := a.Setup(r.Context(), strings.TrimSpace(req.OrgName), req.Email, req.Password)
	switch {
	case errors.Is(err, bootstrap.ErrAlreadyInitialized):
		writeErr(w, http.StatusConflict, "already initialized")
	case err != nil:
		a.Log.Error("setup failed", "err", err)
		writeErr(w, http.StatusInternalServerError, "setup failed")
	default:
		writeJSON(w, http.StatusCreated, map[string]bool{"initialized": true})
	}
}

func (a *API) login(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	tenant := a.Runtime().Keys.TenantID
	email := strings.ToLower(strings.TrimSpace(req.Email))
	key := auth.ClientIP(r) + "|" + email
	now := a.now()
	if !a.limiter.allow(key, now) {
		writeErr(w, http.StatusTooManyRequests, "too many failed attempts; try again later")
		return
	}

	admin, err := a.Store.GetAdminByEmail(r.Context(), tenant, email)
	var hash *string
	if err == nil && !admin.Disabled {
		hash = &admin.PasswordHash
	}
	if !auth.CheckPasswordOrDummy(hash, req.Password) {
		a.limiter.fail(key, now)
		a.audit(r, principal{TenantID: tenant, Admin: store.Admin{Email: email}}, "admin.login", "admin", "", map[string]any{"stage": "password"}, "failure")
		writeErr(w, http.StatusUnauthorized, "invalid email or password")
		return
	}
	a.limiter.reset(key)

	sess, err := a.Sessions.Create(r.Context(), w, r, tenant, admin.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not create session")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"csrf_token": sess.CSRFToken, "mfa_enrolled": admin.TOTPConfirmed})
}

func (a *API) logout(w http.ResponseWriter, r *http.Request) {
	a.Sessions.Destroy(r.Context(), w, r)
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) mfaSetup(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r)
	if p.Admin.TOTPConfirmed {
		writeErr(w, http.StatusConflict, "MFA already enrolled")
		return
	}
	secret, url, err := auth.NewTOTPSecret(p.Admin.Email)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not create TOTP secret")
		return
	}
	if err := a.Store.SetAdminTOTP(r.Context(), p.TenantID, p.Admin.ID, a.TOTPSealer.Seal([]byte(secret)), false); err != nil {
		writeErr(w, http.StatusInternalServerError, "could not store TOTP secret")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"secret": secret, "otpauth_url": url})
}

func (a *API) mfaVerify(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Code string `json:"code"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	p := principalFrom(r)
	if p.Admin.TOTPSecretEnc == nil {
		writeErr(w, http.StatusBadRequest, "MFA not set up; call /api/mfa/setup first")
		return
	}
	key := "mfa|" + p.Session.ID
	now := a.now()
	if !a.limiter.allow(key, now) {
		writeErr(w, http.StatusTooManyRequests, "too many failed attempts; try again later")
		return
	}
	secret, err := a.TOTPSealer.Open(p.Admin.TOTPSecretEnc)
	if err != nil || !auth.ValidateTOTP(string(secret), strings.TrimSpace(req.Code), now) {
		a.limiter.fail(key, now)
		a.audit(r, p, "admin.login", "admin", p.Admin.ID.String(), map[string]any{"stage": "mfa"}, "failure")
		writeErr(w, http.StatusUnauthorized, "invalid code")
		return
	}
	a.limiter.reset(key)
	if !p.Admin.TOTPConfirmed {
		if err := a.Store.SetAdminTOTP(r.Context(), p.TenantID, p.Admin.ID, p.Admin.TOTPSecretEnc, true); err != nil {
			writeErr(w, http.StatusInternalServerError, "could not confirm MFA")
			return
		}
	}
	if err := a.Store.MarkSessionMFA(r.Context(), p.Session.ID); err != nil {
		writeErr(w, http.StatusInternalServerError, "could not update session")
		return
	}
	a.audit(r, p, "admin.login", "admin", p.Admin.ID.String(), nil, "success")
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) me(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r)
	writeJSON(w, http.StatusOK, map[string]string{"id": p.Admin.ID.String(), "email": p.Admin.Email, "role": p.Admin.Role})
}
```
Run: `go get github.com/go-chi/chi/v5`

- [ ] **Step 5: Write the shared HTTP test helpers**

`internal/server/httpapi/helpers_test.go`:
```go
package httpapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"freelocker/internal/server/auth"
	"freelocker/internal/server/bootstrap"
	"freelocker/internal/server/commands"
	"freelocker/internal/server/httpapi"
	"freelocker/internal/server/hub"
	"freelocker/internal/server/keys"
	"freelocker/internal/server/store"
	"freelocker/internal/server/store/storetest"

	"github.com/pquerna/otp/totp"
)

type env struct {
	srv   *httptest.Server
	store *store.Store
	hub   *hub.Hub
	rt    func() *httpapi.Runtime
}

const ownerEmail, ownerPass = "owner@example.com", "owner-password-123"

// newEnv starts an uninitialized API. setupFn mirrors what the app does
// in Task 14 (init + owner + runtime).
func newEnv(t *testing.T) *env {
	t.Helper()
	s := storetest.New(t)
	master := bytes.Repeat([]byte{3}, 32)
	sealer, _ := keys.NewSealer(master, "totp")
	h := hub.New()
	var mu sync.Mutex
	var rt *httpapi.Runtime
	e := &env{store: s, hub: h}
	e.rt = func() *httpapi.Runtime { mu.Lock(); defer mu.Unlock(); return rt }

	api := &httpapi.API{
		Store: s, Hub: h, TOTPSealer: sealer, Sessions: &auth.Sessions{Store: s}, Runtime: e.rt,
		Setup: func(ctx context.Context, org, email, pw string) error {
			if _, err := bootstrap.Init(ctx, s, master, org, time.Now()); err != nil {
				return err
			}
			k, err := bootstrap.Load(ctx, s, master)
			if err != nil {
				return err
			}
			hash, err := auth.HashPassword(pw)
			if err != nil {
				return err
			}
			if _, err := s.CreateAdmin(ctx, k.TenantID, store.Admin{Email: email, PasswordHash: hash, Role: "owner"}); err != nil {
				return err
			}
			mu.Lock()
			rt = &httpapi.Runtime{Keys: k, Commands: &commands.Service{Store: s, Keys: k, Hub: h}}
			mu.Unlock()
			return nil
		},
	}
	e.srv = httptest.NewServer(api.Handler())
	t.Cleanup(e.srv.Close)
	return e
}

type client struct {
	t    *testing.T
	base string
	http *http.Client
	csrf string
}

func (e *env) client(t *testing.T) *client {
	jar, _ := cookiejar.New(nil)
	return &client{t: t, base: e.srv.URL, http: &http.Client{Jar: jar}}
}

// do sends JSON and decodes a JSON response into out (if non-nil).
func (c *client) do(method, path string, body, out any) int {
	c.t.Helper()
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req, _ := http.NewRequest(method, c.base+path, rd)
	req.Header.Set("Content-Type", "application/json")
	if c.csrf != "" {
		req.Header.Set("X-CSRF-Token", c.csrf)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	if out != nil {
		json.NewDecoder(resp.Body).Decode(out)
	}
	return resp.StatusCode
}

// loginFull performs password login and TOTP enrollment/verification.
// It returns the TOTP secret so later logins can reuse it.
func (c *client) loginFull(email, pw, secret string) string {
	c.t.Helper()
	var lr struct {
		CSRF        string `json:"csrf_token"`
		MFAEnrolled bool   `json:"mfa_enrolled"`
	}
	if code := c.do("POST", "/api/login", map[string]string{"email": email, "password": pw}, &lr); code != 200 {
		c.t.Fatalf("login = %d", code)
	}
	c.csrf = lr.CSRF
	if !lr.MFAEnrolled {
		var ms struct {
			Secret string `json:"secret"`
		}
		if code := c.do("POST", "/api/mfa/setup", nil, &ms); code != 200 {
			c.t.Fatalf("mfa setup = %d", code)
		}
		secret = ms.Secret
	}
	code, _ := totp.GenerateCode(secret, time.Now())
	if st := c.do("POST", "/api/mfa/verify", map[string]string{"code": code}, nil); st != 204 {
		c.t.Fatalf("mfa verify = %d", st)
	}
	return secret
}

// initialized runs setup and returns a fully logged-in owner client.
func (e *env) initialized(t *testing.T) *client {
	t.Helper()
	c := e.client(t)
	if code := c.do("POST", "/api/setup", map[string]string{"org_name": "Acme", "email": ownerEmail, "password": ownerPass}, nil); code != 201 {
		t.Fatalf("setup = %d", code)
	}
	c.loginFull(ownerEmail, ownerPass, "")
	return c
}
```

- [ ] **Step 6: Write failing authentication flow tests**

`internal/server/httpapi/authn_test.go`:
```go
package httpapi_test

import (
	"testing"
)

func TestSetupOnlyOnce(t *testing.T) {
	e := newEnv(t)
	c := e.client(t)
	var st struct{ Initialized bool }
	c.do("GET", "/api/setup/status", nil, &st)
	if st.Initialized {
		t.Fatal("fresh server must be uninitialized")
	}
	if code := c.do("POST", "/api/login", map[string]string{"email": "x@y.z", "password": "whatever-long"}, nil); code != 503 {
		t.Errorf("login before setup = %d, want 503", code)
	}
	if code := c.do("POST", "/api/setup", map[string]string{"org_name": "Acme", "email": ownerEmail, "password": "short"}, nil); code != 400 {
		t.Errorf("weak password setup = %d, want 400", code)
	}
	if code := c.do("POST", "/api/setup", map[string]string{"org_name": "Acme", "email": ownerEmail, "password": ownerPass}, nil); code != 201 {
		t.Fatalf("setup = %d", code)
	}
	if code := c.do("POST", "/api/setup", map[string]string{"org_name": "Evil", "email": "e@x.com", "password": ownerPass}, nil); code != 409 {
		t.Errorf("second setup = %d, want 409", code)
	}
}

func TestLoginRequiresPasswordThenMFA(t *testing.T) {
	e := newEnv(t)
	e.initialized(t)

	c := e.client(t)
	if code := c.do("POST", "/api/login", map[string]string{"email": ownerEmail, "password": "wrong-password-xx"}, nil); code != 401 {
		t.Errorf("bad password = %d", code)
	}
	var lr struct {
		CSRF string `json:"csrf_token"`
	}
	c.do("POST", "/api/login", map[string]string{"email": ownerEmail, "password": ownerPass}, &lr)
	c.csrf = lr.CSRF
	if code := c.do("GET", "/api/me", nil, nil); code != 403 {
		t.Errorf("/api/me before MFA = %d, want 403", code)
	}
	if code := c.do("POST", "/api/mfa/verify", map[string]string{"code": "000000"}, nil); code != 401 {
		t.Errorf("wrong TOTP = %d, want 401", code)
	}
}

func TestFullLoginMeCSRFAndLogout(t *testing.T) {
	e := newEnv(t)
	c := e.initialized(t)

	var me struct{ Email, Role string }
	if code := c.do("GET", "/api/me", nil, &me); code != 200 || me.Email != ownerEmail || me.Role != "owner" {
		t.Fatalf("/api/me = %d %+v", code, me)
	}
	good := c.csrf
	c.csrf = "forged"
	if code := c.do("POST", "/api/logout", nil, nil); code != 403 {
		t.Errorf("logout with bad CSRF = %d, want 403", code)
	}
	c.csrf = good
	if code := c.do("POST", "/api/logout", nil, nil); code != 204 {
		t.Errorf("logout = %d", code)
	}
	if code := c.do("GET", "/api/me", nil, nil); code != 401 {
		t.Errorf("/api/me after logout = %d, want 401", code)
	}
}

func TestLoginRateLimited(t *testing.T) {
	e := newEnv(t)
	e.initialized(t)
	c := e.client(t)
	codes := []int{}
	for i := 0; i < 6; i++ {
		codes = append(codes, c.do("POST", "/api/login", map[string]string{"email": ownerEmail, "password": "wrong-password-xx"}, nil))
	}
	if codes[4] != 401 || codes[5] != 429 {
		t.Errorf("codes = %v, want 5x401 then 429", codes)
	}
}
```

- [ ] **Step 7: Run — expect PASS**

Run: `go mod tidy; go test ./internal/server/httpapi/`
Expected: all pass. (bcrypt cost 12 makes each login ~250 ms; the package takes a few seconds.)

- [ ] **Step 8: Commit**

```powershell
git add internal/server/httpapi go.mod go.sum
git commit -m "feat: add console API setup, login, TOTP MFA, CSRF, and rate limiting"
```

---

### Task 13: Console API resources — devices, commands, groups, tokens, admins, audit

**Files:**
- Create: `internal/server/httpapi/routes.go`, `internal/server/httpapi/devices.go`, `internal/server/httpapi/tokens.go`, `internal/server/httpapi/admins.go`, `internal/server/httpapi/auditlog.go`
- Modify: `internal/server/httpapi/api.go` (delete the empty `routes` stub), `internal/server/store/tokens.go` (`CreateDeviceGroup` maps conflicts)
- Test: `internal/server/httpapi/resources_test.go`

**Interfaces:**
- Consumes: everything in Task 12; `agentapi.RevokedError()` (Task 9); `commands.ParseType`, `(*commands.Service).Issue` (Task 10); `tokens.Generate` (Task 4); store functions from Tasks 4, 6, 7, 10, 11.
- Produces endpoints (all JSON; readonly = any logged-in admin with MFA):

| Method & path | Role | Request | Response |
|---|---|---|---|
| `GET /api/devices?status=&group_id=` | readonly | — | `[device]` |
| `GET /api/devices/{id}` | readonly | — | `{"device": device, "uninstall_code"?: string}` (code only for admin+) |
| `POST /api/devices/{id}/revoke` | admin | — | 204 |
| `POST /api/devices/{id}/commands` | admin | `{"type": "ping"}` | 201 `{"id"}` |
| `GET /api/devices/{id}/commands?limit=` | readonly | — | `[command]` |
| `GET /api/groups` / `POST /api/groups` | readonly / admin | `{"name"}` | `[group]` / 201 `{"id"}` |
| `GET /api/tokens` | readonly | — | `[token]` (never includes the secret) |
| `POST /api/tokens` | admin | `{"name", "group_id"?, "expires_in_hours"?, "max_uses"?}` | 201 `{"id","token"}` (only time the token is shown) |
| `POST /api/tokens/{id}/revoke` | admin | — | 204 |
| `GET /api/admins` / `POST /api/admins` | owner | `{"email","password","role"}` | `[admin]` / 201 `{"id"}` |
| `POST /api/admins/{id}/disable` | owner | — | 204 (not self) |
| `GET /api/audit?limit=&before=` | readonly | — | `[audit]` newest first |

  - `device` JSON: `id, hostname, status, connected, group_id, os_build, agent_version, ip_addresses, logged_on_user, uptime_seconds, last_seen_at, cert_expires_at, enrolled_at`
  - `command` JSON: `id, type, state, result, issued_at, expires_at, completed_at`
  - Audit action names: `device.revoke`, `command.issue` (from commands.Service), `group.create`, `token.create`, `token.revoke`, `admin.create`, `admin.disable`.

- [ ] **Step 1: Make `CreateDeviceGroup` return `ErrConflict` on duplicates**

In `internal/server/store/tokens.go`, change the last line of `CreateDeviceGroup` to:
```go
	return id, conflict(err)
```

- [ ] **Step 2: Delete the stub in api.go**

Remove these lines from `internal/server/httpapi/api.go`:
```go
// routes registers resource endpoints; filled in by Task 13.
func (a *API) routes(r chi.Router) {}
```

- [ ] **Step 3: Write failing resource tests**

`internal/server/httpapi/resources_test.go`:
```go
package httpapi_test

import (
	"context"
	"testing"
	"time"

	"freelocker/internal/server/store"

	"github.com/google/uuid"
)

// fakeDevice inserts an enrolled device directly through the store.
func (e *env) fakeDevice(t *testing.T) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	k := e.rt().Keys
	id := uuid.New()
	hash := []byte("fake-" + id.String())
	if _, err := e.store.CreateInstallToken(ctx, k.TenantID, store.InstallToken{Name: "fake"}, hash); err != nil {
		t.Fatal(err)
	}
	_, err := e.store.EnrollDevice(ctx, hash, time.Now(), func(uuid.UUID) (store.NewDevice, error) {
		return store.NewDevice{ID: id, Hostname: "pc-9", CertSerial: "s", CertExpiresAt: time.Now().Add(time.Hour)}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestTokensDevicesCommandsRevokeAudit(t *testing.T) {
	e := newEnv(t)
	c := e.initialized(t)

	var grp struct{ ID string }
	if code := c.do("POST", "/api/groups", map[string]string{"name": "Laptops"}, &grp); code != 201 {
		t.Fatalf("create group = %d", code)
	}
	if code := c.do("POST", "/api/groups", map[string]string{"name": "Laptops"}, nil); code != 409 {
		t.Errorf("duplicate group = %d, want 409", code)
	}
	var tok struct{ ID, Token string }
	if code := c.do("POST", "/api/tokens", map[string]any{"name": "HQ", "group_id": grp.ID, "expires_in_hours": 24, "max_uses": 10}, &tok); code != 201 || tok.Token == "" {
		t.Fatalf("create token = %d %+v", code, tok)
	}
	var toks []map[string]any
	c.do("GET", "/api/tokens", nil, &toks)
	if len(toks) != 1 || toks[0]["name"] != "HQ" || toks[0]["token"] != nil {
		t.Errorf("token list = %+v (must not include the secret)", toks)
	}

	dev := e.fakeDevice(t)
	var devs []map[string]any
	c.do("GET", "/api/devices?status=never_seen", nil, &devs)
	if len(devs) != 1 || devs[0]["hostname"] != "pc-9" {
		t.Fatalf("devices = %+v", devs)
	}
	var detail struct {
		Device        map[string]any `json:"device"`
		UninstallCode string         `json:"uninstall_code"`
	}
	c.do("GET", "/api/devices/"+dev.String(), nil, &detail)
	if detail.UninstallCode != e.rt().Keys.UninstallCode(dev) {
		t.Errorf("uninstall code = %q", detail.UninstallCode)
	}

	if code := c.do("POST", "/api/devices/"+dev.String()+"/commands", map[string]string{"type": "format_c"}, nil); code != 400 {
		t.Errorf("bad command type = %d, want 400", code)
	}
	var cmd struct{ ID string }
	if code := c.do("POST", "/api/devices/"+dev.String()+"/commands", map[string]string{"type": "ping"}, &cmd); code != 201 {
		t.Fatalf("issue command = %d", code)
	}
	var cmds []map[string]any
	c.do("GET", "/api/devices/"+dev.String()+"/commands", nil, &cmds)
	if len(cmds) != 1 || cmds[0]["id"] != cmd.ID || cmds[0]["state"] != "pending" {
		t.Errorf("commands = %+v", cmds)
	}

	if code := c.do("POST", "/api/devices/"+dev.String()+"/revoke", nil, nil); code != 204 {
		t.Fatalf("revoke = %d", code)
	}
	c.do("GET", "/api/devices/"+dev.String(), nil, &detail)
	if detail.Device["status"] != "revoked" {
		t.Errorf("status after revoke = %v", detail.Device["status"])
	}
	if code := c.do("POST", "/api/devices/"+dev.String()+"/commands", map[string]string{"type": "ping"}, nil); code != 409 {
		t.Errorf("command to revoked device = %d, want 409", code)
	}
	if code := c.do("GET", "/api/devices/"+uuid.NewString(), nil, nil); code != 404 {
		t.Errorf("unknown device = %d, want 404", code)
	}

	var audit []struct{ Action string }
	c.do("GET", "/api/audit?limit=50", nil, &audit)
	seen := map[string]bool{}
	for _, a := range audit {
		seen[a.Action] = true
	}
	for _, want := range []string{"group.create", "token.create", "command.issue", "device.revoke", "admin.login"} {
		if !seen[want] {
			t.Errorf("audit missing %s (have %v)", want, seen)
		}
	}
}

func TestRolesAndAdminManagement(t *testing.T) {
	e := newEnv(t)
	owner := e.initialized(t)

	var created struct{ ID string }
	body := map[string]string{"email": "ro@example.com", "password": "readonly-password-1", "role": "readonly"}
	if code := owner.do("POST", "/api/admins", body, &created); code != 201 {
		t.Fatalf("create admin = %d", code)
	}
	if code := owner.do("POST", "/api/admins", body, nil); code != 409 {
		t.Errorf("duplicate admin = %d, want 409", code)
	}
	if code := owner.do("POST", "/api/admins", map[string]string{"email": "x@example.com", "password": "some-password-12", "role": "god"}, nil); code != 400 {
		t.Errorf("bad role = %d, want 400", code)
	}

	dev := e.fakeDevice(t)
	ro := e.client(t)
	ro.loginFull("ro@example.com", "readonly-password-1", "")
	if code := ro.do("GET", "/api/devices", nil, nil); code != 200 {
		t.Errorf("readonly list devices = %d", code)
	}
	var detail map[string]any
	ro.do("GET", "/api/devices/"+dev.String(), nil, &detail)
	if _, ok := detail["uninstall_code"]; ok {
		t.Error("readonly must not see uninstall code")
	}
	for _, path := range []string{"/api/tokens", "/api/groups", "/api/devices/" + dev.String() + "/revoke"} {
		if code := ro.do("POST", path, map[string]string{"name": "x"}, nil); code != 403 {
			t.Errorf("readonly POST %s = %d, want 403", path, code)
		}
	}
	if code := ro.do("GET", "/api/admins", nil, nil); code != 403 {
		t.Errorf("readonly list admins = %d, want 403", code)
	}

	var me struct{ ID string }
	owner.do("GET", "/api/me", nil, &me)
	if code := owner.do("POST", "/api/admins/"+me.ID+"/disable", nil, nil); code != 400 {
		t.Errorf("self-disable = %d, want 400", code)
	}
	if code := owner.do("POST", "/api/admins/"+created.ID+"/disable", nil, nil); code != 204 {
		t.Fatalf("disable = %d", code)
	}
	if code := ro.do("GET", "/api/me", nil, nil); code != 401 {
		t.Errorf("disabled admin /api/me = %d, want 401", code)
	}
}
```

- [ ] **Step 4: Run — expect FAIL** (routes return 404/405)

Run: `go test ./internal/server/httpapi/ -run 'TestTokens|TestRoles'`

- [ ] **Step 5: Implement routes and shared helpers**

`internal/server/httpapi/routes.go`:
```go
package httpapi

import (
	"errors"
	"net/http"
	"strconv"

	"freelocker/internal/server/store"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

func (a *API) routes(r chi.Router) {
	r.Get("/api/devices", a.listDevices)
	r.Get("/api/devices/{id}", a.getDevice)
	r.Get("/api/devices/{id}/commands", a.listDeviceCommands)
	r.Get("/api/groups", a.listGroups)
	r.Get("/api/tokens", a.listTokens)
	r.Get("/api/audit", a.listAudit)

	r.Group(func(r chi.Router) {
		r.Use(a.requireRole("admin"))
		r.Post("/api/devices/{id}/revoke", a.revokeDevice)
		r.Post("/api/devices/{id}/commands", a.issueCommand)
		r.Post("/api/groups", a.createGroup)
		r.Post("/api/tokens", a.createToken)
		r.Post("/api/tokens/{id}/revoke", a.revokeToken)
	})

	r.Group(func(r chi.Router) {
		r.Use(a.requireRole("owner"))
		r.Get("/api/admins", a.listAdmins)
		r.Post("/api/admins", a.createAdmin)
		r.Post("/api/admins/{id}/disable", a.disableAdmin)
	})
}

func pathID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return uuid.Nil, false
	}
	return id, true
}

// queryInt parses an optional positive integer, clamped to [1, max].
func queryInt(r *http.Request, name string, def, max int) int {
	n, err := strconv.Atoi(r.URL.Query().Get(name))
	if err != nil || n < 1 {
		return def
	}
	return min(n, max)
}

func (a *API) storeErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeErr(w, http.StatusNotFound, "not found")
	case errors.Is(err, store.ErrConflict):
		writeErr(w, http.StatusConflict, "already exists")
	default:
		a.Log.Error("store error", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal error")
	}
}
```

- [ ] **Step 6: Implement device and command endpoints**

`internal/server/httpapi/devices.go`:
```go
package httpapi

import (
	"net/http"
	"time"

	"freelocker/internal/server/agentapi"
	"freelocker/internal/server/auth"
	"freelocker/internal/server/commands"
	"freelocker/internal/server/store"

	"github.com/google/uuid"
)

type deviceJSON struct {
	ID            string     `json:"id"`
	Hostname      string     `json:"hostname"`
	Status        string     `json:"status"`
	Connected     bool       `json:"connected"`
	GroupID       *uuid.UUID `json:"group_id"`
	OSBuild       string     `json:"os_build"`
	AgentVersion  string     `json:"agent_version"`
	IPAddresses   []string   `json:"ip_addresses"`
	LoggedOnUser  string     `json:"logged_on_user"`
	UptimeSeconds int64      `json:"uptime_seconds"`
	LastSeenAt    *time.Time `json:"last_seen_at"`
	CertExpiresAt time.Time  `json:"cert_expires_at"`
	EnrolledAt    time.Time  `json:"enrolled_at"`
}

func (a *API) toDeviceJSON(d store.Device, now time.Time) deviceJSON {
	return deviceJSON{
		ID: d.ID.String(), Hostname: d.Hostname, Status: d.Status(now), Connected: a.Hub.Connected(d.ID),
		GroupID: d.GroupID, OSBuild: d.OSBuild, AgentVersion: d.AgentVersion, IPAddresses: d.IPs,
		LoggedOnUser: d.LoggedOnUser, UptimeSeconds: d.UptimeSeconds, LastSeenAt: d.LastSeenAt,
		CertExpiresAt: d.CertExpiresAt, EnrolledAt: d.EnrolledAt,
	}
}

func (a *API) listDevices(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r)
	devs, err := a.Store.ListDevices(r.Context(), p.TenantID)
	if err != nil {
		a.storeErr(w, err)
		return
	}
	wantStatus := r.URL.Query().Get("status")
	wantGroup := r.URL.Query().Get("group_id")
	now := a.now()
	out := []deviceJSON{}
	for _, d := range devs {
		dj := a.toDeviceJSON(d, now)
		if wantStatus != "" && dj.Status != wantStatus {
			continue
		}
		if wantGroup != "" && (d.GroupID == nil || d.GroupID.String() != wantGroup) {
			continue
		}
		out = append(out, dj)
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *API) getDevice(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	p := principalFrom(r)
	d, err := a.Store.GetDevice(r.Context(), p.TenantID, id)
	if err != nil {
		a.storeErr(w, err)
		return
	}
	resp := map[string]any{"device": a.toDeviceJSON(d, a.now())}
	if auth.Allows(p.Admin.Role, "admin") {
		resp["uninstall_code"] = a.Runtime().Keys.UninstallCode(id)
	}
	writeJSON(w, http.StatusOK, resp)
}

func (a *API) revokeDevice(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	p := principalFrom(r)
	if err := a.Store.RevokeDevice(r.Context(), p.TenantID, id); err != nil {
		a.storeErr(w, err)
		return
	}
	a.Hub.Disconnect(id, agentapi.RevokedError())
	a.audit(r, p, "device.revoke", "device", id.String(), nil, "success")
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) issueCommand(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var req struct {
		Type string `json:"type"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	typ, err := commands.ParseType(req.Type)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	p := principalFrom(r)
	d, err := a.Store.GetDevice(r.Context(), p.TenantID, id)
	if err != nil {
		a.storeErr(w, err)
		return
	}
	if d.Revoked {
		writeErr(w, http.StatusConflict, "device revoked")
		return
	}
	cmdID, err := a.Runtime().Commands.Issue(r.Context(), p.TenantID, id, typ, nil, &p.Admin.ID, "admin:"+p.Admin.Email)
	if err != nil {
		a.storeErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"id": cmdID.String()})
}

type commandJSON struct {
	ID          string     `json:"id"`
	Type        string     `json:"type"`
	State       string     `json:"state"`
	Result      string     `json:"result"`
	IssuedAt    time.Time  `json:"issued_at"`
	ExpiresAt   time.Time  `json:"expires_at"`
	CompletedAt *time.Time `json:"completed_at"`
}

func (a *API) listDeviceCommands(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	p := principalFrom(r)
	cmds, err := a.Store.ListDeviceCommands(r.Context(), p.TenantID, id, queryInt(r, "limit", 50, 500))
	if err != nil {
		a.storeErr(w, err)
		return
	}
	out := make([]commandJSON, 0, len(cmds))
	for _, c := range cmds {
		out = append(out, commandJSON{ID: c.ID.String(), Type: c.Type, State: c.State, Result: c.Result,
			IssuedAt: c.IssuedAt, ExpiresAt: c.ExpiresAt, CompletedAt: c.CompletedAt})
	}
	writeJSON(w, http.StatusOK, out)
}
```

- [ ] **Step 7: Implement group and token endpoints**

`internal/server/httpapi/tokens.go`:
```go
package httpapi

import (
	"net/http"
	"strings"
	"time"

	"freelocker/internal/server/store"
	"freelocker/internal/server/tokens"

	"github.com/google/uuid"
)

func (a *API) listGroups(w http.ResponseWriter, r *http.Request) {
	groups, err := a.Store.ListDeviceGroups(r.Context(), principalFrom(r).TenantID)
	if err != nil {
		a.storeErr(w, err)
		return
	}
	out := make([]map[string]string, 0, len(groups))
	for _, g := range groups {
		out = append(out, map[string]string{"id": g.ID.String(), "name": g.Name})
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *API) createGroup(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		writeErr(w, http.StatusBadRequest, "name is required")
		return
	}
	p := principalFrom(r)
	id, err := a.Store.CreateDeviceGroup(r.Context(), p.TenantID, name)
	if err != nil {
		a.storeErr(w, err)
		return
	}
	a.audit(r, p, "group.create", "group", id.String(), map[string]any{"name": name}, "success")
	writeJSON(w, http.StatusCreated, map[string]string{"id": id.String()})
}

type tokenJSON struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	GroupID   *uuid.UUID `json:"group_id"`
	ExpiresAt *time.Time `json:"expires_at"`
	MaxUses   *int       `json:"max_uses"`
	Uses      int        `json:"uses"`
	Revoked   bool       `json:"revoked"`
	CreatedAt time.Time  `json:"created_at"`
}

func (a *API) listTokens(w http.ResponseWriter, r *http.Request) {
	toks, err := a.Store.ListInstallTokens(r.Context(), principalFrom(r).TenantID)
	if err != nil {
		a.storeErr(w, err)
		return
	}
	out := make([]tokenJSON, 0, len(toks))
	for _, t := range toks {
		out = append(out, tokenJSON{ID: t.ID.String(), Name: t.Name, GroupID: t.GroupID, ExpiresAt: t.ExpiresAt,
			MaxUses: t.MaxUses, Uses: t.Uses, Revoked: t.Revoked, CreatedAt: t.CreatedAt})
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *API) createToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name           string     `json:"name"`
		GroupID        *uuid.UUID `json:"group_id"`
		ExpiresInHours *int       `json:"expires_in_hours"`
		MaxUses        *int       `json:"max_uses"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" || (req.ExpiresInHours != nil && *req.ExpiresInHours < 1) || (req.MaxUses != nil && *req.MaxUses < 1) {
		writeErr(w, http.StatusBadRequest, "name is required; expires_in_hours and max_uses must be positive when set")
		return
	}
	p := principalFrom(r)
	if req.GroupID != nil && !a.groupExists(r, p, *req.GroupID) {
		writeErr(w, http.StatusBadRequest, "unknown group_id")
		return
	}
	full, hash, err := tokens.Generate(a.Runtime().Keys.CA.Pin())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not generate token")
		return
	}
	t := store.InstallToken{Name: req.Name, GroupID: req.GroupID, MaxUses: req.MaxUses, CreatedBy: &p.Admin.ID}
	if req.ExpiresInHours != nil {
		exp := a.now().Add(time.Duration(*req.ExpiresInHours) * time.Hour)
		t.ExpiresAt = &exp
	}
	id, err := a.Store.CreateInstallToken(r.Context(), p.TenantID, t, hash)
	if err != nil {
		a.storeErr(w, err)
		return
	}
	a.audit(r, p, "token.create", "token", id.String(), map[string]any{"name": req.Name}, "success")
	writeJSON(w, http.StatusCreated, map[string]string{"id": id.String(), "token": full})
}

func (a *API) groupExists(r *http.Request, p principal, id uuid.UUID) bool {
	groups, err := a.Store.ListDeviceGroups(r.Context(), p.TenantID)
	if err != nil {
		return false
	}
	for _, g := range groups {
		if g.ID == id {
			return true
		}
	}
	return false
}

func (a *API) revokeToken(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	p := principalFrom(r)
	if err := a.Store.RevokeInstallToken(r.Context(), p.TenantID, id); err != nil {
		a.storeErr(w, err)
		return
	}
	a.audit(r, p, "token.revoke", "token", id.String(), nil, "success")
	w.WriteHeader(http.StatusNoContent)
}
```

- [ ] **Step 8: Implement admin and audit endpoints**

`internal/server/httpapi/admins.go`:
```go
package httpapi

import (
	"net/http"
	"slices"
	"strings"
	"time"

	"freelocker/internal/server/auth"
	"freelocker/internal/server/store"
)

type adminJSON struct {
	ID          string    `json:"id"`
	Email       string    `json:"email"`
	Role        string    `json:"role"`
	Disabled    bool      `json:"disabled"`
	MFAEnrolled bool      `json:"mfa_enrolled"`
	CreatedAt   time.Time `json:"created_at"`
}

func (a *API) listAdmins(w http.ResponseWriter, r *http.Request) {
	admins, err := a.Store.ListAdmins(r.Context(), principalFrom(r).TenantID)
	if err != nil {
		a.storeErr(w, err)
		return
	}
	out := make([]adminJSON, 0, len(admins))
	for _, ad := range admins {
		out = append(out, adminJSON{ID: ad.ID.String(), Email: ad.Email, Role: ad.Role, Disabled: ad.Disabled,
			MFAEnrolled: ad.TOTPConfirmed, CreatedAt: ad.CreatedAt})
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *API) createAdmin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))
	if !strings.Contains(req.Email, "@") || !slices.Contains(auth.Roles, req.Role) {
		writeErr(w, http.StatusBadRequest, "a valid email and role (owner, admin, readonly) are required")
		return
	}
	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	p := principalFrom(r)
	id, err := a.Store.CreateAdmin(r.Context(), p.TenantID, store.Admin{Email: req.Email, PasswordHash: hash, Role: req.Role})
	if err != nil {
		a.storeErr(w, err)
		return
	}
	a.audit(r, p, "admin.create", "admin", id.String(), map[string]any{"email": req.Email, "role": req.Role}, "success")
	writeJSON(w, http.StatusCreated, map[string]string{"id": id.String()})
}

func (a *API) disableAdmin(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	p := principalFrom(r)
	if id == p.Admin.ID {
		writeErr(w, http.StatusBadRequest, "cannot disable yourself")
		return
	}
	if err := a.Store.SetAdminDisabled(r.Context(), p.TenantID, id, true); err != nil {
		a.storeErr(w, err)
		return
	}
	if err := a.Store.DeleteAdminSessions(r.Context(), p.TenantID, id); err != nil {
		a.storeErr(w, err)
		return
	}
	a.audit(r, p, "admin.disable", "admin", id.String(), nil, "success")
	w.WriteHeader(http.StatusNoContent)
}
```

`internal/server/httpapi/auditlog.go`:
```go
package httpapi

import (
	"net/http"
	"strconv"
	"time"
)

type auditJSON struct {
	ID         int64          `json:"id"`
	Actor      string         `json:"actor"`
	Action     string         `json:"action"`
	TargetType string         `json:"target_type"`
	TargetID   string         `json:"target_id"`
	Detail     map[string]any `json:"detail"`
	IP         string         `json:"ip"`
	Result     string         `json:"result"`
	CreatedAt  time.Time      `json:"created_at"`
}

func (a *API) listAudit(w http.ResponseWriter, r *http.Request) {
	before, _ := strconv.ParseInt(r.URL.Query().Get("before"), 10, 64)
	entries, err := a.Store.ListAudit(r.Context(), principalFrom(r).TenantID, queryInt(r, "limit", 100, 500), before)
	if err != nil {
		a.storeErr(w, err)
		return
	}
	out := make([]auditJSON, 0, len(entries))
	for _, e := range entries {
		out = append(out, auditJSON{ID: e.ID, Actor: e.Actor, Action: e.Action, TargetType: e.TargetType,
			TargetID: e.TargetID, Detail: e.Detail, IP: e.IP, Result: e.Result, CreatedAt: e.CreatedAt})
	}
	writeJSON(w, http.StatusOK, out)
}
```

- [ ] **Step 9: Run — expect PASS**

Run: `go test ./internal/server/...`

- [ ] **Step 10: Commit**

```powershell
git add internal/server/httpapi internal/server/store
git commit -m "feat: add console API for devices, commands, tokens, groups, admins, and audit"
```

---

### Task 14: App wiring, `freelocker-server` CLI, and Docker packaging

**Files:**
- Create: `internal/server/app/app.go`, `cmd/server/main.go`, `deploy/Dockerfile`, `deploy/docker-compose.yml`, `deploy/server.example.yaml`, `.dockerignore`
- Modify: `internal/server/config/config.go` (add `InsecureCookies`)
- Test: `internal/server/app/app_test.go`

**Interfaces:**
- Consumes: all previous tasks.
- Produces:
  - `config.Config.InsecureCookies bool` (`yaml:"insecure_cookies"`, env `FREELOCKER_INSECURE_COOKIES=true`)
  - `app.New(ctx, cfg config.Config, log *slog.Logger) (*app.App, error)` — opens + migrates DB, loads/creates master secret; the App owns and closes the store.
  - `app.NewWithStore(cfg config.Config, s *store.Store, master []byte, log *slog.Logger) (*app.App, error)` — caller owns the store (tests).
  - `(*App).Initialize(ctx, org, email, password string) (*bootstrap.Keys, error)` — first-run setup without starting listeners; writes audit `setup.complete`.
  - `(*App).CreateAdmin(ctx, email, password, role string) error` — CLI recovery path; audit `admin.create` with actor `system`.
  - `(*App).Handler() http.Handler`; `(*App).AgentAddr() string` ("" until the agent API is listening)
  - `(*App).Run(ctx) error` — activates the agent API if initialized, serves the console API, expires stale commands every minute, and returns on ctx cancel.
  - `(*App).Close()` — stops the agent API; closes the store if owned.
  - CLI: `freelocker-server [serve|init|create-admin] -config path -org -email -password -role`; the password may come from env `FREELOCKER_ADMIN_PASSWORD`.

- [ ] **Step 1: Add `InsecureCookies` to config**

In `internal/server/config/config.go` add the field to `Config`:
```go
	InsecureCookies  bool     `yaml:"insecure_cookies"`
```
and in `Load`, after the other env overrides:
```go
	if os.Getenv("FREELOCKER_INSECURE_COOKIES") == "true" {
		c.InsecureCookies = true
	}
```

- [ ] **Step 2: Write failing app test**

`internal/server/app/app_test.go`:
```go
package app

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"freelocker/internal/server/config"
	"freelocker/internal/server/store/storetest"
)

func testConfig() config.Config {
	return config.Config{AgentListen: "127.0.0.1:0", ConsoleListen: "127.0.0.1:0",
		PublicHostnames: []string{"127.0.0.1"}, InsecureCookies: true}
}

func TestSetupActivatesAgentAPIAndRunReactivates(t *testing.T) {
	s := storetest.New(t)
	master := bytes.Repeat([]byte{4}, 32)

	a, err := NewWithStore(testConfig(), s, master, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	if a.AgentAddr() != "" {
		t.Fatal("agent API must not listen before setup")
	}
	srv := httptest.NewServer(a.Handler())
	defer srv.Close()
	resp, err := http.Post(srv.URL+"/api/setup", "application/json",
		strings.NewReader(`{"org_name":"Acme","email":"o@example.com","password":"owner-password-123"}`))
	if err != nil || resp.StatusCode != 201 {
		t.Fatalf("setup = %v %v", resp.StatusCode, err)
	}
	if a.AgentAddr() == "" {
		t.Fatal("agent API should listen after setup")
	}
	a.Close()

	// A restarted server with the same DB + master secret activates in Run.
	b, err := NewWithStore(testConfig(), s, master, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Close)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- b.Run(ctx) }()
	deadline := time.Now().Add(5 * time.Second)
	for b.AgentAddr() == "" && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if b.AgentAddr() == "" {
		t.Fatal("Run did not activate the agent API")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run returned %v", err)
	}
}

func TestInitializeValidatesInput(t *testing.T) {
	a, _ := NewWithStore(testConfig(), storetest.New(t), bytes.Repeat([]byte{4}, 32), slog.Default())
	t.Cleanup(a.Close)
	if _, err := a.Initialize(context.Background(), "", "o@example.com", "owner-password-123"); err == nil {
		t.Error("empty org must fail")
	}
	if _, err := a.Initialize(context.Background(), "Acme", "o@example.com", "short"); err == nil {
		t.Error("short password must fail")
	}
	if _, err := a.Initialize(context.Background(), "Acme", "o@example.com", "owner-password-123"); err != nil {
		t.Fatal(err)
	}
	if err := a.CreateAdmin(context.Background(), "r@example.com", "recovery-password-1", "owner"); err != nil {
		t.Fatal(err)
	}
	if err := a.CreateAdmin(context.Background(), "x@example.com", "recovery-password-1", "god"); err == nil {
		t.Error("bad role must fail")
	}
}
```

- [ ] **Step 3: Run — expect FAIL**

Run: `go test ./internal/server/app/`

- [ ] **Step 4: Implement the app**

`internal/server/app/app.go`:
```go
// Package app wires the server components together and owns their
// lifecycle.
package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"freelocker/internal/server/agentapi"
	"freelocker/internal/server/auth"
	"freelocker/internal/server/bootstrap"
	"freelocker/internal/server/commands"
	"freelocker/internal/server/config"
	"freelocker/internal/server/httpapi"
	"freelocker/internal/server/hub"
	"freelocker/internal/server/keys"
	"freelocker/internal/server/store"

	"google.golang.org/grpc"
)

type App struct {
	cfg       config.Config
	store     *store.Store
	ownsStore bool
	master    []byte
	log       *slog.Logger
	hub       *hub.Hub
	handler   http.Handler

	setupMu   sync.Mutex
	mu        sync.Mutex
	rt        *httpapi.Runtime
	agentSrv  *grpc.Server
	agentAddr net.Addr
}

func New(ctx context.Context, cfg config.Config, log *slog.Logger) (*App, error) {
	s, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return nil, err
	}
	if err := s.Migrate(ctx); err != nil {
		s.Close()
		return nil, err
	}
	master, err := keys.LoadOrCreateMasterSecret(cfg.MasterSecretFile)
	if err != nil {
		s.Close()
		return nil, err
	}
	a, err := NewWithStore(cfg, s, master, log)
	if err != nil {
		s.Close()
		return nil, err
	}
	a.ownsStore = true
	return a, nil
}

func NewWithStore(cfg config.Config, s *store.Store, master []byte, log *slog.Logger) (*App, error) {
	totpSealer, err := keys.NewSealer(master, "totp")
	if err != nil {
		return nil, err
	}
	a := &App{cfg: cfg, store: s, master: master, log: log, hub: hub.New()}
	api := &httpapi.API{
		Store: s, Runtime: a.runtime, Setup: a.setup, Hub: a.hub, TOTPSealer: totpSealer,
		Sessions: &auth.Sessions{Store: s, Secure: !cfg.InsecureCookies}, Log: log,
	}
	a.handler = api.Handler()
	return a, nil
}

func (a *App) runtime() *httpapi.Runtime {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.rt
}

func (a *App) Handler() http.Handler { return a.handler }

func (a *App) AgentAddr() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.agentAddr == nil {
		return ""
	}
	return a.agentAddr.String()
}

func (a *App) Initialize(ctx context.Context, org, email, password string) (*bootstrap.Keys, error) {
	if strings.TrimSpace(org) == "" || !strings.Contains(email, "@") {
		return nil, errors.New("organization name and a valid email are required")
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		return nil, err
	}
	if _, err := bootstrap.Init(ctx, a.store, a.master, org, time.Now()); err != nil {
		return nil, err
	}
	k, err := bootstrap.Load(ctx, a.store, a.master)
	if err != nil {
		return nil, err
	}
	if _, err := a.store.CreateAdmin(ctx, k.TenantID, store.Admin{Email: email, PasswordHash: hash, Role: "owner"}); err != nil {
		return nil, err
	}
	if err := a.store.AppendAudit(ctx, k.TenantID, store.AuditEntry{
		Actor: "system", Action: "setup.complete", Detail: map[string]any{"org": org, "owner": email}, Result: "success",
	}); err != nil {
		a.log.Error("audit write failed", "err", err)
	}
	return k, nil
}

func (a *App) CreateAdmin(ctx context.Context, email, password, role string) error {
	if !slices.Contains(auth.Roles, role) {
		return fmt.Errorf("role must be one of %v", auth.Roles)
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		return err
	}
	tenant, err := a.store.FirstTenant(ctx)
	if err != nil {
		return fmt.Errorf("server not initialized: %w", err)
	}
	id, err := a.store.CreateAdmin(ctx, tenant, store.Admin{Email: email, PasswordHash: hash, Role: role})
	if err != nil {
		return err
	}
	return a.store.AppendAudit(ctx, tenant, store.AuditEntry{
		Actor: "system", Action: "admin.create", TargetType: "admin", TargetID: id.String(),
		Detail: map[string]any{"email": email, "role": role, "via": "cli"}, Result: "success",
	})
}

func (a *App) setup(ctx context.Context, org, email, password string) error {
	a.setupMu.Lock()
	defer a.setupMu.Unlock()
	k, err := a.Initialize(ctx, org, email, password)
	if err != nil {
		return err
	}
	return a.activate(k)
}

func (a *App) activate(k *bootstrap.Keys) error {
	cmds := &commands.Service{Store: a.store, Keys: k, Hub: a.hub, Log: a.log}
	tlsCfg, err := agentapi.TLSConfig(k, a.cfg.PublicHostnames, time.Now())
	if err != nil {
		return err
	}
	lis, err := net.Listen("tcp", a.cfg.AgentListen)
	if err != nil {
		return fmt.Errorf("agent listener: %w", err)
	}
	srv := agentapi.NewGRPCServer(agentapi.Deps{Store: a.store, Keys: k, Hub: a.hub, Commands: cmds, Log: a.log}, tlsCfg)
	go func() {
		if err := srv.Serve(lis); err != nil {
			a.log.Error("agent API stopped", "err", err)
		}
	}()
	a.mu.Lock()
	a.rt = &httpapi.Runtime{Keys: k, Commands: cmds}
	a.agentSrv, a.agentAddr = srv, lis.Addr()
	a.mu.Unlock()
	a.log.Info("agent API listening", "addr", lis.Addr().String(), "ca_pin", k.CA.Pin())
	return nil
}

func (a *App) Run(ctx context.Context) error {
	k, err := bootstrap.Load(ctx, a.store, a.master)
	switch {
	case err == nil:
		if err := a.activate(k); err != nil {
			return err
		}
	case errors.Is(err, store.ErrNotFound):
		a.log.Warn("server not initialized; complete setup in the console or run `freelocker-server init`")
	default:
		return err
	}

	httpSrv := &http.Server{Addr: a.cfg.ConsoleListen, Handler: a.handler, ReadHeaderTimeout: 10 * time.Second}
	errc := make(chan error, 1)
	go func() {
		var err error
		if a.cfg.ConsoleTLSCert != "" {
			err = httpSrv.ListenAndServeTLS(a.cfg.ConsoleTLSCert, a.cfg.ConsoleTLSKey)
		} else {
			err = httpSrv.ListenAndServe()
		}
		if !errors.Is(err, http.ErrServerClosed) {
			errc <- err
		}
	}()
	a.log.Info("console API listening", "addr", a.cfg.ConsoleListen, "tls", a.cfg.ConsoleTLSCert != "")

	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			return httpSrv.Shutdown(shutdownCtx)
		case err := <-errc:
			return err
		case <-ticker.C:
			if rt := a.runtime(); rt != nil {
				if n, err := rt.Commands.ExpireStale(ctx); err != nil {
					a.log.Error("expire commands", "err", err)
				} else if n > 0 {
					a.log.Info("expired stale commands", "count", n)
				}
			}
		}
	}
}

// Close stops the agent API (long-lived streams are cut, agents
// reconnect to the next instance) and closes the store if owned.
func (a *App) Close() {
	a.mu.Lock()
	srv := a.agentSrv
	a.agentSrv, a.agentAddr = nil, nil
	a.mu.Unlock()
	if srv != nil {
		srv.Stop()
	}
	if a.ownsStore {
		a.store.Close()
	}
}
```

- [ ] **Step 5: Run app tests — expect PASS**

Run: `go test ./internal/server/app/`

- [ ] **Step 6: Implement the CLI**

`cmd/server/main.go`:
```go
// Command freelocker-server runs the FreeLocker management server.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"freelocker/internal/server/app"
	"freelocker/internal/server/config"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if err := run(os.Args[1:], log); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(args []string, log *slog.Logger) error {
	cmd := "serve"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	configPath := fs.String("config", "", "path to server YAML config")
	org := fs.String("org", "", "organization name (init)")
	email := fs.String("email", "", "admin email (init, create-admin)")
	password := fs.String("password", "", "admin password (init, create-admin); prefer env FREELOCKER_ADMIN_PASSWORD")
	role := fs.String("role", "admin", "role for create-admin: owner, admin, readonly")
	fs.Parse(args)
	if *password == "" {
		*password = os.Getenv("FREELOCKER_ADMIN_PASSWORD")
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	a, err := app.New(ctx, cfg, log)
	if err != nil {
		return err
	}
	defer a.Close()

	switch cmd {
	case "serve":
		return a.Run(ctx)
	case "init":
		k, err := a.Initialize(ctx, *org, *email, *password)
		if err != nil {
			return err
		}
		fmt.Printf("Initialized %q. CA pin: %s\n", *org, k.CA.Pin())
		return nil
	case "create-admin":
		return a.CreateAdmin(ctx, *email, *password, *role)
	default:
		return fmt.Errorf("unknown command %q (want serve, init, or create-admin)", cmd)
	}
}
```

Run: `go build -o bin/freelocker-server.exe ./cmd/server`
Expected: builds with no errors.

- [ ] **Step 7: Smoke-test the binary against the dev database**

```powershell
$env:FREELOCKER_DATABASE_URL = "postgres://freelocker:freelocker@localhost:55432/freelocker?sslmode=disable"
$env:FREELOCKER_MASTER_SECRET_FILE = "$env:TEMP\fl-master.key"
$env:FREELOCKER_INSECURE_COOKIES = "true"
$p = Start-Process -PassThru -NoNewWindow .\bin\freelocker-server.exe serve
Start-Sleep 2
Invoke-RestMethod http://localhost:8080/api/setup/status
Stop-Process $p.Id
```
Expected: `initialized : False` (or `True` if the dev DB's `public` schema was initialized before). Tests use per-test schemas, so they do not affect this.

- [ ] **Step 8: Docker packaging**

`.dockerignore`:
```
bin/
web/node_modules/
.git/
docs/
```

`deploy/Dockerfile`:
```dockerfile
FROM golang:1.27 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/freelocker-server ./cmd/server && mkdir -p /out/data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/freelocker-server /freelocker-server
COPY --from=build --chown=65532:65532 /out/data /data
ENV FREELOCKER_MASTER_SECRET_FILE=/data/master.key
VOLUME /data
EXPOSE 8080 8443
ENTRYPOINT ["/freelocker-server"]
CMD ["serve"]
```

`deploy/docker-compose.yml`:
```yaml
# Local (on-prem) install: server + Postgres.
#   docker compose -f deploy/docker-compose.yml up -d --build
# Then open http://localhost:8080 (console UI arrives in plan 1c; until then use the API).
# Set FREELOCKER_PUBLIC_HOSTNAMES to the DNS name/IP agents will use to reach this host.
# BACK UP the serverdata volume: it holds master.key, without which the CA and signing keys cannot be decrypted.
services:
  postgres:
    image: postgres:17
    environment:
      POSTGRES_USER: freelocker
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:-change-me}
      POSTGRES_DB: freelocker
    volumes:
      - pgdata:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U freelocker"]
      interval: 5s
      retries: 10

  server:
    build:
      context: ..
      dockerfile: deploy/Dockerfile
    depends_on:
      postgres:
        condition: service_healthy
    environment:
      FREELOCKER_DATABASE_URL: postgres://freelocker:${POSTGRES_PASSWORD:-change-me}@postgres:5432/freelocker?sslmode=disable
      FREELOCKER_PUBLIC_HOSTNAMES: ${FREELOCKER_PUBLIC_HOSTNAMES:-localhost}
      FREELOCKER_INSECURE_COOKIES: ${FREELOCKER_INSECURE_COOKIES:-false}
    ports:
      - "8080:8080"
      - "8443:8443"
    volumes:
      - serverdata:/data

volumes:
  pgdata:
  serverdata:
```

`deploy/server.example.yaml`:
```yaml
# Copy to server.yaml and run: freelocker-server serve -config server.yaml
# Every key can be overridden by an env var: FREELOCKER_<UPPER_SNAKE_KEY>.
database_url: postgres://freelocker:change-me@localhost:5432/freelocker?sslmode=disable
agent_listen: ":8443"          # gRPC for agents (mTLS). Behind a load balancer this must be TLS passthrough.
console_listen: ":8080"        # REST API for the console
public_hostnames: [localhost]  # names/IPs agents use to reach agent_listen (go into the server cert)
master_secret_file: master.key # created on first run; back it up, keep it out of the database backup
console_tls_cert: ""           # optional PEM cert/key for the console; leave empty behind a TLS proxy
console_tls_key: ""
insecure_cookies: false        # true only for plain-HTTP access to a non-localhost address (testing)
```

- [ ] **Step 9: Verify the container build**

Run:
```powershell
docker compose -f deploy/docker-compose.yml up -d --build
Start-Sleep 5
Invoke-RestMethod http://localhost:8080/api/setup/status
docker compose -f deploy/docker-compose.yml down
```
Expected: `initialized : False`.

- [ ] **Step 10: Commit**

```powershell
git add internal/server/app internal/server/config cmd/server deploy .dockerignore
git commit -m "feat: add server app wiring, CLI, and Docker packaging"
```

---

### Task 15: agent-sim tool and end-to-end integration test

**Files:**
- Create: `internal/sim/backoff.go`, `internal/sim/runner.go`, `cmd/agent-sim/main.go`, `test/integration/flow_test.go`
- Test: `internal/sim/backoff_test.go`, `test/integration/flow_test.go`

**Interfaces:**
- Consumes: `sim.Enroll`, `sim.Connect`, `Session` (Tasks 8–9); `commands.Verify`, `commands.TypeName` (Task 10); `app.NewWithStore`, `(*App).Handler`, `(*App).AgentAddr` (Task 14).
- Produces:
  - `sim.Backoff(attempt int, rnd func() float64) time.Duration` — 1 s doubling up to a 5 min cap, with equal jitter (result in `[d/2, d]`).
  - `sim.Runner{Addr string; Identity *sim.Identity; Hostname string; Interval time.Duration; Log *slog.Logger}` and `(*Runner).Run(ctx) error` — heartbeats, auto-acknowledges verified commands, reconnects with backoff, stops (returns the error) on `Unauthenticated` so revoked devices do not hammer the server; returns nil on ctx cancel after sending Goodbye.
  - CLI: `agent-sim -server host:8443 -token <token> -count N -interval 30s -state sim-state.json`

- [ ] **Step 1: Write failing backoff test**

`internal/sim/backoff_test.go`:
```go
package sim

import (
	"testing"
	"time"
)

func TestBackoff(t *testing.T) {
	lo := func() float64 { return 0 }
	hi := func() float64 { return 1 }
	if d := Backoff(0, lo); d != 500*time.Millisecond {
		t.Errorf("attempt 0 low = %v", d)
	}
	if d := Backoff(0, hi); d != time.Second {
		t.Errorf("attempt 0 high = %v", d)
	}
	if d := Backoff(3, hi); d != 8*time.Second {
		t.Errorf("attempt 3 high = %v", d)
	}
	if d := Backoff(50, hi); d != 5*time.Minute {
		t.Errorf("attempt 50 high = %v, want cap", d)
	}
	if d := Backoff(50, lo); d != 150*time.Second {
		t.Errorf("attempt 50 low = %v", d)
	}
}
```

- [ ] **Step 2: Run — expect FAIL**

Run: `go test ./internal/sim/ -run TestBackoff`

- [ ] **Step 3: Implement backoff and runner**

`internal/sim/backoff.go`:
```go
package sim

import "time"

const (
	backoffBase = time.Second
	backoffCap  = 5 * time.Minute
)

// Backoff returns the delay before reconnect attempt n (0-based) using
// capped exponential backoff with equal jitter.
func Backoff(attempt int, rnd func() float64) time.Duration {
	d := backoffCap
	if attempt < 20 {
		d = min(backoffBase<<attempt, backoffCap)
	}
	half := d / 2
	return half + time.Duration(rnd()*float64(half))
}
```

`internal/sim/runner.go`:
```go
package sim

import (
	"context"
	"log/slog"
	"math/rand/v2"
	"time"

	flv1 "freelocker/gen/freelocker/v1"
	"freelocker/internal/server/commands"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Runner struct {
	Addr     string
	Identity *Identity
	Hostname string
	Interval time.Duration
	Log      *slog.Logger
}

func (r *Runner) Run(ctx context.Context) error {
	if r.Log == nil {
		r.Log = slog.Default()
	}
	started := time.Now()
	attempt := 0
	for {
		err := r.session(ctx, started, func() { attempt = 0 })
		if ctx.Err() != nil {
			return nil
		}
		if status.Code(err) == codes.Unauthenticated {
			r.Log.Error("server rejected device; stopping", "device", r.Identity.DeviceID, "err", err)
			return err
		}
		d := Backoff(attempt, rand.Float64)
		attempt++
		r.Log.Warn("disconnected; will retry", "device", r.Identity.DeviceID, "err", err, "in", d)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(d):
		}
	}
}

func (r *Runner) session(ctx context.Context, started time.Time, connected func()) error {
	sess, err := Connect(ctx, r.Addr, r.Identity)
	if err != nil {
		return err
	}
	defer sess.Close()
	heartbeat := func() error {
		return sess.Heartbeat(&flv1.Inventory{
			Hostname: r.Hostname, OsBuild: "sim", AgentVersion: "sim-0.1", IpAddresses: []string{"127.0.0.1"},
			LoggedOnUser: `SIM\user`, UptimeSeconds: int64(time.Since(started).Seconds()),
		})
	}
	if err := heartbeat(); err != nil {
		return err
	}
	connected()
	tick := time.NewTicker(r.Interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			sess.Goodbye("shutdown")
			return ctx.Err()
		case err := <-sess.Done():
			return err
		case sc, ok := <-sess.Commands():
			if !ok {
				return <-sess.Done()
			}
			cmd, err := commands.Verify(r.Identity.CommandPub, sc, r.Identity.DeviceID, time.Now())
			if err != nil {
				r.Log.Warn("rejected command", "err", err)
				continue
			}
			if err := sess.SendResult(&flv1.CommandResult{CommandId: cmd.GetId(), Success: true,
				Message: "sim handled " + commands.TypeName(cmd.GetType())}); err != nil {
				return err
			}
		case <-tick.C:
			if err := heartbeat(); err != nil {
				return err
			}
		}
	}
}
```

- [ ] **Step 4: Run backoff test — expect PASS**

Run: `go test ./internal/sim/`

- [ ] **Step 5: Implement the agent-sim CLI**

`cmd/agent-sim/main.go`:
```go
// Command agent-sim runs many fake agents against a FreeLocker server for
// integration and load testing.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"time"

	flv1 "freelocker/gen/freelocker/v1"
	"freelocker/internal/sim"
)

type stateEntry struct {
	Hostname string        `json:"hostname"`
	Identity *sim.Identity `json:"identity"`
}

func main() {
	server := flag.String("server", "localhost:8443", "agent API address (host must be in the server's public_hostnames)")
	token := flag.String("token", "", "install token (needed only for agents not yet in the state file)")
	count := flag.Int("count", 1, "number of simulated agents")
	interval := flag.Duration("interval", 30*time.Second, "heartbeat interval")
	statePath := flag.String("state", "sim-state.json", "file that persists enrolled identities between runs")
	flag.Parse()
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	agents, err := loadOrEnroll(ctx, *statePath, *server, *token, *count)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	fmt.Printf("running %d simulated agents against %s (Ctrl+C to stop)\n", len(agents), *server)

	var wg sync.WaitGroup
	for _, a := range agents {
		wg.Add(1)
		go func() {
			defer wg.Done()
			(&sim.Runner{Addr: *server, Identity: a.Identity, Hostname: a.Hostname, Interval: *interval, Log: log}).Run(ctx)
		}()
		time.Sleep(5 * time.Millisecond) // spread connection storms
	}
	wg.Wait()
}

func loadOrEnroll(ctx context.Context, path, server, token string, count int) ([]stateEntry, error) {
	var agents []stateEntry
	if b, err := os.ReadFile(path); err == nil {
		if err := json.Unmarshal(b, &agents); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if len(agents) >= count {
		return agents[:count], nil
	}
	if token == "" {
		return nil, fmt.Errorf("need -token to enroll %d more agents", count-len(agents))
	}

	var (
		mu  sync.Mutex
		wg  sync.WaitGroup
		sem = make(chan struct{}, 50)
		errs []error
	)
	for i := len(agents); i < count; i++ {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer func() { <-sem; wg.Done() }()
			host := fmt.Sprintf("sim-%05d", i)
			id, err := sim.Enroll(ctx, server, token, &flv1.HardwareInfo{Hostname: host, OsBuild: "sim", MachineGuid: host})
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", host, err))
				return
			}
			agents = append(agents, stateEntry{Hostname: host, Identity: id})
		}()
	}
	wg.Wait()
	b, _ := json.MarshalIndent(agents, "", "  ")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return nil, err
	}
	if len(errs) > 0 {
		return nil, fmt.Errorf("%d enrollments failed, first: %w", len(errs), errs[0])
	}
	return agents, nil
}
```

Run: `go build -o bin/agent-sim.exe ./cmd/agent-sim`
Expected: builds with no errors.

- [ ] **Step 6: Write the end-to-end integration test**

`test/integration/flow_test.go`:
```go
// Package integration exercises the full server through its public
// console API and the agent gRPC protocol.
package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"testing"
	"time"

	flv1 "freelocker/gen/freelocker/v1"
	"freelocker/internal/server/app"
	"freelocker/internal/server/config"
	"freelocker/internal/server/store/storetest"
	"freelocker/internal/sim"

	"github.com/pquerna/otp/totp"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type console struct {
	t    *testing.T
	base string
	c    *http.Client
	csrf string
}

func (k *console) do(method, path string, body, out any) int {
	k.t.Helper()
	b, _ := json.Marshal(body)
	if body == nil {
		b = nil
	}
	req, _ := http.NewRequest(method, k.base+path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", k.csrf)
	resp, err := k.c.Do(req)
	if err != nil {
		k.t.Fatal(err)
	}
	defer resp.Body.Close()
	if out != nil {
		json.NewDecoder(resp.Body).Decode(out)
	}
	return resp.StatusCode
}

func eventually(t *testing.T, what string, timeout time.Duration, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(timeout); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestEndToEnd(t *testing.T) {
	ctx := context.Background()
	cfg := config.Config{AgentListen: "127.0.0.1:0", PublicHostnames: []string{"127.0.0.1"}, InsecureCookies: true}
	a, err := app.NewWithStore(cfg, storetest.New(t), bytes.Repeat([]byte{5}, 32), slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	srv := httptest.NewServer(a.Handler())
	defer srv.Close()
	jar, _ := cookiejar.New(nil)
	k := &console{t: t, base: srv.URL, c: &http.Client{Jar: jar}}

	// 1. First-run setup, login, TOTP enrollment.
	if code := k.do("POST", "/api/setup", map[string]string{"org_name": "Acme", "email": "owner@example.com", "password": "owner-password-123"}, nil); code != 201 {
		t.Fatalf("setup = %d", code)
	}
	var lr struct {
		CSRF string `json:"csrf_token"`
	}
	k.do("POST", "/api/login", map[string]string{"email": "owner@example.com", "password": "owner-password-123"}, &lr)
	k.csrf = lr.CSRF
	var ms struct{ Secret string }
	k.do("POST", "/api/mfa/setup", nil, &ms)
	code, _ := totp.GenerateCode(ms.Secret, time.Now())
	if st := k.do("POST", "/api/mfa/verify", map[string]string{"code": code}, nil); st != 204 {
		t.Fatalf("mfa verify = %d", st)
	}

	// 2. Create an install token and enroll a simulated agent with it.
	var tok struct{ Token string }
	if st := k.do("POST", "/api/tokens", map[string]any{"name": "e2e", "max_uses": 5}, &tok); st != 201 {
		t.Fatalf("create token = %d", st)
	}
	id, err := sim.Enroll(ctx, a.AgentAddr(), tok.Token, &flv1.HardwareInfo{Hostname: "e2e-pc", OsBuild: "26100"})
	if err != nil {
		t.Fatal(err)
	}
	runCtx, stopRunner := context.WithCancel(ctx)
	defer stopRunner()
	runErr := make(chan error, 1)
	go func() {
		runErr <- (&sim.Runner{Addr: a.AgentAddr(), Identity: id, Hostname: "e2e-pc", Interval: 200 * time.Millisecond}).Run(runCtx)
	}()

	// 3. Device shows online (spec target: within 60 s; locally well under 5 s).
	eventually(t, "device online", 5*time.Second, func() bool {
		var devs []struct{ Hostname, Status string }
		k.do("GET", "/api/devices", nil, &devs)
		return len(devs) == 1 && devs[0].Hostname == "e2e-pc" && devs[0].Status == "online"
	})

	// 4. Issue a command; the sim verifies its signature and acknowledges it.
	var cmd struct{ ID string }
	if st := k.do("POST", "/api/devices/"+id.DeviceID+"/commands", map[string]string{"type": "ping"}, &cmd); st != 201 {
		t.Fatalf("issue = %d", st)
	}
	eventually(t, "command succeeded", 5*time.Second, func() bool {
		var cmds []struct{ ID, State string }
		k.do("GET", "/api/devices/"+id.DeviceID+"/commands", nil, &cmds)
		return len(cmds) == 1 && cmds[0].ID == cmd.ID && cmds[0].State == "succeeded"
	})

	// 5. Revoke: the live stream is cut and the agent stops retrying.
	if st := k.do("POST", "/api/devices/"+id.DeviceID+"/revoke", nil, nil); st != 204 {
		t.Fatalf("revoke = %d", st)
	}
	select {
	case err := <-runErr:
		if status.Code(err) != codes.Unauthenticated {
			t.Fatalf("runner ended with %v, want Unauthenticated", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("runner did not stop after revoke")
	}

	// 6. Every step is in the audit log.
	var audit []struct{ Action string }
	k.do("GET", "/api/audit?limit=100", nil, &audit)
	seen := map[string]bool{}
	for _, e := range audit {
		seen[e.Action] = true
	}
	for _, want := range []string{"setup.complete", "admin.login", "token.create", "device.enroll", "command.issue", "command.result", "device.revoke"} {
		if !seen[want] {
			t.Errorf("audit log missing %q; have %v", want, seen)
		}
	}
}
```

- [ ] **Step 7: Run the integration test — expect PASS**

Run: `go test ./test/integration/ -v`
Expected: `--- PASS: TestEndToEnd`

- [ ] **Step 8: Run the full suite**

Run: `go vet ./...; go test ./...`
Expected: vet clean; every package `ok`.

- [ ] **Step 9: Manual load check (1,000 agents)**

```powershell
docker compose -f deploy/docker-compose.yml up -d --build
# create the owner and a token (the console UI comes in plan 1c):
docker compose -f deploy/docker-compose.yml exec server /freelocker-server init -org Acme -email owner@example.com -password owner-password-123
```
Then log in and create a token via the API (e.g. with the PowerShell `Invoke-RestMethod -SessionVariable` session, including TOTP), and run:
```powershell
.\bin\agent-sim.exe -server localhost:8443 -token <token> -count 1000 -interval 30s
```
Expected: all 1,000 enroll; `GET /api/devices?status=online` returns 1,000 entries within ~60 s; server container CPU stays below one core (`docker stats`). Record the numbers in the commit message.

Note: if `init` ran inside the container *after* `serve` started, restart the server container (`docker compose restart server`) so it activates the agent API; or use `POST /api/setup` instead, which activates immediately.

- [ ] **Step 10: Commit**

```powershell
git add internal/sim cmd/agent-sim test
git commit -m "feat: add agent-sim load tool and end-to-end integration test"
```

---

## Spec coverage (sub-project #1, server side)

| Spec section | Covered by |
|---|---|
| §3 architecture, outbound-only agents, identity from certs | Tasks 8–9 |
| §4 enrollment (token, CSR, CA, device record, audit) | Tasks 4, 5, 7, 8 |
| §5 stream, heartbeat 30 s, online 90 s, backoff, skew, commands | Tasks 7, 9, 10, 15 |
| §6 CA, 90-day certs, renewal, key sealing, TLS modes | Tasks 3, 5, 9, 14 |
| §7 uninstall code, clean-shutdown vs unexpected offline | Tasks 5, 7, 9, 13 |
| §7 agent self-protection, MSI, updater, release hosting | **Plan 1b** |
| §8 auth, TOTP, sessions, CSRF, rate limit, RBAC, audit, setup, config | Tasks 2, 6, 11–14 |
| §9 console UI | **Plan 1c** (API in Tasks 12–13) |
| §10 deployment (compose, container, single instance) | Task 14 |
| §11 testing (unit, integration, agent-sim, 1,000-agent target) | All tasks; Task 15 |
| §12 success criteria 1, 3, 5 | Tasks 14, 15 (criteria 2 and 4 need the real agent: plan 1b) |
