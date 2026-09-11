# Core Platform 1b — Windows Agent, Updater & MSI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `freelocker-agent`, a Windows service that enrolls with the server, maintains a live gRPC stream (heartbeat + inventory), executes signed commands, auto-renews its certificate, protects its own files, updates itself from server-hosted signed releases, and ships as a silently-installable MSI.

**Architecture:** New agent code in one Go module (the existing `freelocker` module). Wire-protocol logic mirrors `internal/sim` but with real, DPAPI-protected key storage and real command execution behind small interfaces so the cross-platform logic is unit-testable on any OS while Windows syscalls live behind build tags. Server gains release-hosting endpoints and an `UpdateAgent` command payload. The MSI (WiX v5) installs the service per-machine with `SERVER_URL`/`TOKEN` properties for GPO/Intune.

**Tech Stack:** Go 1.27, `golang.org/x/sys/windows` (+ `/svc`, `/svc/mgr`, `/svc/eventlog`, `/registry`), crypt32 DPAPI via syscall, gRPC + the existing `proto/freelocker/v1`, WiX Toolset v5 (installed; `WixToolset.UI`/`WixToolset.Firewall` extensions present), the existing server packages.

**Spec:** `docs/superpowers/specs/2026-09-10-core-platform-design.md` (§4–§7)

**Depends on:** plan 1a (merged). Reuses `commands.Verify/TypeName/ParseType`, `proto` types, and for tests `app.NewWithStore` + `storetest`.

## Global Constraints

- Module path `freelocker`; Go floor 1.27. Agent builds for `GOOS=windows GOARCH=amd64`.
- Windows-only source uses `//go:build windows`; every such file has a `//go:build !windows` sibling (stub or fake) so `go build`/`go vet` and pure-logic tests pass on the dev machine and in CI on any OS.
- Install dir `C:\Program Files\FreeLocker\`; data dir `C:\ProgramData\FreeLocker\`. Paths come from `agentpaths`, never hard-coded elsewhere.
- Device private key at rest: DPAPI **machine scope** (`CRYPTPROTECT_LOCAL_MACHINE`). Key type ECDSA P-256 (matches the CA).
- Service name `FreeLockerAgent`; display name "FreeLocker Agent"; runs as `LocalSystem`; start type automatic.
- Agent talks only outbound to `agent_listen` over mTLS; no inbound listener, no firewall rule.
- Heartbeat every 30 s; reconnect via `sim.Backoff` cadence (reuse the same 1 s→5 min equal-jitter curve); certificate auto-renew when remaining life < `ca.RenewAfter` (30 days before 90-day expiry).
- Command signatures verified with `commands.Verify` against the enrolled command public key; duplicate command IDs are ignored (at-least-once delivery).
- Uninstall requires the per-device uninstall code (server shows it; agent holds only its SHA-256) unless a server `Uninstall` command drives it.
- Agent version string: `internal/agent/version.Version` (default `dev`, set at build with `-ldflags "-X freelocker/internal/agent/version.Version=<v>"`).
- Update binaries are verified by SHA-256 **and** Ed25519 signature against the enrolled update public key before use.
- Test DB (server-side tasks): `deploy/docker-compose.dev.yml` on `localhost:55432`; Docker Desktop must be running.

## Deliberate scope decisions (flag to reviewer)

1. **`internal/sim` stays** the protocol-accurate test agent; the production agent is separate code. The duplication is intentional — an independent second implementation keeps the protocol honest — but both share `commands` and `proto`.
2. **`RotateCertificate` command** = force an immediate renewal (same code path as the scheduled renew).
3. **Release hosting** is minimal: `agent_releases` (already in schema) plus owner-only upload and unauthenticated-but-hash-checked download over the console HTTP listener. Signing the release uses the server's existing update-signing key (`bootstrap.Keys.UpdateKey`); an `flctl`-style step is out of scope — the server signs on upload.
4. **Rollback** watches for a successful heartbeat from the new binary within 2 minutes; if none, the updater restores the previous binary and restarts.

## File Structure

```
internal/agent/version/version.go            build-stamped version var
internal/agent/agentpaths/agentpaths.go       install/data paths (+ _windows override)
internal/agent/config/config.go               config.yaml (server_url, token) + env
internal/agent/secret/secret.go               Protector interface + FileProtector (portable)
internal/agent/secret/secret_windows.go       DPAPI machine-scope protector
internal/agent/identity/identity.go            keypair, CSR, enroll, renew, load/save, TLS config
internal/agent/inventory/inventory.go          Inventory struct + Collector interface + fake
internal/agent/inventory/inventory_windows.go  real Windows collector
internal/agent/executor/executor.go            command dispatch table
internal/agent/runner/runner.go                enroll→connect→heartbeat→commands→renew loop
internal/agent/updater/updater.go              download+verify+swap+rollback
internal/agent/service/service_windows.go      svc.Handler, event log
internal/agent/service/service_other.go        non-windows stub (console run only)
cmd/agent/main.go                              verbs: run, install-service, uninstall, version
cmd/agent-updater/main.go                      swap helper (separate exe)
internal/server/store/releases.go              agent_releases CRUD
internal/server/httpapi/releases.go            upload (owner) + download endpoints
internal/server/commands/update.go             UpdateAgent payload (version, url, sha256, sig)
deploy/msi/Package.wxs                          WiX v5 package
deploy/msi/build.ps1                            build script (go build + wix build)
docs/agent-manual-test.md                      VM install/uninstall/update checklist
```

---

### Task 1: Agent paths, version, and config

**Files:**
- Create: `internal/agent/version/version.go`, `internal/agent/agentpaths/agentpaths.go`, `internal/agent/agentpaths/agentpaths_windows.go`, `internal/agent/config/config.go`
- Test: `internal/agent/config/config_test.go`, `internal/agent/agentpaths/agentpaths_test.go`

**Interfaces:**
- Produces:
  - `version.Version string` (var, default `"dev"`)
  - `agentpaths.Paths{InstallDir, DataDir string}`; `agentpaths.Default() Paths`; methods `(Paths).Config() string` (`<DataDir>/config.yaml`), `Key()`, `Cert()`, `CA()`, `Enrollment()` (`enrollment.json`), `Log()`. Non-Windows `Default()` uses `os.TempDir()+/freelocker` so tests are hermetic; Windows uses the ProgramData/Program Files constants.
  - `config.Config{ServerURL string; Token string}`; `config.Load(path string) (Config, error)` — YAML, overridden by env `FREELOCKER_SERVER_URL` / `FREELOCKER_TOKEN`; `config.Write(path string, c Config) error` (0600).
  - `config.ErrNoServerURL`.

- [ ] **Step 1: Write failing config test**

`internal/agent/config/config_test.go`:
```go
package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteLoadAndEnvOverride(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := Write(p, Config{ServerURL: "fl.example.com:8443", Token: "sec.pin"}); err != nil {
		t.Fatal(err)
	}
	c, err := Load(p)
	if err != nil || c.ServerURL != "fl.example.com:8443" || c.Token != "sec.pin" {
		t.Fatalf("Load = %+v, %v", c, err)
	}
	t.Setenv("FREELOCKER_SERVER_URL", "other:9443")
	if c, _ := Load(p); c.ServerURL != "other:9443" {
		t.Errorf("env override = %q", c.ServerURL)
	}
}

func TestLoadRequiresServerURL(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.yaml")
	Write(p, Config{Token: "x"})
	if _, err := Load(p); err == nil {
		t.Fatal("expected ErrNoServerURL")
	}
}
```

- [ ] **Step 2: Run — expect FAIL**

Run: `go test ./internal/agent/config/`

- [ ] **Step 3: Implement version, paths, config**

`internal/agent/version/version.go`:
```go
// Package version holds the agent version, stamped at build time with
// -ldflags "-X freelocker/internal/agent/version.Version=<v>".
package version

var Version = "dev"
```

`internal/agent/agentpaths/agentpaths.go`:
```go
// Package agentpaths centralizes the agent's on-disk locations.
package agentpaths

import (
	"os"
	"path/filepath"
)

type Paths struct {
	InstallDir string
	DataDir    string
}

func (p Paths) Config() string     { return filepath.Join(p.DataDir, "config.yaml") }
func (p Paths) Key() string        { return filepath.Join(p.DataDir, "device.key") }
func (p Paths) Cert() string       { return filepath.Join(p.DataDir, "device.crt") }
func (p Paths) CA() string         { return filepath.Join(p.DataDir, "ca.crt") }
func (p Paths) Enrollment() string { return filepath.Join(p.DataDir, "enrollment.json") }
func (p Paths) Log() string        { return filepath.Join(p.DataDir, "agent.log") }

// defaultDirs is overridden on Windows.
var defaultDirs = func() (install, data string) {
	base := filepath.Join(os.TempDir(), "freelocker")
	return filepath.Join(base, "bin"), filepath.Join(base, "data")
}

func Default() Paths {
	install, data := defaultDirs()
	return Paths{InstallDir: install, DataDir: data}
}
```

`internal/agent/agentpaths/agentpaths_windows.go`:
```go
//go:build windows

package agentpaths

import (
	"os"
	"path/filepath"
)

func init() {
	defaultDirs = func() (install, data string) {
		pf := os.Getenv("ProgramFiles")
		if pf == "" {
			pf = `C:\Program Files`
		}
		pd := os.Getenv("ProgramData")
		if pd == "" {
			pd = `C:\ProgramData`
		}
		return filepath.Join(pf, "FreeLocker"), filepath.Join(pd, "FreeLocker")
	}
}
```

`internal/agent/config/config.go`:
```go
// Package config loads the agent's server URL and (pre-enrollment) install token.
package config

import (
	"errors"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

var ErrNoServerURL = errors.New("server_url is required")

type Config struct {
	ServerURL string `yaml:"server_url"`
	Token     string `yaml:"token"`
}

func Load(path string) (Config, error) {
	var c Config
	b, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return c, fmt.Errorf("read config: %w", err)
	}
	if err == nil {
		if err := yaml.Unmarshal(b, &c); err != nil {
			return c, fmt.Errorf("parse config: %w", err)
		}
	}
	if v := os.Getenv("FREELOCKER_SERVER_URL"); v != "" {
		c.ServerURL = v
	}
	if v := os.Getenv("FREELOCKER_TOKEN"); v != "" {
		c.Token = v
	}
	if c.ServerURL == "" {
		return c, ErrNoServerURL
	}
	return c, nil
}

func Write(path string, c Config) error {
	b, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}
```

`internal/agent/agentpaths/agentpaths_test.go`:
```go
package agentpaths

import (
	"path/filepath"
	"testing"
)

func TestPathsAreUnderDataDir(t *testing.T) {
	p := Default()
	if p.DataDir == "" || p.InstallDir == "" {
		t.Fatal("empty paths")
	}
	for _, got := range []string{p.Config(), p.Key(), p.Cert(), p.CA(), p.Enrollment()} {
		if filepath.Dir(got) != p.DataDir {
			t.Errorf("%s not under DataDir %s", got, p.DataDir)
		}
	}
}
```

- [ ] **Step 4: Run — expect PASS**

Run: `go test ./internal/agent/...`

- [ ] **Step 5: Commit**

```powershell
git add internal/agent/version internal/agent/agentpaths internal/agent/config
git commit -m "feat(agent): add paths, version, and config"
```

---

### Task 2: Secret protection (portable interface + DPAPI on Windows)

**Files:**
- Create: `internal/agent/secret/secret.go`, `internal/agent/secret/secret_windows.go`, `internal/agent/secret/secret_other.go`
- Test: `internal/agent/secret/secret_test.go`

**Interfaces:**
- Produces:
  - `secret.Protector` interface: `Protect(plain []byte) ([]byte, error)`, `Unprotect(sealed []byte) ([]byte, error)`.
  - `secret.FileProtector{}` — portable identity protector (no encryption; used off-Windows and in tests). Documented as **not secure**; real protection is DPAPI.
  - `secret.Default() Protector` — returns the DPAPI protector on Windows, `FileProtector{}` elsewhere.
  - Windows: `secret.DPAPI{}` implementing `Protector` via `CryptProtectData`/`CryptUnprotectData` with `CRYPTPROTECT_LOCAL_MACHINE`.

- [ ] **Step 1: Write portable test**

`internal/agent/secret/secret_test.go`:
```go
package secret

import (
	"bytes"
	"testing"
)

func TestDefaultRoundtrip(t *testing.T) {
	p := Default()
	sealed, err := p.Protect([]byte("device-private-key"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := p.Unprotect(sealed)
	if err != nil || !bytes.Equal(got, []byte("device-private-key")) {
		t.Fatalf("Unprotect = %q, %v", got, err)
	}
}
```

- [ ] **Step 2: Run — expect FAIL**

Run: `go test ./internal/agent/secret/`

- [ ] **Step 3: Implement**

`internal/agent/secret/secret.go`:
```go
// Package secret protects the agent's private key at rest. On Windows it
// uses DPAPI machine scope; elsewhere a non-encrypting file protector is
// used only so the surrounding logic is testable off-Windows.
package secret

type Protector interface {
	Protect(plain []byte) ([]byte, error)
	Unprotect(sealed []byte) ([]byte, error)
}

// FileProtector performs no encryption. NOT for production key storage.
type FileProtector struct{}

func (FileProtector) Protect(plain []byte) ([]byte, error)    { return append([]byte(nil), plain...), nil }
func (FileProtector) Unprotect(sealed []byte) ([]byte, error) { return append([]byte(nil), sealed...), nil }
```

`internal/agent/secret/secret_other.go`:
```go
//go:build !windows

package secret

func Default() Protector { return FileProtector{} }
```

`internal/agent/secret/secret_windows.go`:
```go
//go:build windows

package secret

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

const cryptProtectLocalMachine = 0x4

var (
	crypt32            = windows.NewLazySystemDLL("crypt32.dll")
	procProtectData    = crypt32.NewProc("CryptProtectData")
	procUnprotectData  = crypt32.NewProc("CryptUnprotectData")
	kernel32           = windows.NewLazySystemDLL("kernel32.dll")
	procLocalFree      = kernel32.NewProc("LocalFree")
)

type dataBlob struct {
	cbData uint32
	pbData *byte
}

func newBlob(b []byte) dataBlob {
	if len(b) == 0 {
		return dataBlob{}
	}
	return dataBlob{cbData: uint32(len(b)), pbData: &b[0]}
}

func (b dataBlob) bytes() []byte {
	out := make([]byte, b.cbData)
	copy(out, unsafe.Slice(b.pbData, b.cbData))
	return out
}

type DPAPI struct{}

func Default() Protector { return DPAPI{} }

func (DPAPI) Protect(plain []byte) ([]byte, error)    { return crypt(procProtectData, plain) }
func (DPAPI) Unprotect(sealed []byte) ([]byte, error) { return crypt(procUnprotectData, sealed) }

func crypt(proc *windows.LazyProc, in []byte) ([]byte, error) {
	inBlob := newBlob(in)
	var outBlob dataBlob
	r, _, err := proc.Call(
		uintptr(unsafe.Pointer(&inBlob)),
		0, 0, 0, 0,
		cryptProtectLocalMachine,
		uintptr(unsafe.Pointer(&outBlob)),
	)
	if r == 0 {
		return nil, fmt.Errorf("DPAPI call failed: %w", err)
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(outBlob.pbData)))
	return outBlob.bytes(), nil
}
```

- [ ] **Step 4: Run — expect PASS** (DPAPI path exercised on this Windows dev machine)

Run: `go test ./internal/agent/secret/`

- [ ] **Step 5: Commit**

```powershell
git add internal/agent/secret
git commit -m "feat(agent): add DPAPI-backed secret protector with portable fallback"
```

---

### Task 3: Agent identity — keypair, enroll, renew, load, TLS

**Files:**
- Create: `internal/agent/identity/identity.go`
- Test: `internal/agent/identity/identity_test.go`

**Interfaces:**
- Consumes: `secret.Protector`, `agentpaths.Paths`, `tokens.Parse`, `ca.PinFromCert`, proto Enrollment/Agent clients.
- Produces:
  - `identity.Enrollment{DeviceID string; CommandPub, UpdatePub, UninstallHash []byte}` (persisted as JSON).
  - `identity.Store{Paths agentpaths.Paths; Protector secret.Protector}`.
  - `(*Store).Enroll(ctx, serverURL, installToken, hw *flv1.HardwareInfo) (*identity.Enrollment, error)` — generates key, pins server CA to the token, calls Enroll RPC, writes key (protected)+cert+ca+enrollment.json.
  - `(*Store).Load() (*identity.Loaded, error)` where `Loaded{Enrollment; TLSConfig() (*tls.Config, error); CertNotAfter time.Time}`; `identity.ErrNotEnrolled`.
  - `(*Store).Renew(ctx, serverURL string, l *identity.Loaded) error` — new key+CSR via Agent.RenewCertificate, atomically replaces cert+key.
  - `(*Store).Enrolled() bool`.

- [ ] **Step 1: Write failing test** (uses the real server via `app.NewWithStore`)

`internal/agent/identity/identity_test.go`:
```go
package identity_test

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	flv1 "freelocker/gen/freelocker/v1"
	"freelocker/internal/agent/agentpaths"
	"freelocker/internal/agent/identity"
	"freelocker/internal/agent/secret"
	"freelocker/internal/server/app"
	"freelocker/internal/server/config"
	"freelocker/internal/server/store"
	"freelocker/internal/server/store/storetest"

	"log/slog"

	"github.com/google/uuid"
)

// startServer boots a real server and returns its agent address + a token.
func startServer(t *testing.T) (addr, token string) {
	t.Helper()
	cfg := config.Config{AgentListen: "127.0.0.1:0", PublicHostnames: []string{"127.0.0.1"}, InsecureCookies: true}
	a, err := app.NewWithStore(cfg, storetest.New(t), bytes.Repeat([]byte{6}, 32), slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	if _, err := a.Initialize(context.Background(), "Acme", "o@example.com", "owner-password-123"); err != nil {
		t.Fatal(err)
	}
	// Reuse the app's runtime by issuing a token through the store directly.
	return a.AgentAddr(), a.MintTestToken(t)
}

func paths(t *testing.T) agentpaths.Paths {
	d := t.TempDir()
	return agentpaths.Paths{InstallDir: d, DataDir: d}
}

func TestEnrollLoadRenew(t *testing.T) {
	ctx := context.Background()
	addr, token := startServer(t)
	st := &identity.Store{Paths: paths(t), Protector: secret.Default()}

	if st.Enrolled() {
		t.Fatal("should not be enrolled yet")
	}
	enr, err := st.Enroll(ctx, addr, token, &flv1.HardwareInfo{Hostname: "pc-1", OsBuild: "26100"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := uuid.Parse(enr.DeviceID); err != nil {
		t.Fatalf("device id = %q", enr.DeviceID)
	}
	if !st.Enrolled() {
		t.Fatal("should be enrolled after Enroll")
	}

	l, err := st.Load()
	if err != nil || l.DeviceID != enr.DeviceID || len(l.CommandPub) != 32 {
		t.Fatalf("Load = %+v, %v", l, err)
	}
	if time.Until(l.CertNotAfter) < 80*24*time.Hour {
		t.Errorf("cert expiry too soon: %v", l.CertNotAfter)
	}
	if _, err := l.TLSConfig(); err != nil {
		t.Fatalf("TLSConfig: %v", err)
	}

	oldNotAfter := l.CertNotAfter
	if err := st.Renew(ctx, addr, l); err != nil {
		t.Fatal(err)
	}
	l2, _ := st.Load()
	if !l2.CertNotAfter.After(oldNotAfter.Add(-time.Second)) {
		t.Errorf("renew did not extend expiry: %v -> %v", oldNotAfter, l2.CertNotAfter)
	}
}
```

Note: this test needs a server helper `MintTestToken`. Add it in Step 2.

- [ ] **Step 2: Add the test-only token minter to the app**

In `internal/server/app/app.go` add (guarded for test use, but harmless in prod):
```go
// TokenForTests creates an unlimited install token. Intended for tests
// and manual bring-up; requires the server to be initialized.
func (a *App) TokenForTests(ctx context.Context) (string, error) {
	rt := a.runtime()
	if rt == nil {
		return "", errors.New("not initialized")
	}
	full, hash, err := tokens.Generate(rt.Keys.CA.Pin())
	if err != nil {
		return "", err
	}
	if _, err := a.store.CreateInstallToken(ctx, rt.Keys.TenantID, store.InstallToken{Name: "bring-up"}, hash); err != nil {
		return "", err
	}
	return full, nil
}
```
Add imports `"freelocker/internal/server/tokens"` (and `store` is already imported). Then in the test file replace `a.MintTestToken(t)` with:
```go
tok, err := a.TokenForTests(context.Background())
if err != nil {
	t.Fatal(err)
}
return a.AgentAddr(), tok
```

- [ ] **Step 3: Run — expect FAIL**

Run: `go test ./internal/agent/identity/`

- [ ] **Step 4: Implement identity**

`internal/agent/identity/identity.go`:
```go
// Package identity manages the agent's cryptographic identity: its key,
// certificate, and the metadata returned at enrollment.
package identity

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"

	flv1 "freelocker/gen/freelocker/v1"
	"freelocker/internal/agent/agentpaths"
	"freelocker/internal/agent/secret"
	"freelocker/internal/server/ca"
	"freelocker/internal/server/tokens"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

var ErrNotEnrolled = errors.New("agent is not enrolled")

type Enrollment struct {
	DeviceID      string `json:"device_id"`
	CommandPub    []byte `json:"command_pub"`
	UpdatePub     []byte `json:"update_pub"`
	UninstallHash []byte `json:"uninstall_hash"`
}

type Store struct {
	Paths     agentpaths.Paths
	Protector secret.Protector
}

func (s *Store) Enrolled() bool {
	_, err := os.Stat(s.Paths.Enrollment())
	return err == nil
}

func (s *Store) Enroll(ctx context.Context, serverURL, installToken string, hw *flv1.HardwareInfo) (*Enrollment, error) {
	secretPart, pin, err := tokens.Parse(installToken)
	if err != nil {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: hw.GetHostname()}}, key)
	if err != nil {
		return nil, err
	}
	conn, err := grpc.NewClient(serverURL, grpc.WithTransportCredentials(credentials.NewTLS(pinnedTLS(pin))))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	resp, err := flv1.NewEnrollmentClient(conn).Enroll(ctx, &flv1.EnrollRequest{
		TokenSecret: secretPart, CsrDer: csr, Hardware: hw,
	})
	if err != nil {
		return nil, fmt.Errorf("enroll: %w", err)
	}
	if err := s.writeIdentity(key, resp.GetCertDer(), resp.GetCaCertDer()); err != nil {
		return nil, err
	}
	enr := &Enrollment{
		DeviceID: resp.GetDeviceId(), CommandPub: resp.GetCommandSigningPublicKey(),
		UpdatePub: resp.GetUpdateSigningPublicKey(), UninstallHash: resp.GetUninstallCodeSha256(),
	}
	return enr, s.writeEnrollment(enr)
}

type Loaded struct {
	Enrollment
	certDER      []byte
	keyDER       []byte
	caDER        []byte
	CertNotAfter time.Time
}

func (s *Store) Load() (*Loaded, error) {
	if !s.Enrolled() {
		return nil, ErrNotEnrolled
	}
	var enr Enrollment
	b, err := os.ReadFile(s.Paths.Enrollment())
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &enr); err != nil {
		return nil, err
	}
	certDER, err := readPEM(s.Paths.Cert(), "CERTIFICATE")
	if err != nil {
		return nil, err
	}
	caDER, err := readPEM(s.Paths.CA(), "CERTIFICATE")
	if err != nil {
		return nil, err
	}
	sealed, err := readPEM(s.Paths.Key(), "FREELOCKER SEALED KEY")
	if err != nil {
		return nil, err
	}
	keyDER, err := s.Protector.Unprotect(sealed)
	if err != nil {
		return nil, fmt.Errorf("unprotect key: %w", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}
	return &Loaded{Enrollment: enr, certDER: certDER, keyDER: keyDER, caDER: caDER, CertNotAfter: cert.NotAfter}, nil
}

func (l *Loaded) TLSConfig() (*tls.Config, error) {
	key, err := x509.ParsePKCS8PrivateKey(l.keyDER)
	if err != nil {
		return nil, err
	}
	caCert, err := x509.ParseCertificate(l.caDER)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	return &tls.Config{
		MinVersion: tls.VersionTLS13, RootCAs: roots,
		Certificates: []tls.Certificate{{Certificate: [][]byte{l.certDER}, PrivateKey: key}},
	}, nil
}

func (s *Store) Renew(ctx context.Context, serverURL string, l *Loaded) error {
	tlsCfg, err := l.TLSConfig()
	if err != nil {
		return err
	}
	conn, err := grpc.NewClient(serverURL, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	if err != nil {
		return err
	}
	defer conn.Close()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: l.DeviceID}}, key)
	if err != nil {
		return err
	}
	resp, err := flv1.NewAgentClient(conn).RenewCertificate(ctx, &flv1.RenewRequest{CsrDer: csr})
	if err != nil {
		return err
	}
	return s.writeIdentity(key, resp.GetCertDer(), l.caDER)
}

func (s *Store) writeIdentity(key *ecdsa.PrivateKey, certDER, caDER []byte) error {
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	sealed, err := s.Protector.Protect(keyDER)
	if err != nil {
		return err
	}
	if err := writePEM(s.Paths.Key(), "FREELOCKER SEALED KEY", sealed, 0o600); err != nil {
		return err
	}
	if err := writePEM(s.Paths.Cert(), "CERTIFICATE", certDER, 0o644); err != nil {
		return err
	}
	return writePEM(s.Paths.CA(), "CERTIFICATE", caDER, 0o644)
}

func (s *Store) writeEnrollment(e *Enrollment) error {
	b, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.Paths.Enrollment(), b, 0o600)
}

func pinnedTLS(pin string) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13, InsecureSkipVerify: true,
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

func writePEM(path, typ string, der []byte, mode os.FileMode) error {
	b := pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
	return os.WriteFile(path, b, mode)
}

func readPEM(path, typ string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil || block.Type != typ {
		return nil, fmt.Errorf("%s: expected PEM %q", path, typ)
	}
	return block.Bytes, nil
}
```

- [ ] **Step 5: Run — expect PASS**

Run: `go test ./internal/agent/identity/ ./internal/server/app/`

- [ ] **Step 6: Commit**

```powershell
git add internal/agent/identity internal/server/app
git commit -m "feat(agent): add identity store (enroll, load, renew) and server test token helper"
```

---

### Task 4: Inventory collection

**Files:**
- Create: `internal/agent/inventory/inventory.go`, `internal/agent/inventory/inventory_windows.go`, `internal/agent/inventory/inventory_other.go`
- Test: `internal/agent/inventory/inventory_test.go`

**Interfaces:**
- Produces:
  - `inventory.Collector` interface: `Collect() *flv1.Inventory`.
  - `inventory.Base{Hostname, OSBuild, AgentVersion string; StartedAt time.Time}` with `(Base).fill(inv *flv1.Inventory)` setting hostname/os/version/uptime.
  - `inventory.New() Collector` — Windows collector on Windows (adds IPs + logged-on user via registry/WMI-free calls), portable collector elsewhere (hostname + net interfaces, empty user).
  - Portable helper `inventory.LocalIPs() []string` (non-loopback IPv4/IPv6).

- [ ] **Step 1: Write portable test**

`internal/agent/inventory/inventory_test.go`:
```go
package inventory

import (
	"testing"
	"time"
)

func TestCollectFillsBasics(t *testing.T) {
	c := New()
	inv := c.Collect()
	if inv.GetHostname() == "" {
		t.Error("hostname empty")
	}
	if inv.GetAgentVersion() == "" {
		t.Error("agent version empty")
	}
	if inv.GetUptimeSeconds() < 0 {
		t.Error("negative uptime")
	}
	time.Sleep(0)
}

func TestLocalIPsExcludeLoopback(t *testing.T) {
	for _, ip := range LocalIPs() {
		if ip == "127.0.0.1" || ip == "::1" {
			t.Errorf("loopback leaked: %s", ip)
		}
	}
}
```

- [ ] **Step 2: Run — expect FAIL**

Run: `go test ./internal/agent/inventory/`

- [ ] **Step 3: Implement**

`internal/agent/inventory/inventory.go`:
```go
// Package inventory gathers the facts sent in each heartbeat.
package inventory

import (
	"net"
	"os"
	"time"

	flv1 "freelocker/gen/freelocker/v1"
	"freelocker/internal/agent/version"
)

type Collector interface {
	Collect() *flv1.Inventory
}

type Base struct {
	StartedAt time.Time
}

func (b Base) base() *flv1.Inventory {
	host, _ := os.Hostname()
	return &flv1.Inventory{
		Hostname: host, AgentVersion: version.Version,
		IpAddresses: LocalIPs(), UptimeSeconds: int64(time.Since(b.StartedAt).Seconds()),
	}
}

func LocalIPs() []string {
	var out []string
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok && !ipn.IP.IsLoopback() && !ipn.IP.IsLinkLocalUnicast() {
			out = append(out, ipn.IP.String())
		}
	}
	return out
}
```

`internal/agent/inventory/inventory_other.go`:
```go
//go:build !windows

package inventory

import (
	"time"

	flv1 "freelocker/gen/freelocker/v1"
)

type portable struct{ Base }

func New() Collector { return portable{Base{StartedAt: time.Now()}} }

func (p portable) Collect() *flv1.Inventory { return p.base() }
```

`internal/agent/inventory/inventory_windows.go`:
```go
//go:build windows

package inventory

import (
	"time"

	flv1 "freelocker/gen/freelocker/v1"

	"golang.org/x/sys/windows/registry"
)

type winCollector struct{ Base }

func New() Collector { return winCollector{Base{StartedAt: time.Now()}} }

func (w winCollector) Collect() *flv1.Inventory {
	inv := w.base()
	inv.OsBuild = osBuild()
	inv.LoggedOnUser = loggedOnUser()
	return inv
}

func osBuild() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer k.Close()
	product, _, _ := k.GetStringValue("ProductName")
	build, _, _ := k.GetStringValue("CurrentBuild")
	if build != "" {
		return product + " " + build
	}
	return product
}

// loggedOnUser reads the interactive user recorded by Explorer's shell
// folder key under the last-logged-on session, best effort.
func loggedOnUser() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI`, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer k.Close()
	user, _, _ := k.GetStringValue("LastLoggedOnUser")
	return user
}
```

- [ ] **Step 4: Run — expect PASS**

Run: `go test ./internal/agent/inventory/`

- [ ] **Step 5: Commit**

```powershell
git add internal/agent/inventory
git commit -m "feat(agent): add inventory collection"
```

---

### Task 5: Command executor

**Files:**
- Create: `internal/agent/executor/executor.go`
- Test: `internal/agent/executor/executor_test.go`

**Interfaces:**
- Consumes: proto types, `commands.TypeName`.
- Produces:
  - `executor.Actions` interface: `RefreshInventory(ctx) error`, `RotateCertificate(ctx) error`, `Uninstall(ctx) error`, `UpdateAgent(ctx context.Context, p *flv1.Command) error`. (Ping needs no action.)
  - `executor.Executor{Actions executor.Actions; Log *slog.Logger}`.
  - `(*Executor).Run(ctx, cmd *flv1.Command) *flv1.CommandResult` — dispatches by `cmd.Type`, returns a result with `CommandId` set; unknown/unspecified types → failure "unsupported command".
  - `(*Executor).Seen(id string) bool` and internal dedupe: repeated IDs return the first result again without re-running (at-least-once delivery from the server).

- [ ] **Step 1: Write failing test**

`internal/agent/executor/executor_test.go`:
```go
package executor

import (
	"context"
	"errors"
	"testing"

	flv1 "freelocker/gen/freelocker/v1"
)

type fakeActions struct {
	refresh, rotate, uninstall, update int
	updateErr                          error
}

func (f *fakeActions) RefreshInventory(context.Context) error { f.refresh++; return nil }
func (f *fakeActions) RotateCertificate(context.Context) error { f.rotate++; return nil }
func (f *fakeActions) Uninstall(context.Context) error         { f.uninstall++; return nil }
func (f *fakeActions) UpdateAgent(context.Context, *flv1.Command) error {
	f.update++
	return f.updateErr
}

func cmd(id string, t flv1.CommandType) *flv1.Command { return &flv1.Command{Id: id, Type: t} }

func TestDispatchAndResults(t *testing.T) {
	fa := &fakeActions{}
	e := &Executor{Actions: fa}
	ctx := context.Background()

	if r := e.Run(ctx, cmd("c1", flv1.CommandType_COMMAND_TYPE_PING)); !r.GetSuccess() || r.GetCommandId() != "c1" {
		t.Fatalf("ping = %+v", r)
	}
	e.Run(ctx, cmd("c2", flv1.CommandType_COMMAND_TYPE_REFRESH_INVENTORY))
	e.Run(ctx, cmd("c3", flv1.CommandType_COMMAND_TYPE_ROTATE_CERTIFICATE))
	if fa.refresh != 1 || fa.rotate != 1 {
		t.Fatalf("actions = %+v", fa)
	}
	if r := e.Run(ctx, cmd("c9", flv1.CommandType_COMMAND_TYPE_UNSPECIFIED)); r.GetSuccess() {
		t.Error("unspecified must fail")
	}
}

func TestDedupeReturnsFirstResult(t *testing.T) {
	fa := &fakeActions{updateErr: errors.New("nope")}
	e := &Executor{Actions: fa}
	ctx := context.Background()
	first := e.Run(ctx, cmd("dup", flv1.CommandType_COMMAND_TYPE_UPDATE_AGENT))
	second := e.Run(ctx, cmd("dup", flv1.CommandType_COMMAND_TYPE_UPDATE_AGENT))
	if fa.update != 1 {
		t.Errorf("action ran %d times, want 1", fa.update)
	}
	if first.GetSuccess() || second.GetSuccess() || second.GetMessage() != first.GetMessage() {
		t.Errorf("dedupe should replay first failure: %+v %+v", first, second)
	}
}
```

- [ ] **Step 2: Run — expect FAIL**

Run: `go test ./internal/agent/executor/`

- [ ] **Step 3: Implement**

`internal/agent/executor/executor.go`:
```go
// Package executor runs signed server commands on the agent.
package executor

import (
	"context"
	"log/slog"
	"sync"

	flv1 "freelocker/gen/freelocker/v1"
)

type Actions interface {
	RefreshInventory(ctx context.Context) error
	RotateCertificate(ctx context.Context) error
	Uninstall(ctx context.Context) error
	UpdateAgent(ctx context.Context, cmd *flv1.Command) error
}

type Executor struct {
	Actions Actions
	Log     *slog.Logger

	mu   sync.Mutex
	seen map[string]*flv1.CommandResult
}

func (e *Executor) log() *slog.Logger {
	if e.Log != nil {
		return e.Log
	}
	return slog.Default()
}

func (e *Executor) Run(ctx context.Context, cmd *flv1.Command) *flv1.CommandResult {
	e.mu.Lock()
	if e.seen == nil {
		e.seen = map[string]*flv1.CommandResult{}
	}
	if prev, ok := e.seen[cmd.GetId()]; ok {
		e.mu.Unlock()
		return prev
	}
	e.mu.Unlock()

	res := e.dispatch(ctx, cmd)
	res.CommandId = cmd.GetId()

	e.mu.Lock()
	e.seen[cmd.GetId()] = res
	e.mu.Unlock()
	return res
}

func (e *Executor) dispatch(ctx context.Context, cmd *flv1.Command) *flv1.CommandResult {
	var err error
	switch cmd.GetType() {
	case flv1.CommandType_COMMAND_TYPE_PING:
		return ok("pong")
	case flv1.CommandType_COMMAND_TYPE_REFRESH_INVENTORY:
		err = e.Actions.RefreshInventory(ctx)
	case flv1.CommandType_COMMAND_TYPE_ROTATE_CERTIFICATE:
		err = e.Actions.RotateCertificate(ctx)
	case flv1.CommandType_COMMAND_TYPE_UNINSTALL:
		err = e.Actions.Uninstall(ctx)
	case flv1.CommandType_COMMAND_TYPE_UPDATE_AGENT:
		err = e.Actions.UpdateAgent(ctx, cmd)
	default:
		return fail("unsupported command")
	}
	if err != nil {
		e.log().Warn("command failed", "id", cmd.GetId(), "type", cmd.GetType().String(), "err", err)
		return fail(err.Error())
	}
	return ok("done")
}

func ok(msg string) *flv1.CommandResult   { return &flv1.CommandResult{Success: true, Message: msg} }
func fail(msg string) *flv1.CommandResult { return &flv1.CommandResult{Success: false, Message: msg} }
```

- [ ] **Step 4: Run — expect PASS**

Run: `go test ./internal/agent/executor/`

- [ ] **Step 5: Commit**

```powershell
git add internal/agent/executor
git commit -m "feat(agent): add command executor with dedupe"
```

---

### Task 6: Runner — enroll, connect, heartbeat, commands, renew, reconnect

**Files:**
- Create: `internal/agent/runner/runner.go`
- Test: `internal/agent/runner/runner_test.go`

**Interfaces:**
- Consumes: `identity.Store/Loaded`, `inventory.Collector`, `executor.Executor`, `commands.Verify`, `sim.Backoff` (reuse), `ca.RenewAfter`, proto Agent client.
- Produces:
  - `runner.Runner{ServerURL string; Identity *identity.Store; Inventory inventory.Collector; Executor *executor.Executor; HeartbeatInterval time.Duration; Log *slog.Logger; Clock func() time.Time}`.
  - `(*Runner).EnsureEnrolled(ctx, token string, hw *flv1.HardwareInfo) error` — enroll only if not already.
  - `(*Runner).Run(ctx) error` — loads identity, then loops: connect, heartbeat, handle commands (verify → execute → send result), renew when cert within `ca.RenewAfter`; reconnect with backoff; returns nil on ctx cancel (after Goodbye), returns the error on `Unauthenticated` (revoked) so the service stops retrying.
  - `runner.HardwareInfo() *flv1.HardwareInfo` helper building the enroll payload from `inventory`.

- [ ] **Step 1: Write failing integration test** (real server; agent enrolls, goes online, obeys a ping, then revoke stops it)

`internal/agent/runner/runner_test.go`:
```go
package runner_test

import (
	"bytes"
	"context"
	"log/slog"
	"testing"
	"time"

	flv1 "freelocker/gen/freelocker/v1"
	"freelocker/internal/agent/agentpaths"
	"freelocker/internal/agent/executor"
	"freelocker/internal/agent/identity"
	"freelocker/internal/agent/inventory"
	"freelocker/internal/agent/runner"
	"freelocker/internal/agent/secret"
	"freelocker/internal/server/app"
	"freelocker/internal/server/config"
	"freelocker/internal/server/store/storetest"

	"github.com/google/uuid"
)

type noopActions struct{ rotate func(context.Context) error }

func (noopActions) RefreshInventory(context.Context) error       { return nil }
func (n noopActions) RotateCertificate(ctx context.Context) error { return n.rotate(ctx) }
func (noopActions) Uninstall(context.Context) error              { return nil }
func (noopActions) UpdateAgent(context.Context, *flv1.Command) error { return nil }

func TestRunnerEnrollsOnlineCommandAndRevoke(t *testing.T) {
	ctx := context.Background()
	cfg := config.Config{AgentListen: "127.0.0.1:0", PublicHostnames: []string{"127.0.0.1"}, InsecureCookies: true}
	a, err := app.NewWithStore(cfg, storetest.New(t), bytes.Repeat([]byte{7}, 32), slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	if _, err := a.Initialize(ctx, "Acme", "o@example.com", "owner-password-123"); err != nil {
		t.Fatal(err)
	}
	token, err := a.TokenForTests(ctx)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	st := &identity.Store{Paths: agentpaths.Paths{InstallDir: dir, DataDir: dir}, Protector: secret.Default()}
	r := &runner.Runner{
		ServerURL: a.AgentAddr(), Identity: st, Inventory: inventory.New(),
		Executor: &executor.Executor{Actions: noopActions{rotate: func(context.Context) error { return nil }}},
		HeartbeatInterval: 150 * time.Millisecond,
	}
	if err := r.EnsureEnrolled(ctx, token, runner.HardwareInfo(inventory.New())); err != nil {
		t.Fatal(err)
	}
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- r.Run(runCtx) }()

	enr, _ := st.Load()
	devID := uuid.MustParse(enr.DeviceID)
	tenant := mustTenant(t, a)
	eventually(t, "online", func() bool {
		d, _ := a.Store().GetDevice(ctx, tenant, devID)
		return d.Status(time.Now()) == "online"
	})

	a.Store().RevokeDevice(ctx, tenant, devID)
	a.Hub().Disconnect(devID, agentRevoked())
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("runner should stop with an error after revoke")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("runner did not stop after revoke")
	}
	cancel()
}
```
This test needs small server accessors. Add them in Step 2.

- [ ] **Step 2: Add server test accessors**

In `internal/server/app/app.go` add:
```go
// Store exposes the underlying store (tests and CLI recovery).
func (a *App) Store() *store.Store { return a.store }

// Hub exposes the connection hub (tests).
func (a *App) Hub() *hub.Hub { return a.hub }

// Tenant returns the initialized tenant id (tests).
func (a *App) Tenant() (uuid.UUID, bool) {
	rt := a.runtime()
	if rt == nil {
		return uuid.Nil, false
	}
	return rt.Keys.TenantID, true
}
```
Add imports `"freelocker/internal/server/hub"` (already imported) and `"github.com/google/uuid"`. Then add to the runner test file:
```go
func mustTenant(t *testing.T, a *app.App) uuid.UUID {
	t.Helper()
	id, ok := a.Tenant()
	if !ok {
		t.Fatal("not initialized")
	}
	return id
}
func agentRevoked() error { return agentapi.RevokedError() }
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(30 * time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}
```
and imports `"freelocker/internal/server/agentapi"`.

- [ ] **Step 3: Run — expect FAIL**

Run: `go test ./internal/agent/runner/`

- [ ] **Step 4: Implement runner**

`internal/agent/runner/runner.go`:
```go
// Package runner is the agent's main control loop: enroll, connect,
// heartbeat, obey commands, renew, and reconnect.
package runner

import (
	"context"
	"log/slog"
	"math/rand/v2"
	"time"

	flv1 "freelocker/gen/freelocker/v1"
	"freelocker/internal/agent/executor"
	"freelocker/internal/agent/identity"
	"freelocker/internal/agent/inventory"
	"freelocker/internal/server/ca"
	"freelocker/internal/server/commands"
	"freelocker/internal/sim"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

type Runner struct {
	ServerURL         string
	Identity          *identity.Store
	Inventory         inventory.Collector
	Executor          *executor.Executor
	HeartbeatInterval time.Duration
	Log               *slog.Logger
	Clock             func() time.Time
}

func HardwareInfo(c inventory.Collector) *flv1.HardwareInfo {
	inv := c.Collect()
	return &flv1.HardwareInfo{Hostname: inv.GetHostname(), OsBuild: inv.GetOsBuild()}
}

func (r *Runner) log() *slog.Logger {
	if r.Log != nil {
		return r.Log
	}
	return slog.Default()
}

func (r *Runner) now() time.Time {
	if r.Clock != nil {
		return r.Clock()
	}
	return time.Now()
}

func (r *Runner) EnsureEnrolled(ctx context.Context, token string, hw *flv1.HardwareInfo) error {
	if r.Identity.Enrolled() {
		return nil
	}
	_, err := r.Identity.Enroll(ctx, r.ServerURL, token, hw)
	return err
}

func (r *Runner) Run(ctx context.Context) error {
	attempt := 0
	for {
		err := r.session(ctx, func() { attempt = 0 })
		if ctx.Err() != nil {
			return nil
		}
		if status.Code(err) == codes.Unauthenticated {
			r.log().Error("server rejected agent; stopping", "err", err)
			return err
		}
		d := sim.Backoff(attempt, rand.Float64)
		attempt++
		r.log().Warn("disconnected; will retry", "err", err, "in", d)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(d):
		}
	}
}

func (r *Runner) session(ctx context.Context, connected func()) error {
	l, err := r.Identity.Load()
	if err != nil {
		return err
	}
	if time.Until(l.CertNotAfter) < ca.RenewAfter {
		if err := r.Identity.Renew(ctx, r.ServerURL, l); err != nil {
			r.log().Warn("certificate renewal failed", "err", err)
		} else if l, err = r.Identity.Load(); err != nil {
			return err
		}
	}
	tlsCfg, err := l.TLSConfig()
	if err != nil {
		return err
	}
	conn, err := grpc.NewClient(r.ServerURL, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	if err != nil {
		return err
	}
	defer conn.Close()
	stream, err := flv1.NewAgentClient(conn).Connect(ctx)
	if err != nil {
		return err
	}
	if err := r.heartbeat(stream); err != nil {
		return err
	}
	connected()

	recv := make(chan *flv1.ServerMessage, 16)
	recvErr := make(chan error, 1)
	go func() {
		for {
			m, err := stream.Recv()
			if err != nil {
				recvErr <- err
				return
			}
			recv <- m
		}
	}()

	tick := time.NewTicker(r.HeartbeatInterval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			stream.Send(&flv1.AgentMessage{Body: &flv1.AgentMessage_Goodbye{Goodbye: &flv1.Goodbye{Reason: "shutdown"}}})
			stream.CloseSend()
			return ctx.Err()
		case err := <-recvErr:
			return err
		case <-tick.C:
			if err := r.heartbeat(stream); err != nil {
				return err
			}
		case m := <-recv:
			if sc := m.GetCommand(); sc != nil {
				r.handleCommand(ctx, stream, l, sc)
			}
		}
	}
}

func (r *Runner) heartbeat(stream flv1.Agent_ConnectClient) error {
	return stream.Send(&flv1.AgentMessage{Body: &flv1.AgentMessage_Heartbeat{Heartbeat: &flv1.Heartbeat{
		Inventory: r.Inventory.Collect(), SentAtUnix: r.now().Unix(),
	}}})
}

func (r *Runner) handleCommand(ctx context.Context, stream flv1.Agent_ConnectClient, l *identity.Loaded, sc *flv1.SignedCommand) {
	cmd, err := commands.Verify(l.CommandPub, sc, l.DeviceID, r.now())
	if err != nil {
		r.log().Warn("rejected command", "err", err)
		return
	}
	res := r.Executor.Run(ctx, cmd)
	if err := stream.Send(&flv1.AgentMessage{Body: &flv1.AgentMessage_CommandResult{CommandResult: res}}); err != nil {
		r.log().Warn("send command result", "err", err)
	}
}
```

- [ ] **Step 5: Run — expect PASS**

Run: `go test ./internal/agent/runner/ ./internal/server/app/`

- [ ] **Step 6: Commit**

```powershell
git add internal/agent/runner internal/server/app
git commit -m "feat(agent): add runner control loop and server test accessors"
```

---

### Task 7: Release hosting (server) and UpdateAgent payload

**Files:**
- Create: `internal/server/store/releases.go`, `internal/server/httpapi/releases.go`, `internal/server/commands/update.go`
- Modify: `internal/server/httpapi/routes.go` (register release routes)
- Test: `internal/server/store/releases_test.go`, `internal/server/httpapi/releases_test.go`, `internal/server/commands/update_test.go`

**Interfaces:**
- Produces:
  - `store.Release{Version string; SHA256, Signature []byte; UploadedAt time.Time}`; `(*Store).PutRelease(ctx, tenantID, r) error`; `(*Store).GetRelease(ctx, tenantID, version) (Release, error)`; `(*Store).LatestRelease(ctx, tenantID) (Release, error)` (ErrNotFound if none).
  - Binaries are stored on disk under a server `releaseDir`, named `<version>.exe`; the DB row holds the hash+signature. `httpapi.API` gains `ReleaseDir string`.
  - `commands.UpdatePayload{Version, URL string; SHA256, Signature []byte}`; `commands.MarshalUpdate(p) []byte`; `commands.ParseUpdate(b) (UpdatePayload, error)`; `(*Service).IssueUpdate(ctx, tenantID, deviceID uuid.UUID, p UpdatePayload, actor string) (uuid.UUID, error)`.
  - Endpoints: `POST /api/releases` (owner; multipart: `version`, `file`) signs with `Keys.UpdateKey`, stores file+row, 201 `{version, sha256}`; `GET /api/releases` (readonly) lists; `GET /agent/releases/{version}` (no auth, on the console listener) streams the binary (integrity is the agent's hash+sig check).

- [ ] **Step 1: Write failing update-payload test**

`internal/server/commands/update_test.go`:
```go
package commands

import "testing"

func TestUpdatePayloadRoundtrip(t *testing.T) {
	p := UpdatePayload{Version: "1.2.3", URL: "https://s/agent/releases/1.2.3", SHA256: []byte("hash"), Signature: []byte("sig")}
	got, err := ParseUpdate(MarshalUpdate(p))
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != p.Version || got.URL != p.URL || string(got.SHA256) != "hash" || string(got.Signature) != "sig" {
		t.Fatalf("roundtrip = %+v", got)
	}
	if _, err := ParseUpdate([]byte("{bad")); err == nil {
		t.Error("bad json must fail")
	}
}
```

- [ ] **Step 2: Run — expect FAIL**

Run: `go test ./internal/server/commands/ -run TestUpdatePayload`

- [ ] **Step 3: Implement update payload**

`internal/server/commands/update.go`:
```go
package commands

import (
	"context"
	"encoding/json"

	flv1 "freelocker/gen/freelocker/v1"

	"github.com/google/uuid"
)

type UpdatePayload struct {
	Version   string `json:"version"`
	URL       string `json:"url"`
	SHA256    []byte `json:"sha256"`
	Signature []byte `json:"signature"`
}

func MarshalUpdate(p UpdatePayload) []byte {
	b, _ := json.Marshal(p)
	return b
}

func ParseUpdate(b []byte) (UpdatePayload, error) {
	var p UpdatePayload
	err := json.Unmarshal(b, &p)
	return p, err
}

func (s *Service) IssueUpdate(ctx context.Context, tenantID, deviceID uuid.UUID, p UpdatePayload, actor string) (uuid.UUID, error) {
	return s.Issue(ctx, tenantID, deviceID, flv1.CommandType_COMMAND_TYPE_UPDATE_AGENT, MarshalUpdate(p), nil, actor)
}
```

- [ ] **Step 4: Run — expect PASS**

Run: `go test ./internal/server/commands/ -run TestUpdatePayload`

- [ ] **Step 5: Write failing store test**

`internal/server/store/releases_test.go`:
```go
package store_test

import (
	"context"
	"errors"
	"testing"

	"freelocker/internal/server/store"
	"freelocker/internal/server/store/storetest"
)

func TestReleases(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	tenant, _ := s.CreateTenant(ctx, "Acme")

	if _, err := s.LatestRelease(ctx, tenant); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("empty latest err = %v", err)
	}
	for _, v := range []string{"1.0.0", "1.2.0"} {
		if err := s.PutRelease(ctx, tenant, store.Release{Version: v, SHA256: []byte("h" + v), Signature: []byte("s")}); err != nil {
			t.Fatal(err)
		}
	}
	r, err := s.GetRelease(ctx, tenant, "1.0.0")
	if err != nil || string(r.SHA256) != "h1.0.0" {
		t.Fatalf("get = %+v, %v", r, err)
	}
	latest, err := s.LatestRelease(ctx, tenant)
	if err != nil || latest.Version != "1.2.0" {
		t.Fatalf("latest = %+v, %v", latest, err)
	}
	// PutRelease upserts.
	if err := s.PutRelease(ctx, tenant, store.Release{Version: "1.0.0", SHA256: []byte("new"), Signature: []byte("s2")}); err != nil {
		t.Fatal(err)
	}
	r, _ = s.GetRelease(ctx, tenant, "1.0.0")
	if string(r.SHA256) != "new" {
		t.Errorf("upsert failed: %s", r.SHA256)
	}
}
```

- [ ] **Step 6: Run — expect FAIL**

Run: `go test ./internal/server/store/ -run TestReleases`

- [ ] **Step 7: Implement release store**

`internal/server/store/releases.go`:
```go
package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type Release struct {
	Version    string
	SHA256     []byte
	Signature  []byte
	UploadedAt time.Time
}

func (s *Store) PutRelease(ctx context.Context, tenantID uuid.UUID, r Release) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO agent_releases (tenant_id, version, sha256, signature, uploaded_at)
		VALUES ($1, $2, $3, $4, now())
		ON CONFLICT (tenant_id, version) DO UPDATE SET sha256 = EXCLUDED.sha256, signature = EXCLUDED.signature, uploaded_at = now()`,
		tenantID, r.Version, r.SHA256, r.Signature)
	return err
}

func (s *Store) GetRelease(ctx context.Context, tenantID uuid.UUID, version string) (Release, error) {
	var r Release
	err := s.pool.QueryRow(ctx, `SELECT version, sha256, signature, uploaded_at FROM agent_releases WHERE tenant_id = $1 AND version = $2`,
		tenantID, version).Scan(&r.Version, &r.SHA256, &r.Signature, &r.UploadedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	return r, err
}

func (s *Store) LatestRelease(ctx context.Context, tenantID uuid.UUID) (Release, error) {
	var r Release
	err := s.pool.QueryRow(ctx, `SELECT version, sha256, signature, uploaded_at FROM agent_releases WHERE tenant_id = $1 ORDER BY uploaded_at DESC LIMIT 1`,
		tenantID).Scan(&r.Version, &r.SHA256, &r.Signature, &r.UploadedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	return r, err
}

func (s *Store) ListReleases(ctx context.Context, tenantID uuid.UUID) ([]Release, error) {
	rows, _ := s.pool.Query(ctx, `SELECT version, sha256, signature, uploaded_at FROM agent_releases WHERE tenant_id = $1 ORDER BY uploaded_at DESC`, tenantID)
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Release, error) {
		var rel Release
		return rel, r.Scan(&rel.Version, &rel.SHA256, &rel.Signature, &rel.UploadedAt)
	})
}
```

Update the migration so `agent_releases` has the needed columns and PK. In `internal/server/store/migrations/0001_init.sql` replace the `agent_releases` block with:
```sql
CREATE TABLE agent_releases (
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    version text NOT NULL,
    sha256 bytea NOT NULL,
    signature bytea NOT NULL,
    uploaded_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, version)
);
```
(The 1a migration created a placeholder `agent_releases`; since 1a is merged and no production data exists, editing 0001 is acceptable. If a deployed DB already exists, add `0002_releases.sql` instead — note this in the commit.)

- [ ] **Step 8: Run — expect PASS**

Run: `go test ./internal/server/store/ -run TestReleases`

- [ ] **Step 9: Implement HTTP release endpoints and wire routes**

`internal/server/httpapi/releases.go`:
```go
package httpapi

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"freelocker/internal/server/store"

	"github.com/go-chi/chi/v5"
)

func (a *API) uploadRelease(w http.ResponseWriter, r *http.Request) {
	if a.ReleaseDir == "" {
		writeErr(w, http.StatusServiceUnavailable, "release hosting not configured")
		return
	}
	if err := r.ParseMultipartForm(64 << 20); err != nil {
		writeErr(w, http.StatusBadRequest, "expected multipart form with version and file")
		return
	}
	version := strings.TrimSpace(r.FormValue("version"))
	if version == "" || strings.ContainsAny(version, `/\..`) {
		writeErr(w, http.StatusBadRequest, "version is required and must be a plain version string")
		return
	}
	file, _, err := r.FormFile("file")
	if err != nil {
		writeErr(w, http.StatusBadRequest, "file is required")
		return
	}
	defer file.Close()

	if err := os.MkdirAll(a.ReleaseDir, 0o755); err != nil {
		writeErr(w, http.StatusInternalServerError, "could not create release dir")
		return
	}
	dst := filepath.Join(a.ReleaseDir, version+".exe")
	out, err := os.Create(dst)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not write release")
		return
	}
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(out, h), file); err != nil {
		out.Close()
		writeErr(w, http.StatusInternalServerError, "could not store release")
		return
	}
	out.Close()
	sum := h.Sum(nil)
	sig := ed25519.Sign(a.Runtime().Keys.UpdateKey, sum)

	p := principalFrom(r)
	if err := a.Store.PutRelease(r.Context(), p.TenantID, store.Release{Version: version, SHA256: sum, Signature: sig, UploadedAt: time.Now()}); err != nil {
		a.storeErr(w, err)
		return
	}
	a.audit(r, p, "release.upload", "release", version, map[string]any{"sha256_hex": toHex(sum)}, "success")
	writeJSON(w, http.StatusCreated, map[string]string{"version": version, "sha256": toHex(sum)})
}

func (a *API) listReleases(w http.ResponseWriter, r *http.Request) {
	rels, err := a.Store.ListReleases(r.Context(), principalFrom(r).TenantID)
	if err != nil {
		a.storeErr(w, err)
		return
	}
	out := make([]map[string]any, 0, len(rels))
	for _, rel := range rels {
		out = append(out, map[string]any{"version": rel.Version, "sha256": toHex(rel.SHA256), "uploaded_at": rel.UploadedAt})
	}
	writeJSON(w, http.StatusOK, out)
}

// downloadRelease is unauthenticated; the agent verifies hash + signature.
func (a *API) downloadRelease(w http.ResponseWriter, r *http.Request) {
	version := chi.URLParam(r, "version")
	if a.ReleaseDir == "" || strings.ContainsAny(version, `/\..`) {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	f, err := os.Open(filepath.Join(a.ReleaseDir, version+".exe"))
	if err != nil {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	io.Copy(w, f)
}

func toHex(b []byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = hexdigits[v>>4]
		out[i*2+1] = hexdigits[v&0xf]
	}
	return string(out)
}

var _ = errors.Is // keep errors imported if unused after edits
```

In `internal/server/httpapi/api.go` add `ReleaseDir string` to the `API` struct, and register the download route (unauthenticated) inside `Handler()` before the session groups:
```go
	r.Get("/agent/releases/{version}", a.downloadRelease)
```
In `internal/server/httpapi/routes.go`, inside the `requireRole("admin")` group add `r.Get("/api/releases", a.listReleases)` (readonly is fine too — put the GET in the readonly section) and inside a new `requireRole("owner")`-adjacent section add `r.Post("/api/releases", a.uploadRelease)`. Concretely: add `r.Get("/api/releases", a.listReleases)` next to the other readonly GETs, and `r.Post("/api/releases", a.uploadRelease)` in the owner group.

- [ ] **Step 10: Write failing HTTP test**

`internal/server/httpapi/releases_test.go`:
```go
package httpapi_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"mime/multipart"
	"net/http"
	"testing"
)

func TestReleaseUploadAndDownload(t *testing.T) {
	e := newEnv(t)
	c := e.initialized(t)

	body := &bytes.Buffer{}
	mw := multipart.NewWriter(body)
	mw.WriteField("version", "1.0.0")
	fw, _ := mw.CreateFormFile("file", "agent.exe")
	payload := []byte("fake-agent-binary")
	fw.Write(payload)
	mw.Close()

	req, _ := http.NewRequest("POST", c.base+"/api/releases", body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("X-CSRF-Token", c.csrf)
	resp, err := c.http.Do(req)
	if err != nil || resp.StatusCode != 201 {
		t.Fatalf("upload = %v %v", resp.StatusCode, err)
	}
	resp.Body.Close()

	sum := sha256.Sum256(payload)
	// The server signs the hash with the update key; the agent (Task 8)
	// verifies it. Here we just confirm the download bytes match the hash.
	dl, err := c.http.Get(c.base + "/agent/releases/1.0.0")
	if err != nil || dl.StatusCode != 200 {
		t.Fatalf("download = %v %v", dl.StatusCode, err)
	}
	got, _ := io.ReadAll(dl.Body)
	dl.Body.Close()
	if gotSum := sha256.Sum256(got); gotSum != sum {
		t.Errorf("downloaded bytes hash mismatch")
	}
	_ = ed25519.PublicKey{}
	_ = hex.EncodeToString
}
```
Note: `newEnv` must set `ReleaseDir`. In `helpers_test.go`, add `ReleaseDir: t.TempDir()` to the `httpapi.API{...}` literal.

- [ ] **Step 11: Run — expect PASS**

Run: `go test ./internal/server/...`

- [ ] **Step 12: Commit**

```powershell
git add internal/server/store/releases.go internal/server/store/releases_test.go internal/server/store/migrations internal/server/httpapi/releases.go internal/server/httpapi/releases_test.go internal/server/httpapi/api.go internal/server/httpapi/routes.go internal/server/httpapi/helpers_test.go internal/server/commands/update.go internal/server/commands/update_test.go
git commit -m "feat(server): add agent release hosting and UpdateAgent payload"
```

---

### Task 8: Updater — download, verify, swap, rollback

**Files:**
- Create: `internal/agent/updater/updater.go`, `cmd/agent-updater/main.go`
- Test: `internal/agent/updater/updater_test.go`

**Interfaces:**
- Consumes: `commands.UpdatePayload`, enrolled update public key, `agentpaths`.
- Produces:
  - `updater.Download(ctx, url string, wantSHA256 []byte) ([]byte, error)` — HTTP GET, verify SHA-256.
  - `updater.Verify(pub ed25519.PublicKey, sha256sum, signature []byte) error`.
  - `updater.Stage(dir string, bin []byte) (path string, err error)` — writes `<dir>/freelocker-agent.new.exe` (0755).
  - `updater.Plan{CurrentExe, NewExe, UpdaterExe, ServiceName string}` and `(Plan).SwapArgs() []string` — the arguments the running agent passes to `agent-updater` to perform stop→backup→replace→start→verify-heartbeat→rollback.
  - `cmd/agent-updater`: a tiny separate process that performs the swap so the file being replaced is not the running image. Verb: `agent-updater swap -service <name> -current <path> -new <path>`; on failure to see the service healthy within 2 min, restores `<path>.bak` and restarts.

- [ ] **Step 1: Write failing test** (download + verify are pure and testable)

`internal/agent/updater/updater_test.go`:
```go
package updater

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDownloadVerifiesHash(t *testing.T) {
	payload := []byte("new-agent-binary")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(payload) }))
	defer srv.Close()
	sum := sha256.Sum256(payload)

	got, err := Download(context.Background(), srv.URL, sum[:])
	if err != nil || string(got) != string(payload) {
		t.Fatalf("Download = %q, %v", got, err)
	}
	if _, err := Download(context.Background(), srv.URL, []byte("wrong-hash-32-bytes-xxxxxxxxxxxx")); err == nil {
		t.Error("hash mismatch must fail")
	}
}

func TestVerifySignature(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sum := sha256.Sum256([]byte("x"))
	sig := ed25519.Sign(priv, sum[:])
	if err := Verify(pub, sum[:], sig); err != nil {
		t.Fatalf("valid sig rejected: %v", err)
	}
	if err := Verify(pub, sum[:], []byte("bad")); err == nil {
		t.Error("bad sig must fail")
	}
}

func TestStageWritesExecutable(t *testing.T) {
	p, err := Stage(t.TempDir(), []byte("bin"))
	if err != nil {
		t.Fatal(err)
	}
	if p == "" {
		t.Fatal("empty staged path")
	}
}
```

- [ ] **Step 2: Run — expect FAIL**

Run: `go test ./internal/agent/updater/`

- [ ] **Step 3: Implement updater**

`internal/agent/updater/updater.go`:
```go
// Package updater downloads, verifies, and stages agent updates. The
// actual binary swap is performed by the separate cmd/agent-updater
// process so the running image is not being replaced under itself.
package updater

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
)

func Download(ctx context.Context, url string, wantSHA256 []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download: status %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 256<<20))
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(b)
	if !bytes.Equal(sum[:], wantSHA256) {
		return nil, errors.New("downloaded binary hash mismatch")
	}
	return b, nil
}

func Verify(pub ed25519.PublicKey, sha256sum, signature []byte) error {
	if len(pub) != ed25519.PublicKeySize {
		return errors.New("bad update public key")
	}
	if !ed25519.Verify(pub, sha256sum, signature) {
		return errors.New("update signature invalid")
	}
	return nil
}

func Stage(dir string, bin []byte) (string, error) {
	path := filepath.Join(dir, "freelocker-agent.new.exe")
	if err := os.WriteFile(path, bin, 0o755); err != nil {
		return "", err
	}
	return path, nil
}

type Plan struct {
	CurrentExe  string
	NewExe      string
	UpdaterExe  string
	ServiceName string
}

func (p Plan) SwapArgs() []string {
	return []string{"swap", "-service", p.ServiceName, "-current", p.CurrentExe, "-new", p.NewExe}
}
```

`cmd/agent-updater/main.go`:
```go
// Command agent-updater replaces the FreeLocker agent binary out of band
// and rolls back if the new build does not become healthy.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"time"
)

func main() {
	if len(os.Args) < 2 || os.Args[1] != "swap" {
		fmt.Fprintln(os.Stderr, "usage: agent-updater swap -service <name> -current <path> -new <path>")
		os.Exit(2)
	}
	fs := flag.NewFlagSet("swap", flag.ExitOnError)
	service := fs.String("service", "FreeLockerAgent", "service name")
	current := fs.String("current", "", "path to the installed agent exe")
	newExe := fs.String("new", "", "path to the downloaded new exe")
	fs.Parse(os.Args[2:])
	if *current == "" || *newExe == "" {
		fmt.Fprintln(os.Stderr, "current and new are required")
		os.Exit(2)
	}
	if err := swap(*service, *current, *newExe); err != nil {
		fmt.Fprintln(os.Stderr, "swap failed:", err)
		os.Exit(1)
	}
}

func swap(service, current, newExe string) error {
	backup := current + ".bak"
	sc := func(args ...string) error { return exec.Command("sc.exe", args...).Run() }

	sc("stop", service)
	waitStopped(service, 30*time.Second)

	os.Remove(backup)
	if err := os.Rename(current, backup); err != nil {
		return fmt.Errorf("backup current: %w", err)
	}
	if err := os.Rename(newExe, current); err != nil {
		os.Rename(backup, current) // restore
		sc("start", service)
		return fmt.Errorf("install new: %w", err)
	}
	if err := sc("start", service); err != nil {
		return rollback(service, current, backup, fmt.Errorf("start new: %w", err))
	}
	if healthy(service, 2*time.Minute) {
		os.Remove(backup)
		return nil
	}
	return rollback(service, current, backup, fmt.Errorf("new agent did not become healthy"))
}

func rollback(service, current, backup string, cause error) error {
	exec.Command("sc.exe", "stop", service).Run()
	waitStopped(service, 30*time.Second)
	os.Remove(current)
	if err := os.Rename(backup, current); err != nil {
		return fmt.Errorf("%v; ALSO rollback failed: %w", cause, err)
	}
	exec.Command("sc.exe", "start", service).Run()
	return cause
}

// healthy is a placeholder for a real health probe; the running agent
// writes a heartbeat marker file when it connects. See runner wiring.
func healthy(service string, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if serviceRunning(service) {
			return true
		}
		time.Sleep(3 * time.Second)
	}
	return false
}

func serviceRunning(service string) bool {
	out, err := exec.Command("sc.exe", "query", service).Output()
	return err == nil && containsRunning(out)
}

func containsRunning(b []byte) bool {
	return len(b) > 0 && (indexOf(b, "RUNNING") >= 0)
}

func indexOf(b []byte, s string) int {
	for i := 0; i+len(s) <= len(b); i++ {
		if string(b[i:i+len(s)]) == s {
			return i
		}
	}
	return -1
}

func waitStopped(service string, d time.Duration) {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if !serviceRunning(service) {
			return
		}
		time.Sleep(1 * time.Second)
	}
}
```
Note: `agent-updater` uses only `os/exec` + `sc.exe`, so it compiles on any OS (the tool is only run on Windows). Health here is "service reports RUNNING"; a stricter heartbeat-marker probe can be added later.

- [ ] **Step 4: Run — expect PASS**

Run: `go test ./internal/agent/updater/`; `go build ./cmd/agent-updater`

- [ ] **Step 5: Commit**

```powershell
git add internal/agent/updater cmd/agent-updater
git commit -m "feat(agent): add updater (download/verify/stage) and swap helper"
```

---

### Task 9: Windows service, actions wiring, and CLI

**Files:**
- Create: `internal/agent/service/service_windows.go`, `internal/agent/service/service_other.go`, `internal/agent/actions/actions.go`, `cmd/agent/main.go`
- Test: `internal/agent/actions/actions_test.go`

**Interfaces:**
- Consumes: everything above; `svc`, `eventlog`, `mgr` from `golang.org/x/sys/windows`.
- Produces:
  - `actions.Actions{Runner *runner.Runner; Identity *identity.Store; Paths agentpaths.Paths; UpdatePub func() ed25519.PublicKey; UninstallHash func() []byte; ServerURL string; Log *slog.Logger; requestStop context.CancelFunc}` implementing `executor.Actions`:
    - `RefreshInventory` → send an immediate heartbeat (via a channel the runner exposes) — for v1, no-op returning nil (heartbeat cadence is 30 s; flagged).
    - `RotateCertificate` → `identity.Renew`.
    - `Uninstall` → run `agent-updater`-independent uninstall: stop+delete service and remove data (delegated to `actions.Uninstaller`, injected; on Windows spawns `cmd/agent uninstall -force-fromserver`).
    - `UpdateAgent` → parse payload, `updater.Download`+`Verify`+`Stage`, then launch `agent-updater swap ...` detached and return nil (the swap stops this service).
  - `service.Run(ctx, r *runner.Runner) error` — Windows: `svc.Run` with start/stop handling + eventlog; other OS: just `r.Run(ctx)` (console mode).
  - CLI verbs in `cmd/agent`: `run` (service or console), `install-service`, `uninstall [-code <code>]`, `version`.

- [ ] **Step 1: Write failing actions test** (UpdateAgent verify path, portable)

`internal/agent/actions/actions_test.go`:
```go
package actions

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"testing"

	flv1 "freelocker/gen/freelocker/v1"
	"freelocker/internal/server/commands"
)

func TestUpdateAgentRejectsBadSignature(t *testing.T) {
	payload := []byte("agent-bytes")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(payload) }))
	defer srv.Close()
	sum := sha256.Sum256(payload)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	_, wrongPriv, _ := ed25519.GenerateKey(rand.Reader)

	a := &Actions{
		UpdatePub: func() ed25519.PublicKey { return pub },
		StageOnly: true, // test hook: stop before launching the swap helper
	}
	cmd := &flv1.Command{Type: flv1.CommandType_COMMAND_TYPE_UPDATE_AGENT,
		Payload: commands.MarshalUpdate(commands.UpdatePayload{
			URL: srv.URL, Version: "9.9.9", SHA256: sum[:], Signature: ed25519.Sign(wrongPriv, sum[:]),
		})}
	if err := a.UpdateAgent(context.Background(), cmd); err == nil {
		t.Fatal("update with wrong signature must fail")
	}
}
```

- [ ] **Step 2: Run — expect FAIL**

Run: `go test ./internal/agent/actions/`

- [ ] **Step 3: Implement actions**

`internal/agent/actions/actions.go`:
```go
// Package actions implements executor.Actions for the real agent.
package actions

import (
	"context"
	"crypto/ed25519"
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"

	flv1 "freelocker/gen/freelocker/v1"
	"freelocker/internal/agent/agentpaths"
	"freelocker/internal/agent/identity"
	"freelocker/internal/agent/updater"
	"freelocker/internal/server/commands"
)

type Actions struct {
	Identity  *identity.Store
	Paths     agentpaths.Paths
	ServerURL string
	UpdatePub func() ed25519.PublicKey
	Log       *slog.Logger

	// Renew is injected by the service so RotateCertificate reuses the
	// runner's server URL and loaded identity.
	Renew func(ctx context.Context) error
	// Uninstaller performs stop+delete+cleanup (Windows implementation
	// injected by the service; nil elsewhere).
	Uninstaller func(ctx context.Context) error

	// StageOnly stops UpdateAgent before launching the swap helper (tests).
	StageOnly bool
}

func (a *Actions) log() *slog.Logger {
	if a.Log != nil {
		return a.Log
	}
	return slog.Default()
}

func (a *Actions) RefreshInventory(ctx context.Context) error { return nil }

func (a *Actions) RotateCertificate(ctx context.Context) error {
	if a.Renew == nil {
		return errors.New("renew not wired")
	}
	return a.Renew(ctx)
}

func (a *Actions) Uninstall(ctx context.Context) error {
	if a.Uninstaller == nil {
		return errors.New("uninstall not supported in this build")
	}
	return a.Uninstaller(ctx)
}

func (a *Actions) UpdateAgent(ctx context.Context, cmd *flv1.Command) error {
	p, err := commands.ParseUpdate(cmd.GetPayload())
	if err != nil {
		return err
	}
	bin, err := updater.Download(ctx, p.URL, p.SHA256)
	if err != nil {
		return err
	}
	if err := updater.Verify(a.UpdatePub(), p.SHA256, p.Signature); err != nil {
		return err
	}
	staged, err := updater.Stage(a.Paths.InstallDir, bin)
	if err != nil {
		return err
	}
	if a.StageOnly {
		return nil
	}
	current, err := os.Executable()
	if err != nil {
		return err
	}
	plan := updater.Plan{
		CurrentExe: current, NewExe: staged, ServiceName: "FreeLockerAgent",
		UpdaterExe: filepath.Join(a.Paths.InstallDir, "agent-updater.exe"),
	}
	cmdExec := exec.Command(plan.UpdaterExe, plan.SwapArgs()...)
	if err := cmdExec.Start(); err != nil {
		return err
	}
	a.log().Info("update staged; swap helper launched", "version", p.Version)
	return nil // the swap helper will stop this service
}
```

`internal/agent/service/service_other.go`:
```go
//go:build !windows

package service

import (
	"context"

	"freelocker/internal/agent/runner"
)

// Run executes the agent in the foreground on non-Windows platforms.
func Run(ctx context.Context, r *runner.Runner) error { return r.Run(ctx) }
```

`internal/agent/service/service_windows.go`:
```go
//go:build windows

package service

import (
	"context"

	"freelocker/internal/agent/runner"

	"golang.org/x/sys/windows/svc"
)

const Name = "FreeLockerAgent"

type handler struct {
	runner *runner.Runner
}

// Run runs as a Windows service if launched by the SCM, else in console mode.
func Run(ctx context.Context, r *runner.Runner) error {
	isService, err := svc.IsWindowsService()
	if err != nil {
		return err
	}
	if !isService {
		return r.Run(ctx)
	}
	return svc.Run(Name, &handler{runner: r})
}

func (h *handler) Execute(args []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown
	status <- svc.Status{State: svc.StartPending}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { h.runner.Run(ctx); close(done) }()
	status <- svc.Status{State: svc.Running, Accepts: accepted}

	for {
		select {
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
				<-done
				return false, 0
			}
		case <-done:
			return false, 0
		}
	}
}
```

`cmd/agent/main.go`:
```go
// Command freelocker-agent is the endpoint agent: a Windows service that
// enrolls with the server and enforces policy. It also runs in the
// foreground for development on any OS.
package main

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"os"
	"os/signal"
	"time"

	"freelocker/internal/agent/actions"
	"freelocker/internal/agent/agentpaths"
	"freelocker/internal/agent/config"
	"freelocker/internal/agent/executor"
	"freelocker/internal/agent/identity"
	"freelocker/internal/agent/inventory"
	"freelocker/internal/agent/runner"
	"freelocker/internal/agent/secret"
	"freelocker/internal/agent/service"
	"freelocker/internal/agent/version"

	"log/slog"
)

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	verb := "run"
	if len(os.Args) > 1 {
		verb = os.Args[1]
	}
	switch verb {
	case "version":
		fmt.Println(version.Version)
	case "run":
		if err := runAgent(log); err != nil {
			log.Error("agent exited", "err", err)
			os.Exit(1)
		}
	case "install-service", "uninstall":
		if err := manage(verb, os.Args[2:], log); err != nil {
			log.Error(verb+" failed", "err", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintln(os.Stderr, "usage: freelocker-agent [run|install-service|uninstall|version]")
		os.Exit(2)
	}
}

func runAgent(log *slog.Logger) error {
	paths := agentpaths.Default()
	cfg, err := config.Load(paths.Config())
	if err != nil {
		return err
	}
	st := &identity.Store{Paths: paths, Protector: secret.Default()}
	inv := inventory.New()
	r := &runner.Runner{
		ServerURL: cfg.ServerURL, Identity: st, Inventory: inv,
		HeartbeatInterval: 30 * time.Second, Log: log,
	}
	act := &actions.Actions{
		Identity: st, Paths: paths, ServerURL: cfg.ServerURL, Log: log,
		UpdatePub: func() ed25519.PublicKey {
			l, err := st.Load()
			if err != nil {
				return nil
			}
			return ed25519.PublicKey(l.UpdatePub)
		},
		Renew: func(ctx context.Context) error {
			l, err := st.Load()
			if err != nil {
				return err
			}
			return st.Renew(ctx, cfg.ServerURL, l)
		},
		Uninstaller: uninstaller(paths),
	}
	r.Executor = &executor.Executor{Actions: act, Log: log}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	if !st.Enrolled() {
		if cfg.Token == "" {
			return fmt.Errorf("not enrolled and no token in %s", paths.Config())
		}
		if err := r.EnsureEnrolled(ctx, cfg.Token, runner.HardwareInfo(inv)); err != nil {
			return err
		}
		log.Info("enrolled")
	}
	return service.Run(ctx, r)
}
```
Note: `manage` (install-service/uninstall) and `uninstaller` are Windows-specific — implement in Task 10's service-management file. Provide non-Windows stubs so `go build` works on the dev machine:

`cmd/agent/manage_other.go`:
```go
//go:build !windows

package main

import (
	"context"
	"errors"
	"log/slog"

	"freelocker/internal/agent/agentpaths"
)

func manage(string, []string, *slog.Logger) error {
	return errors.New("service management is only available on Windows")
}

func uninstaller(agentpaths.Paths) func(context.Context) error { return nil }
```

- [ ] **Step 4: Run — expect PASS; build for both OSes**

Run: `go test ./internal/agent/actions/`
Run: `go build ./cmd/agent` (dev machine)
Run: `$env:GOOS='windows'; go build -o bin/freelocker-agent.exe ./cmd/agent; $env:GOOS=''` (already Windows here, but confirms the windows-tagged files compile)

- [ ] **Step 5: Commit**

```powershell
git add internal/agent/actions internal/agent/service cmd/agent
git commit -m "feat(agent): add actions, Windows service wrapper, and CLI"
```

---

### Task 10: Windows service management, self-protection, MSI, and manual test doc

**Files:**
- Create: `cmd/agent/manage_windows.go`, `internal/agent/hardening/hardening_windows.go`, `internal/agent/hardening/hardening_other.go`, `deploy/msi/Package.wxs`, `deploy/msi/build.ps1`, `docs/agent-manual-test.md`
- Test: `internal/agent/hardening/hardening_test.go` (portable no-op assertions)

**Interfaces:**
- Produces:
  - `hardening.SecureDataDir(dir string) error` — Windows: set ACLs to SYSTEM+Administrators (via `icacls`); other: no-op nil.
  - `hardening.ConfigureRecovery(service string) error` — Windows: `sc failure <svc> reset= 86400 actions= restart/5000/restart/5000/restart/5000`; other: no-op.
  - `cmd/agent` Windows `manage`: `install-service` (create service via `mgr`, set recovery, secure data dir, start), `uninstall [-code <code>]` (verify code SHA-256 against enrollment unless `-force-fromserver`, then stop+delete service, remove data dir).
  - MSI: per-machine, properties `SERVERURL` and `TOKEN`, writes `config.yaml`, installs `freelocker-agent.exe` + `agent-updater.exe`, registers+starts the service, ACLs the data dir. Silent: `msiexec /i FreeLocker.msi /qn SERVERURL=... TOKEN=...`.

- [ ] **Step 1: Write portable hardening test**

`internal/agent/hardening/hardening_test.go`:
```go
package hardening

import "testing"

func TestNoopsOffWindowsSucceed(t *testing.T) {
	// On non-Windows these are no-ops; on Windows they invoke icacls/sc.
	// Either way they must not panic and must return nil for a temp dir.
	if err := SecureDataDir(t.TempDir()); err != nil {
		t.Errorf("SecureDataDir: %v", err)
	}
}
```

- [ ] **Step 2: Run — expect FAIL** (package doesn't exist)

Run: `go test ./internal/agent/hardening/`

- [ ] **Step 3: Implement hardening (both tags)**

`internal/agent/hardening/hardening_other.go`:
```go
//go:build !windows

package hardening

func SecureDataDir(dir string) error      { return nil }
func ConfigureRecovery(service string) error { return nil }
```

`internal/agent/hardening/hardening_windows.go`:
```go
//go:build windows

package hardening

import (
	"fmt"
	"os/exec"
)

// SecureDataDir restricts the data directory to SYSTEM and Administrators.
func SecureDataDir(dir string) error {
	// Reset inheritance, grant SYSTEM and Administrators full control only.
	steps := [][]string{
		{dir, "/inheritance:r"},
		{dir, "/grant:r", "SYSTEM:(OI)(CI)F"},
		{dir, "/grant:r", "Administrators:(OI)(CI)F"},
	}
	for _, args := range steps {
		if out, err := exec.Command("icacls", args...).CombinedOutput(); err != nil {
			return fmt.Errorf("icacls %v: %v (%s)", args, err, out)
		}
	}
	return nil
}

func ConfigureRecovery(service string) error {
	out, err := exec.Command("sc.exe", "failure", service,
		"reset=", "86400", "actions=", "restart/5000/restart/5000/restart/5000").CombinedOutput()
	if err != nil {
		return fmt.Errorf("sc failure: %v (%s)", err, out)
	}
	return nil
}
```

- [ ] **Step 4: Run — expect PASS**

Run: `go test ./internal/agent/hardening/`

- [ ] **Step 5: Implement Windows service management**

`cmd/agent/manage_windows.go`:
```go
//go:build windows

package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"freelocker/internal/agent/agentpaths"
	"freelocker/internal/agent/hardening"
	"freelocker/internal/agent/identity"
	"freelocker/internal/agent/secret"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const serviceName = "FreeLockerAgent"

func manage(verb string, args []string, log *slog.Logger) error {
	switch verb {
	case "install-service":
		return installService()
	case "uninstall":
		fs := flag.NewFlagSet("uninstall", flag.ExitOnError)
		code := fs.String("code", "", "uninstall code from the console")
		force := fs.Bool("force-fromserver", false, "skip code check (server-driven uninstall)")
		fs.Parse(args)
		return uninstall(*code, *force)
	default:
		return fmt.Errorf("unknown verb %q", verb)
	}
}

func installService() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	if s, err := m.OpenService(serviceName); err == nil {
		s.Close()
		return fmt.Errorf("service %s already installed", serviceName)
	}
	s, err := m.CreateService(serviceName, exe, mgr.Config{
		DisplayName: "FreeLocker Agent", StartType: mgr.StartAutomatic, Description: "FreeLocker endpoint agent.",
	}, "run")
	if err != nil {
		return err
	}
	defer s.Close()

	paths := agentpaths.Default()
	if err := hardening.SecureDataDir(paths.DataDir); err != nil {
		return err
	}
	if err := hardening.ConfigureRecovery(serviceName); err != nil {
		return err
	}
	return s.Start()
}

func uninstall(code string, force bool) error {
	paths := agentpaths.Default()
	if !force {
		st := &identity.Store{Paths: paths, Protector: secret.Default()}
		enr, err := st.Load()
		if err != nil {
			return fmt.Errorf("cannot verify uninstall code: %w", err)
		}
		sum := sha256.Sum256([]byte(code))
		if subtle.ConstantTimeCompare(sum[:], enr.UninstallHash) != 1 {
			return fmt.Errorf("incorrect uninstall code")
		}
	}
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err == nil {
		defer s.Close()
		s.Control(svc.Stop)
		waitStopped(s, 30*time.Second)
		s.Delete()
	}
	return os.RemoveAll(paths.DataDir)
}

func waitStopped(s *mgr.Service, d time.Duration) {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if st, err := s.Query(); err == nil && st.State == svc.Stopped {
			return
		}
		time.Sleep(time.Second)
	}
}

// uninstaller returns a func the running service uses to remove itself on
// a server Uninstall command (bypasses the code check).
func uninstaller(paths agentpaths.Paths) func(context.Context) error {
	return func(context.Context) error {
		exe := filepath.Join(paths.InstallDir, "freelocker-agent.exe")
		return startDetached(exe, "uninstall", "-force-fromserver")
	}
}

func startDetached(exe string, args ...string) error {
	// A separate process performs stop+delete so the service can exit first.
	return exec.Command(exe, args...).Start()
}
```
Add `"os/exec"` to imports. Remove the non-Windows `uninstaller`/`manage` collision by keeping `manage_other.go` (Task 9) `//go:build !windows`.

- [ ] **Step 6: Author the WiX package and build script**

`deploy/msi/Package.wxs`:
```xml
<Wix xmlns="http://wixtoolset.org/schemas/v4/wxs">
  <Package Name="FreeLocker Agent" Manufacturer="FreeLocker" Version="0.1.0.0"
           UpgradeCode="7B3F5B1E-9C4D-4E2A-9F2B-1A2B3C4D5E6F" Scope="perMachine">
    <MajorUpgrade DowngradeErrorMessage="A newer version is already installed." />
    <MediaTemplate EmbedCab="yes" />

    <Property Id="SERVERURL" Secure="yes" />
    <Property Id="TOKEN" Secure="yes" />

    <StandardDirectory Id="ProgramFiles64Folder">
      <Directory Id="INSTALLDIR" Name="FreeLocker" />
    </StandardDirectory>
    <StandardDirectory Id="CommonAppDataFolder">
      <Directory Id="DATADIR" Name="FreeLocker" />
    </StandardDirectory>

    <ComponentGroup Id="Files" Directory="INSTALLDIR">
      <Component Id="AgentExe" Guid="*">
        <File Id="AgentExe" Source="freelocker-agent.exe" KeyPath="yes" />
        <ServiceInstall Id="AgentSvc" Name="FreeLockerAgent" DisplayName="FreeLocker Agent"
                        Type="ownProcess" Start="auto" ErrorControl="normal" Account="LocalSystem"
                        Description="FreeLocker endpoint agent." Arguments="run">
          <ServiceConfig OnInstall="yes" OnReinstall="yes" DelayedAutoStart="no" />
        </ServiceInstall>
        <ServiceControl Id="AgentSvcCtl" Name="FreeLockerAgent" Start="install" Stop="both" Remove="uninstall" Wait="yes" />
      </Component>
      <Component Id="UpdaterExe" Guid="*">
        <File Id="UpdaterExe" Source="agent-updater.exe" KeyPath="yes" />
      </Component>
    </ComponentGroup>

    <Component Id="ConfigFile" Directory="DATADIR" Guid="*">
      <File Id="ConfigYaml" Source="config.yaml" KeyPath="yes" />
    </Component>

    <Feature Id="Main">
      <ComponentGroupRef Id="Files" />
      <ComponentRef Id="ConfigFile" />
    </Feature>
  </Package>
</Wix>
```
Note: writing `config.yaml` with the SERVERURL/TOKEN values is done by `build.ps1` staging a templated file per build, or via a small custom action. For v1, `build.ps1` writes `config.yaml` from the `SERVERURL`/`TOKEN` passed to the build; silent-install-time substitution via a custom action is a follow-up (flagged). The simplest correct path: the MSI lays down an empty `config.yaml`, and a `CAConfig` custom action writes SERVERURL/TOKEN at install time — implemented as a deferred exec of `freelocker-agent` `write-config`. To keep this task shippable, add a `write-config` verb:

In `cmd/agent/main.go` add a `write-config` case calling a small helper that reads `SERVERURL`/`TOKEN` from args and calls `config.Write`. Then in `Package.wxs` add:
```xml
      <CustomAction Id="WriteConfig" Directory="INSTALLDIR" ExeCommand="[INSTALLDIR]freelocker-agent.exe write-config -server &quot;[SERVERURL]&quot; -token &quot;[TOKEN]&quot;" Execute="deferred" Impersonate="no" Return="check" />
      <InstallExecuteSequence>
        <Custom Action="WriteConfig" Before="StartServices" Condition="SERVERURL" />
      </InstallExecuteSequence>
```

`deploy/msi/build.ps1`:
```powershell
param([string]$Version = "0.1.0")
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$stage = Join-Path $env:TEMP "fl-msi-stage"
Remove-Item -Recurse -Force $stage -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $stage | Out-Null

$env:GOOS = "windows"; $env:GOARCH = "amd64"
& go build -ldflags "-s -w -X freelocker/internal/agent/version.Version=$Version" -o (Join-Path $stage "freelocker-agent.exe") "$root/cmd/agent"
& go build -ldflags "-s -w" -o (Join-Path $stage "agent-updater.exe") "$root/cmd/agent-updater"
"" | Set-Content (Join-Path $stage "config.yaml")   # placeholder; filled by WriteConfig custom action

Copy-Item "$root/deploy/msi/Package.wxs" $stage
Push-Location $stage
& wix build Package.wxs -o (Join-Path $root "bin/FreeLocker.msi")
Pop-Location
Write-Host "Built bin/FreeLocker.msi (version $Version)"
```

- [ ] **Step 7: Write the manual test checklist**

`docs/agent-manual-test.md`:
```markdown
# Agent manual test (Windows VM)

Prereqs: a Windows VM that can reach the server's agent port; the server
running with a reachable `public_hostnames` entry; an install token and
the device's uninstall code from the console.

1. **Build the MSI:** on the dev box run `deploy/msi/build.ps1 -Version 0.1.0`. Copy `bin/FreeLocker.msi` to the VM.
2. **Silent install:** `msiexec /i FreeLocker.msi /qn SERVERURL=fl.example.com:8443 TOKEN=<token> /l*v install.log`
3. **Service running:** `sc query FreeLockerAgent` shows RUNNING. `C:\ProgramData\FreeLocker\config.yaml` has the URL; `enrollment.json`, `device.crt`, `device.key`, `ca.crt` exist.
4. **Online in console within 60 s.** Inventory shows the VM hostname, OS build, IPs.
5. **Data dir ACL:** `icacls C:\ProgramData\FreeLocker` lists only SYSTEM and Administrators.
6. **Recovery:** `sc qfailure FreeLockerAgent` shows three restart actions.
7. **Command:** issue Ping from the console → succeeds within seconds.
8. **Kill test:** `taskkill /f /im freelocker-agent.exe` → service restarts within ~5 s; device returns to online (console shows "unexpected_offline" briefly).
9. **Cert renewal:** (optional, clock-advance) not part of the smoke test.
10. **Self-update:** upload a new build via `POST /api/releases`; issue UpdateAgent; the service swaps to the new version and reports the new version in inventory; a deliberately broken build rolls back within 2 minutes.
11. **Uninstall needs code:** `freelocker-agent uninstall` → refused; `freelocker-agent uninstall -code <wrong>` → refused; `-code <correct>` → service removed, data dir gone.
12. **Server-driven uninstall:** issue Uninstall from the console → agent removes itself.
13. **Revoke:** revoke the device → live stream drops and the agent stops retrying (Event Log entry).
```

- [ ] **Step 8: Build everything for Windows and vet**

Run:
```powershell
go vet ./...
go build -o bin/freelocker-agent.exe ./cmd/agent
go build -o bin/agent-updater.exe ./cmd/agent-updater
go test ./...
```
Expected: vet clean, both agent binaries build, all tests pass.

- [ ] **Step 9: Build the MSI (if WiX present)**

Run: `deploy/msi/build.ps1 -Version 0.1.0`
Expected: `bin/FreeLocker.msi` produced. (Requires the WiX v5 CLI; if the build environment lacks it, skip and note in the commit — the MSI is verified on the VM.)

- [ ] **Step 10: Commit**

```powershell
git add cmd/agent internal/agent/hardening deploy/msi docs/agent-manual-test.md
git commit -m "feat(agent): add service management, self-protection, and MSI packaging"
```

---

## Spec coverage (sub-project #1, agent side)

| Spec section | Covered by |
|---|---|
| §4 enrollment (keypair, DPAPI, CSR, mTLS thereafter) | Tasks 2, 3 |
| §5 stream, 30 s heartbeat, inventory, commands, reconnect/backoff, skew | Tasks 4, 6 |
| §6 90-day certs, auto-renew at 60 days, key sealing | Tasks 2, 3, 6 |
| §7 uninstall code, self-protection ACLs, service recovery, updates+rollback | Tasks 8, 9, 10 |
| §7 MSI silent install (SERVER_URL/TOKEN via GPO/Intune) | Task 10 |
| §12 success criteria 2 (MSI → online in 60 s) and 4 (update + rollback) | Task 10 manual checklist |

## Deferred / flagged

- `RefreshInventory` command currently no-ops (heartbeat cadence is 30 s); wire an immediate-heartbeat channel later if needed.
- MSI config injection uses a `write-config` custom action; a fully declarative approach can replace it later.
- EV code-signing of the MSI and the agent binaries is out of scope here (needed before the WDAC/kernel work in later sub-projects and for production trust).
