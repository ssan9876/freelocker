# Sub-project #2 — Application Control (WDAC allowlisting) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Default-deny application allowlisting managed from the console: admins build policies of allow rules (by SHA-256 hash, code signer/publisher, or path), assign them to device groups, and the agent enforces them through Windows Defender Application Control (WDAC). A learning mode records the applications a device actually runs so admins can build a baseline, and blocked/would-be-blocked launches are reported back.

**Architecture:** Server owns policies and rules, compiles them to a WDAC SiPolicy XML document, versions them, and resolves the effective policy for each device (by group). The agent pulls its assigned policy over a new gRPC call, applies it through an `Enforcer` interface, and reports observed applications (learning) and block events. `WDACEnforcer` (Windows) writes and activates the policy with `CiTool`; a `NoopEnforcer` is used off-Windows and in tests. **Every policy defaults to audit mode** (WDAC logs would-be blocks and blocks nothing); enforce mode is an explicit per-policy choice, and live activation is a manual VM procedure — never run against the dev machine.

**Tech Stack:** Go 1.27, the existing proto/gRPC, `golang.org/x/sys/windows` (Authenticode via WinVerifyTrust/wintrust, CodeIntegrity event log via the Windows Event Log API or `wevtutil`), WDAC (`CiTool.exe`, `ConvertFrom-CIPolicy`), the existing React console.

**Spec:** `docs/superpowers/specs/2026-09-10-core-platform-design.md` (roadmap item 2)

**Depends on:** sub-project #1 (all merged).

## Global Constraints

- Module `freelocker`; Go floor 1.27. Windows-only source uses `//go:build windows` with a `!windows` sibling.
- Every table carries `tenant_id`; every store call takes `tenantID` first after `ctx`.
- Policies default to `mode = "audit"`. `mode = "enforce"` is explicit. The agent never activates a policy whose mode it cannot honor safely; on any apply error it stays on the last-known-good policy.
- WDAC XML is generated deterministically (stable ordering) so identical rule sets produce byte-identical policy and a stable content hash → version.
- The server signs the compiled policy bytes with the existing `UpdateKey` (reused as policy-signing key); the agent verifies before applying.
- Hash rules are SHA-256 (hex, upper-case in WDAC). Publisher rules identify a signer by certificate TBS hash + optional publisher name. Path rules are Windows paths, optionally with a trailing `\*` wildcard.
- Learning observations and block events are TimescaleDB-friendly plain rows for now (hypertables deferred to sub-project #3).
- Test DB: `deploy/docker-compose.dev.yml` on `localhost:55432`; Docker running.
- Live WDAC activation, Authenticode verification of real binaries, and CodeIntegrity log parsing are verified on a Windows VM (audit mode), documented in `docs/appcontrol-manual-test.md`. Automated tests cover the model, the compiler, the protocol, the scanner's hashing, and event parsing on sample data — never live enforcement.

## Deliberate scope decisions (flag to reviewer)

1. **WDAC XML is v1/best-effort for Windows acceptance.** Tests assert structure (skeleton, rule options, allow entries, audit toggle), not that `ConvertFrom-CIPolicy` accepts it — that is the VM step. Path- and publisher-rule fidelity may need iteration on a VM.
2. **Policy delivery is a pull** (`GetPolicy` RPC) driven by a `policy_version` field the agent puts in its heartbeat, rather than a pushed command — simpler and idempotent.
3. **Learning mode = process/binary observation**, not full CodeIntegrity audit ingestion: the agent enumerates running executables, hashes and (best-effort) resolves their signer, and reports them. Full audit-log ingestion for learning is folded into block-event reading.
4. **Enforce activation stays opt-in and manual** this sub-project; the console can set a policy to enforce, but the manual-test doc is the only place enforcement is actually turned on, on a VM.

## File Structure

```
internal/appcontrol/wdac/wdac.go            SiPolicy XML model + compiler + content hash
internal/appcontrol/rules/rules.go          rule kinds, validation, normalization
internal/server/store/policies.go           policies, rules, assignments, versions
internal/server/store/observations.go       learning observations + block events
internal/server/policysvc/policysvc.go      compile+version+sign+resolve effective policy
internal/server/httpapi/policies.go         policy/rule/assignment/learning/blocks endpoints
internal/server/agentapi/policy.go          GetPolicy RPC + heartbeat policy_version
internal/agent/enforcer/enforcer.go         Enforcer interface + NoopEnforcer
internal/agent/enforcer/wdac_windows.go     WDACEnforcer (CiTool, audit default)
internal/agent/scan/scan.go                 observed-app scanner (hash + signer)
internal/agent/scan/authenticode_windows.go real signer resolution
internal/agent/blocks/blocks_windows.go     CodeIntegrity event reader
internal/agent/blocks/blocks.go             BlockEvent type + parser (portable)
proto/freelocker/v1/agent.proto             + GetPolicy, PolicyResponse, ObserveRequest, ReportBlocks (modify)
web/src/pages/{Policies,PolicyDetail,Learning,Blocks}.tsx   console (modify nav)
docs/appcontrol-manual-test.md              VM audit-mode verification
```

## Tasks

Each task is TDD (failing test → implement → pass) and ends in a commit. Full code lives in the repo; this list is the roadmap and the interface contract.

### Task 1 — `internal/appcontrol/rules`: rule kinds, validation, normalization
- `rules.Kind` = `hash|publisher|path`; `rules.Rule{Kind, Value, PublisherName, Description}`.
- `rules.Normalize(r) (Rule, error)`: upper-case + validate 64-hex for `hash`; require non-empty TBS-hex (64) for `publisher`; validate a Windows path (optionally trailing `\*`) for `path`. Reject unknown kinds / malformed values.
- Tests: valid/invalid for each kind; normalization is idempotent.

### Task 2 — `internal/appcontrol/wdac`: SiPolicy compiler + content hash
- `wdac.Policy{Mode ("audit"|"enforce"), Rules []rules.Rule}`; `wdac.Compile(p) ([]byte, error)` → deterministic SiPolicy XML (stable rule ordering, upper-case hashes). Audit mode adds the `Enabled:Audit Mode` rule option; enforce omits it. Hash/path → `<Allow>` FileRules; publisher → `<Signer>` + Allow signer ref; all referenced from a single SigningScenario.
- `wdac.ContentHash(xml []byte) string` (SHA-256 hex) → the policy version id.
- Tests: audit toggle present/absent by mode; every hash appears once upper-cased; identical rule sets (any input order) compile byte-identical; empty policy still valid skeleton (deny-all).

### Task 3 — `internal/server/store/policies.go` (+ migration `0003_appcontrol.sql`)
- Tables: `policies(id, tenant_id, name, mode, created_at)`, `policy_rules(id, policy_id, tenant_id, kind, value, publisher_name, description, added_by, created_at)`, `policy_versions(policy_id, tenant_id, version, xml bytea, signature bytea, created_at)`, `policy_assignments(tenant_id, group_id PK, policy_id)`.
- CRUD: CreatePolicy, ListPolicies, GetPolicy, SetPolicyMode, DeletePolicy; AddRule, ListRules, DeleteRule; PutPolicyVersion, GetPolicyVersion, LatestPolicyVersion; AssignPolicy, EffectivePolicyForDevice(deviceID) (via group).
- Tests: CRUD, tenant isolation, assignment resolution, version upsert.

### Task 4 — `internal/server/store/observations.go`
- `observations` (learning) `(tenant_id, device_id, sha256, path, signer, first_seen, last_seen, count)` upsert by (device, sha256, path); `block_events(tenant_id, device_id, sha256, path, signer, blocked bool, at)`.
- RecordObservation (upsert), ListObservations(tenant, filters), PromoteToRule helper is in policysvc; RecordBlockEvents (batch), ListBlockEvents.
- Tests: upsert increments count + bumps last_seen; block events list newest-first; tenant isolation.

### Task 5 — `internal/server/policysvc`
- `policysvc.Service{Store, Keys}`: `Recompile(ctx, tenantID, policyID)` → compile rules, `PutPolicyVersion` with content-hash version + Ed25519 signature (UpdateKey); `Effective(ctx, deviceID)` → latest signed version for the device's assigned policy (or a default deny-all policy when unassigned).
- Tests: recompile produces a version + valid signature; changing rules changes the version; unassigned device gets the deny-all default.

### Task 6 — proto + Agent `GetPolicy` RPC + heartbeat `policy_version`
- proto: add `Inventory.policy_version`; `GetPolicyRequest{}`→`GetPolicyResponse{version, mode, xml, signature}`; regenerate.
- `agentapi/policy.go`: `GetPolicy` returns the device's effective policy (auth'd like the rest of the Agent service); record heartbeat `policy_version` on the device row (migration adds `devices.policy_version text`).
- Tests: enrolled sim calls GetPolicy, gets the assigned policy's version + verifiable signature; heartbeat updates the stored policy_version.

### Task 7 — `internal/server/httpapi/policies.go`
- Endpoints (readonly GET / admin mutate): policies CRUD, rules add/list/delete, mode set, assign to group, recompile; learning: list observations, promote observation→rule; blocks: list. Wire routes; add `ReleaseDir`-style nothing new.
- Tests: full policy lifecycle over HTTP; promote observation creates a rule and recompiles; RBAC (readonly can't mutate).

### Task 8 — `internal/agent/enforcer`
- `enforcer.Enforcer` iface: `Apply(ctx, mode string, xml []byte) error`, `Events(ctx) ([]blocks.BlockEvent, error)`, `Status() enforcer.Status`. `NoopEnforcer` (records last applied; used off-Windows/tests). `wdac_windows.go` `WDACEnforcer`: writes `.cip` to CodeIntegrity active dir and runs `CiTool --update-policy` (audit default); never enforces unless mode=="enforce" AND an explicit opt-in file/flag is present.
- Tests (portable): Noop records applied mode+version; Apply rejects unknown mode.

### Task 9 — `internal/agent/scan` + `internal/agent/blocks`
- `scan.Observed{SHA256, Path, Signer}`; `scan.HashFile(path)`; `scan.Running() ([]Observed, error)` (portable: enumerate processes via gopsutil-free `os` + `/proc` or Windows Toolhelp; signer resolution Windows-only, empty elsewhere).
- `blocks.BlockEvent{SHA256, Path, Signer, Blocked, At}`; `blocks.ParseCodeIntegrity(xml []byte) ([]BlockEvent, error)` (parses `wevtutil` XML sample); Windows reader shells `wevtutil qe`.
- Tests: HashFile matches a known SHA-256; ParseCodeIntegrity extracts events from a captured sample.

### Task 10 — runner wiring + integration test
- Runner: on connect and every N min, call `GetPolicy`; if version changed, verify signature and `enforcer.Apply`; put applied version in heartbeat. Periodically `scan.Running` → `Observe` RPC; drain `enforcer.Events` → `ReportBlocks` RPC. Add those two RPCs (or fold into existing stream messages) — implement as unary Agent RPCs `Observe` and `ReportBlocks`.
- Integration test: real server + sim-like agent using NoopEnforcer: assign a policy, agent pulls+applies it (version recorded), reports an observation (appears in store), reports a block event (appears in store).

### Task 11 — console pages
- `Policies` (list, create, mode toggle, assign to group), `PolicyDetail` (rules list, add hash/publisher/path rule, delete, recompile, show version), `Learning` (observations table, "Add as rule"), `Blocks` (block events table). Add nav items. API client types.
- Verify: `npm run build`; manual smoke.

### Task 12 — manual VM doc + finalize
- `docs/appcontrol-manual-test.md`: build a policy in audit mode, assign to the VM's group, confirm the agent pulls+writes it, `CiTool` shows it active, run a blocked app, confirm an audit block event appears in the console; then (VM only) flip to enforce and confirm the app is actually blocked; recovery steps.
- `go vet ./...`, full `go test ./...`, `npm run build`. Commit.

## Deferred
- TimescaleDB hypertables for observations/blocks → sub-project #3.
- Real-time allow/deny prompts → sub-project #5 (kernel driver).
- WDAC XML fidelity for exotic rule types; supplemental policies; signed policy activation with reboot.
