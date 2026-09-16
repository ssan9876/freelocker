# Ringfencing (network + child process) — design

**Status:** approved 2026-09-15.

## Goal

Constrain what an *allowed* application may do. Today an app-control rule is
binary: a hash, publisher or path rule lets a program run, and a program that
runs has the machine's full network and can spawn anything. Ringfencing adds
the second half — this program may run, *but* it may not reach the network,
and Office may not spawn a script interpreter.

Two dimensions ship here. File and registry containment are deliberately out
of scope: they need a file-system minifilter, which is sub-project 5
(`2026-09-10-kernel-driver-design.md`). There is no honest approximation with
ACLs, because ACLs are per-user, not per-application.

| Dimension | Mechanism | Per-application? | Native audit mode? |
|---|---|---|---|
| Network | Windows Firewall outbound rule, `program=` scoped | Yes, exact | No — see [Audit mode](#audit-mode) |
| Child process | Defender ASR rules, machine policy | No — machine-wide, with path exclusions | Yes (`AuditMode`) |
| File / registry | *(deferred to the kernel driver)* | — | — |

## Model

A **ringfence** is its own object assigned to a device group, mirroring how an
app-control policy is assigned. It is independent of the group's app-control
policy: a group may be WDAC-enforce while ringfence-audit, which is the normal
state while an admin learns which apps legitimately need the network.

The two dimensions have genuinely different shapes — firewall rules need a
program path, ASR rules are machine-wide toggles — so the ringfence holds both
rather than pretending they are the same thing.

### Tables — migration `0020_ringfencing.sql`

- `ringfence_policies` — `id`, `tenant_id`, `name`, `mode` (`audit|enforce`,
  **default `audit`**), `created_at`, `UNIQUE (tenant_id, name)`. Mirrors
  `policies`.
- `ringfence_programs` — `id`, `tenant_id`, `ringfence_id`
  (`ON DELETE CASCADE`), `path`, `network_blocked bool`, `note`.
  The per-application network dimension.
- `ringfence_protections` — `tenant_id`, `ringfence_id`, `asr_rule`, `action`
  (`off|audit|block`), PK `(ringfence_id, asr_rule)`. A row per exposed ASR
  GUID, so the curated set can grow without a migration per rule and each rule
  carries its own action.
- `ringfence_assignments` — `tenant_id`, `group_id` PK, `ringfence_id`.
  Mirrors `policy_assignments`: one ringfence per group.
- `ringfence_events` — `id bigserial`, `tenant_id`, `device_id`
  (`ON DELETE CASCADE`), `kind` (`network|child_process`), `program`,
  `detail`, `enforced bool`, `at`. Index `(tenant_id, at DESC)`.

`ringfence_events` is a separate table, **not** `block_events`. Block events
are execution-shaped (`sha256`/`path`/`signer`) and, more importantly, feed the
approvals queue — routing ringfence violations there would manufacture
approval requests to add hash rules, which is meaningless for "Chrome tried to
reach the internet".

### Exposed ASR rules

The curated set, all child-process / script-execution shaped:

| GUID | Blocks |
|---|---|
| `D4F940AB-401B-4EFC-AADC-AD5F3C50688A` | Office applications creating child processes |
| `3B576869-A4EC-4529-8536-B80A7769E899` | Office applications creating executable content |
| `D3E037E1-3EB8-44C8-A917-57927947596D` | JS/VBScript launching downloaded executable content |
| `5BEB7EFE-FD9A-4556-801D-275E5FFC04CC` | Execution of potentially obfuscated scripts |
| `92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B` | Win32 API calls from Office macros |
| `D1E49AAC-8F56-4280-B9BA-993A6D77406C` | Process creation from PSExec and WMI |

## Protocol

Additive, one new RPC pair (approach A — its own channel, like `GetControls`,
so ringfence mode stays independent of WDAC mode):

```proto
rpc GetRingfence(GetRingfenceRequest) returns (GetRingfenceResponse);
rpc ReportRingfenceEvents(ReportRingfenceEventsRequest) returns (ReportRingfenceEventsResponse);

message GetRingfenceResponse {
  string version = 1;                          // content hash; agent no-ops when unchanged
  string mode = 2;                             // audit | enforce
  repeated RingfenceProgram programs = 3;      // path, network_blocked
  repeated RingfenceProtection protections = 4;// asr_rule, action
}
```

`version` is a hash of the resolved content rather than a counter, so the
agent's reconcile is idempotent with no server-side version bookkeeping.

Like `GetControls`, the payload is unsigned and protected by mTLS. This is the
precedent the existing device controls already set: unblocking USB is no less
security-relevant than unblocking network.

## Agent — package `internal/agent/ringfence`

Shaped exactly like `internal/agent/controls`: a `Ringfence` value type, an
`Enforcer` interface (`Apply(ctx, Ringfence) error`,
`Violations(ctx) ([]Violation, error)`, `Status()`), a `NoopEnforcer` for
`!windows` and tests, and `ringfence_windows.go` behind the build tag.

### Network

Rules are named deterministically — `FreeLocker-RF-<sha256(path)[:16]>` — so
reconcile is a diff: enumerate existing `FreeLocker-RF-*` rules, add what is
missing, delete what is stale, no-op when the content hash is unchanged.

- **enforce:** `netsh advfirewall firewall add rule name=… dir=out action=block program="<path>"`
- **audit:** no rule is created at all.

Windows Firewall is deny-wins, so a ringfence block holds under the default
outbound-allow policy, and it composes harmlessly with the device-level
`NetworkBlocked` default-block (both blocked stays blocked).

### Child process

Machine policy at
`HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules`,
one value per GUID: `0` off, `1` block, `2` audit. Registry rather than
`Set-MpPreference`, to match the existing `setDWord` style in
`controls_windows.go` and because deleting the value is an exact revert.

**ASR is inert when Defender is not the active anti-virus.** `Status()`
therefore reports ASR availability (Defender service running, not in passive
mode), the agent sends it with the ringfence status, and the console shows
"not enforced — Defender inactive" rather than a green tick. A control that
silently does nothing is worse than one that admits it.

### Audit mode

Windows Firewall has no audit mode — a program block rule either exists and
blocks, or does not exist and allows. Audit is therefore synthesised from
Windows Filtering Platform connection auditing:

- `auditpol /set /subcategory:"Filtering Platform Connection" /success:enable`
- **audit:** read 5156 (connection allowed) filtered to ringfenced program
  paths. A ringfenced program connecting *is* the would-have-blocked signal;
  reported with `enforced = false`.
- **enforce:** read 5157 (connection blocked); reported with `enforced = true`.

ASR violations come from `Microsoft-Windows-Windows Defender/Operational`,
event 1121 (blocked) and 1122 (audited).

Both reuse the `wevtutil qe` + parse pattern already in
`internal/agent/events` (4688/4624).

**5156 is extremely noisy** — it fires for every outbound connection on the
machine. Three-layer mitigation, all required:

1. filter by `Application` matching a ringfenced path *before* parsing;
2. dedupe by `(program, remote IP, port)` within the reporting interval;
3. cap the batch size per report.

Without this, audit mode on a busy machine floods the tenant's event table.

## HTTP API (admin writes; reads any role)

- `GET|POST /api/ringfences`, `GET|PATCH|DELETE /api/ringfences/{id}`
  (`PATCH` covers rename and mode)
- `GET|POST /api/ringfences/{id}/programs`, `DELETE /api/ringfences/{id}/programs/{pid}`
- `PUT /api/ringfences/{id}/protections` — body `{asr_rule, action}`, upserts
  that one rule's action; `action: "off"` deletes the row
- `PUT /api/groups/{id}/ringfence` (assign), `DELETE` (unassign)
- `GET /api/ringfence-events`

Audited as `ringfence.create|update|delete|assign|unassign|program|protection`;
a mode change is audited distinctly from a rename, as policy mode changes are.

## Console

- `web/src/pages/Ringfences.tsx` — list, create, rename, delete, mode toggle.
- `web/src/pages/RingfenceDetail.tsx` — programs table, ASR protections with
  off/audit/block per rule, group assignment.
- A ringfence-events view, separate from the Blocks page: Blocks stays
  WDAC-specific, and only it feeds Approvals.
- `DeviceDetail` gains the device's effective ringfence and the ASR
  availability status.

## Safety

The project rule holds without exception:

- `mode` defaults to `audit` in the schema; enforce is an explicit switch.
- The agent **refuses** a ringfence whose program entries match its own image
  or the updater's, so ringfencing can never sever management. This is the
  direct analogue of the existing "refuse to block if the server will not
  resolve" rule in `controls_windows.go`.
- Unassigning reverts every `FreeLocker-RF-*` rule and every ASR value the
  agent set — the feature is fully reversible.
- Live enforcement is verified only on a disposable VM, per
  `docs/ringfence-manual-test.md` (new).

## Testing

| Layer | Covers | Runs |
|---|---|---|
| Parsers | 5156/5157 and Defender 1121/1122 against captured XML fixtures | Anywhere, incl. CI |
| Reconcile | applied rules + desired rules → adds/deletes; idempotent on unchanged hash | Anywhere |
| Store | CRUD, one-ringfence-per-group, effective resolution, cross-tenant isolation | Dev Postgres |
| HTTP | RBAC, `ringfence.*` audit entries, validation | Dev Postgres |
| Wire | `GetRingfence` + `ReportRingfenceEvents` via `internal/sim` | Dev Postgres |
| Console | create → add program → protection to audit → assign → enforce → delete | Playwright |
| VM only | that the firewall rule blocks, that ASR fires, that revert leaves no residue | Disposable VM |

**This feature ships unverified against a real endpoint**, exactly as WDAC and
device control did before their VM runs. The Go tests prove the model, the
API, the protocol and the parsers — not that Windows does what we asked. The
README status must say so rather than imply otherwise.

## Out of scope

- File and registry containment (kernel driver, sub-project 5).
- Per-application *allow* network rules — only containment (block) is
  modelled; an app not named in a ringfence is unaffected.
- Ringfence device-level overrides. Group assignment only for v1; the
  `device_control_overrides` pattern is available if it is wanted later.
