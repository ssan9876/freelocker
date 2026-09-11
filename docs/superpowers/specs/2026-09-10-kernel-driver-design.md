# Sub-project #5 — Kernel Driver Backend (Design)

**Status:** Design only. This component cannot be built or tested in the
current environment; it requires the Windows Driver Kit, kernel C/C++, an
EV code-signing certificate with Microsoft attestation signing,
test-signing mode, and a dedicated kernel-debugging VM. This document
specifies it and confirms the software seam it plugs into already exists.

## Why a driver (what WDAC doesn't give us)

Sub-projects #1–#2 enforce application control through WDAC, which decides
allow/deny in the Windows kernel from a policy compiled ahead of time.
That is robust but not *interactive*: it cannot pause a launch and ask an
admin "allow this program?" in real time, and policy changes take seconds
to apply. A FreeLocker kernel driver adds:

- **Real-time interception** of process creation (and optionally image
  load / script host activity).
- **Ringfencing** — allow an app to run but restrict what it can touch.
- **Interactive approval** — hold a launch, ask the server, and let an
  admin approve or deny it live, with the decision cached.

## The seam already exists

The agent defines `enforcer.Enforcer` (sub-project #1's design decision:
"enforcement sits behind a Go interface"):

```go
type Enforcer interface {
    Apply(ctx, version, mode string, xml []byte) error
    Events(ctx) ([]blocks.BlockEvent, error)
    Status() Status
}
```

`WDACEnforcer` implements it today. A `DriverEnforcer` implements the same
interface later — the runner, server, and protocol do not change. The
driver becomes an alternate (or additional) backend selected by
`enforcer.Default()`.

## Architecture

```
User mode (existing agent, SYSTEM service)
  DriverEnforcer  ── DeviceIoControl / FilterCommunicationPort ──┐
                                                                 ▼
Kernel mode (freelocker.sys, signed minifilter + callbacks)
  - PsSetCreateProcessNotifyRoutineEx2  → intercept process create
  - (optional) minifilter (FltRegisterFilter) for file ringfencing
  - (optional) image-load callback for DLL/driver control
  Decision: check local allow-cache (hash/signer/path) → allow;
            else block, and post an approval request to user mode.
```

### Decision flow
1. A process is about to start. The kernel callback computes/looks up its
   hash and signer and consults an in-kernel allow-cache derived from the
   same rules the server already compiles (hash/publisher/path).
2. **Cache hit (allow):** let it run.
3. **Cache miss:** in *enforce* mode, block the create and raise an
   approval request to the user-mode service; in *audit* mode, allow and
   log (as WDAC audit does today).
4. The service forwards the approval request to the server; an admin sees
   it in the console and approves or denies; the decision is cached (and
   can become a permanent rule).

### User-mode ↔ kernel comms
A `FltCommunicationPort` (or a control device + inverted-call IOCTLs): the
service posts the ruleset down and receives approval requests up. Requests
carry image path, hashes, and signer.

## What is buildable now, without the driver

The **interactive-approval workflow** — agent asks, admin approves in the
console, decision returns and can become a rule — is server/protocol/UI
work that does not require the kernel. It can be driven in the interim by
the WDAC audit events the agent already reports (a would-block becomes an
approval request). Recommended as the next increment; the driver later
just supplies faster, blocking interception.

Concretely, reusing existing pieces:
- `block_events` (audit would-blocks) already flow to the server.
- A new `approval_requests` table + `Approve`/`Deny` console actions +
  a `ResolveApproval` that appends the approved hash to a policy (the
  `promoteObservation` path already does exactly this).

## Signing & distribution requirements (the hard prerequisites)
- EV code-signing certificate (hardware token).
- Submission to the Microsoft Partner Center for **attestation signing**
  (or full WHQL) so the driver loads without test-signing on customer
  machines.
- The agent MSI (sub-project #1b) must install and register the driver
  and start it as a boot/system-start service.

## Testing story (why it's out of scope here)
- A Hyper-V/VMware VM with kernel debugging (WinDbg over a named pipe),
  Driver Verifier enabled, and test-signing mode for development builds.
- Bug-check (BSOD) risk means every change is exercised in the VM before
  any signed release. This is incompatible with the current CI/dev box.

## Recommendation
Ship the interactive-approval workflow on the existing WDAC-audit stream
first (fully buildable and testable), then implement `freelocker.sys` and
`DriverEnforcer` in a dedicated kernel-dev environment once an EV
certificate and attestation signing are in place.
