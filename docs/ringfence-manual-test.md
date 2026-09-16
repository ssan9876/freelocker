# Ringfence manual test (Windows VM)

**Do all of this on a disposable Windows VM, never a machine you rely on and
never the dev box.** Enforcing a ringfence adds real Windows Firewall rules
and writes real Defender ASR machine policy; a mistake here can cut off the
VM's own network or block software you need. Every ringfence starts in
**audit mode** (reports what would be blocked, blocks nothing); enforce is a
deliberate, separate step taken from the ringfence's detail page behind a
confirmation dialog.

Prereqs: the server running and reachable; the VM enrolled (see
`docs/agent-manual-test.md`) and appearing online in the console; the VM has
Windows Defender available (Microsoft Defender Antivirus, real-time
protection on) so ASR rules and network filtering can actually take effect.

## Network containment — audit (safe)

1. In the console, create a ringfence (Ringfences → name it, e.g. "curl
   test"). It starts in audit mode.
2. Add a program: path `C:\Windows\System32\curl.exe`, check **Network
   blocked**.
3. Assign the ringfence to the VM's group (ringfence detail page → Group
   assignment).
4. Wait for the agent to apply it (~5 min heartbeat). On the VM, run `curl
   https://example.com`. It must **succeed** — audit mode never blocks.
5. Within a minute a ringfence event appears in the console (or the
   device's event stream) for this program with `enforced = false` — i.e.
   "would have blocked."

## Network containment — enforce

6. On the ringfence detail page, switch **Ringfence mode** to Enforce. A
   confirmation dialog appears ("Switch to enforce?"); click **Switch to
   enforce** to complete it.
7. Wait for the agent to re-apply (~5 min). Re-run `curl
   https://example.com` on the VM. It must **fail** (blocked), and an event
   appears with `enforced = true`.
8. Confirm the agent's own connection to the server is unaffected — it must
   keep checking in and the device must stay online in the console while
   curl is blocked.

## Self-exclusion refusal

9. Try to ringfence the agent's own executable
   (`C:\Program Files\FreeLocker\freelocker-agent.exe`, or wherever it is
   installed) with network blocked, and assign it to the VM's group. The
   agent must refuse to apply this program's containment and log a message
   containing "refusing to ringfence the agent's own image" (check the
   agent's log, typically under `C:\ProgramData\FreeLocker`). The agent
   must keep working normally.

## Child-process containment — audit

10. On the same or a new ringfence, set the ASR rule "Office applications
    creating child processes" to **Audit**. Wait for the agent to apply it.
11. On the VM, have Word (or another Office app) run a macro that launches
    PowerShell (e.g. `Shell("powershell.exe")` from a VBA macro). It must
    **succeed** — PowerShell launches — and a `child_process` event appears
    with `enforced = false`.

## Child-process containment — block

12. Set the same rule to **Block**. Wait for the agent to re-apply.
13. Repeat the macro. PowerShell must **not** launch, and the event now
    shows `enforced = true`.

## Reversibility

14. Unassign the ringfence from the VM's group (ringfence detail page →
    Group assignment → Unassign), or delete the assignment entirely. Wait
    for the agent to reconcile (~5 min).
15. On the VM, confirm no FreeLocker firewall rules remain:
    `netsh advfirewall firewall show rule name=all | findstr FreeLocker-RF`
    must return nothing.
16. Confirm no leftover ASR policy values: check the ASR rule registry
    values under
    `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules`
    (or `Get-MpPreference | Select -Expand AttackSurfaceReductionRules_Ids`)
    — none of the six FreeLocker-managed rule GUIDs should remain set from
    this ringfence.

## Defender inactive

17. Disable Defender real-time protection on the VM (or otherwise take
    Defender out of an active state). Wait for the agent's next report.
18. The console must show **"not enforced — Defender inactive"** on the
    device for this ringfence/ASR status, not a green "enforced" tick. This
    confirms the console is honest about Defender's real state rather than
    assuming enforcement worked because the policy was sent.

## What this checklist does not cover

File and registry containment for ringfenced programs are **not**
implemented — they are part of sub-project 5 (the kernel driver) and have
no enforcement path yet. This checklist only exercises network and
child-process (ASR) containment.

## What automated tests already cover (so this doc stays short)

The ringfence data model, protocol, agent diffing, path/rule parsers, the
Windows firewall and ASR registry writers (mocked), the runner's
self-exclusion safety check, the HTTP API (CRUD, programs, protections,
mode, assignment, audit logging), and the console pages are all covered by
Go unit tests and the Playwright console flow (`web/e2e/smoke.spec.ts`).
Those tests prove the model, the API and the UI behave as designed — they
do **not** prove that Windows Firewall or Defender ASR actually contain
anything on a real machine. That is exactly what this checklist verifies.
