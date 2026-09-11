# Application control manual test (Windows VM)

WDAC can lock a machine out of software. **Do all of this on a disposable
Windows VM**, never a machine you rely on. Every policy starts in **audit
mode** (logs would-be blocks, blocks nothing); enforce is a deliberate,
separate step with a documented recovery path.

Prereqs: the server running and reachable; the VM enrolled (see
`docs/agent-manual-test.md`) and appearing online in the console; the VM is
Windows 11 / Server 2022+ (has `CiTool.exe`).

## Audit mode (safe)

1. **Create a policy** in the console (Policies → Create). It starts in audit mode.
2. **Populate it from learning.** Open the VM's device page; under *Observed applications*, pick the policy and *Add as rule* for the apps the VM legitimately runs. Or add hash/publisher/path rules directly on the policy page.
3. **Assign** the policy to the VM's group (Policies list → assign to group).
4. **Confirm the agent applied it.** Within ~5 min the device's heartbeat shows the policy version; on the VM:
   - `C:\ProgramData\FreeLocker\policy.xml` and `policy.cip` exist.
   - `CiTool --list-policies` lists the FreeLocker base policy `{A244370E-…}` as active, **Audit** enforcement.
5. **Generate an audit event.** Run an application that is *not* allowed. It still runs (audit mode). Within a minute the console's *Blocked programs* page shows it as "Would block (audit)".
6. **Review** the block events and add any legitimately-needed apps as rules until the audit list is clean.

## Enforce mode (VM only, has a recovery path)

1. On the VM, create the opt-in flag: `New-Item C:\ProgramData\FreeLocker\allow-enforce`. Without this file the agent keeps a policy in audit even if the console says enforce — a safety interlock.
2. In the console set the policy to **Enforce** and wait for the agent to apply it (device page shows the new version).
3. `CiTool --list-policies` now shows the policy as **Enforced**.
4. Run a disallowed app: it is blocked. The *Blocked programs* page shows it as "Blocked".
5. Run an allowed app: it launches normally.

### Recovery if enforce locks something out
- From the console, set the policy back to **Audit** (the agent re-applies within ~5 min), or **revoke** the device (it stops pulling policy).
- On the VM directly: delete `C:\ProgramData\FreeLocker\allow-enforce`, then remove the active policy with `CiTool --remove-policy {A244370E-44C9-4C06-B551-F6016E563076}` and reboot. WDAC base policies take effect/clear on reboot.
- Worst case: boot into recovery and delete `C:\Windows\System32\CodeIntegrity\CiPolicies\Active\*.cip`, then reboot.

## What automated tests already cover (so this doc stays short)
- Rule validation/normalization, deterministic WDAC XML + versioning, policy store/versioning/assignment, effective-policy resolution and signing, the GetPolicy/Observe/ReportBlocks RPCs, the console policy API, the enforcer interface, file hashing, CodeIntegrity XML parsing, and the full agent app-control loop (with a test enforcer).
- **Not** covered here: that Windows' `ConvertFrom-CIPolicy` accepts the generated XML and that `CiTool` activates it — that is exactly what steps 4–5 above verify. If `ConvertFrom-CIPolicy` rejects the XML, capture the error and iterate on `internal/appcontrol/wdac`.
