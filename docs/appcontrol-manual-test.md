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
5. **Generate an audit event.** Run a non-Microsoft application that is *not* allowed. It still runs (audit mode). Within a minute the console's *Blocked programs* page shows it as "Would block (audit)". Windows' own programs never appear there: every policy includes Microsoft's DefaultWindows baseline (Windows components, WHQL drivers, Store apps), so only third-party software needs rules.
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

## Publisher rules (the point: a rule that survives app updates)

A hash rule breaks the moment an application updates. A publisher rule allows
anything signed by the same code-signing certificate, so it keeps working.

1. **Run a signed third-party app** on the VM (something not covered by the
   Microsoft baseline — a portable tool signed by its vendor is ideal).
2. On the device page, under *Observed applications*, check the **Publisher**
   column. A signature Windows trusts shows the publisher's name; one it
   cannot verify shows "(unverified)", and an unsigned or catalog-signed file
   shows "—". Many Microsoft binaries are catalog-signed and show "—"; they
   are already allowed by the baseline, so that is expected.
3. **Allow the publisher:** pick the policy, then *Add as publisher*. The
   button is disabled unless Windows verified the signature — deliberately, so
   a forged or tampered signature can never become a rule.
4. On the policy page the new rule's kind is `publisher` and its value is a
   64-character certificate hash (**not** the file's hash), with the
   publisher's name beside it.
5. **Prove it survives an update:** run a *different* build signed by the same
   publisher (a newer version, or another tool from the same vendor). In audit
   mode it produces no "would block"; in enforce mode it launches. Its file
   hash was never allowed — only its publisher.
6. **Prove it is still a real restriction:** in enforce mode, an unsigned copy
   of the same program (edit a byte of the file to break its signature) is
   still blocked.
7. **Approvals path:** in audit mode, let a blocked signed app raise an
   approval request, then use *Approve publisher* on the Approvals page. Same
   verified-only rule applies, and the audit log records
   `approval.approve` with `kind: publisher`.

Note: a publisher whose certificate uses the older SHA-1 signing algorithm
cannot become a rule (WDAC needs the longer modern identifier); the console
shows the publisher but the rule is refused. Allow those by hash.

## What automated tests already cover (so this doc stays short)
- Rule validation/normalization, deterministic WDAC XML + versioning, the Microsoft baseline in every policy, policy store/versioning/assignment, recompiling all policies at server startup, effective-policy resolution and signing, the GetPolicy/Observe/ReportBlocks RPCs, the console policy API, the enforcer interface, Authenticode file hashing, CodeIntegrity XML parsing, and the full agent app-control loop (with a test enforcer).
- **Publisher identity:** `internal/appcontrol/signature` tests cover PE/PKCS#7 parsing, the TBS hash (including that it follows the certificate's own hash algorithm), picking the code-signing certificate rather than the embedded timestamp responder, and unsigned/malformed files. A Windows-only test verifies a real signed system binary through `WinVerifyTrust`. Server tests cover promote/approve-as-publisher, including that an unverified publisher is refused and that the certificate hash is always read server-side, never taken from the client.
- **Windows accepts the XML:** a Windows-only test (`internal/appcontrol/wdac/wdac_windows_test.go`) converts empty, hash, path, publisher and mixed policies in both modes with `ConvertFrom-CIPolicy` on any Windows dev box. It only writes a `.cip` to a temp dir; nothing is deployed.
- **Not** covered here: that `CiTool` activates the policy and CodeIntegrity enforces it as expected — that is exactly what steps 4–5 above verify.
