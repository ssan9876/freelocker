# Interactive approvals manual test (Windows VM)

Approvals turn blocked / would-block launches into a console queue.
**Approve** adds the program's SHA-256 as an allow rule on the policy that
blocked it and recompiles that policy; **Deny** closes the request and keeps
the hash out of the pending queue for that policy. Deny blocks nothing
extra — the policy is already an allowlist.

The hash comes from the CodeIntegrity event's `SHA256 Hash` field — the
same Authenticode hash WDAC matches `<Allow Hash=…>` rules against — so an
approved hash is exactly what the policy needs. Step 7 below confirms it.

Run this in **audit mode** on a disposable VM. Audit is enough to exercise
the whole workflow and never locks the VM out.

Prereqs: everything in `docs/appcontrol-manual-test.md` *Audit mode* steps
1–4 — a policy assigned to the VM's group, applied by the agent
(`CiTool --list-policies` shows it active in **Audit**), and the VM online.
Note the policy version shown on the device page.

## Approve

1. **Trigger a would-block.** On the VM, run a program that is *not* on the
   policy (e.g. copy a small portable tool to `C:\Users\Public\` and run it).
   It still runs — audit mode.
2. **See the request.** Within about a minute:
   - *Blocked programs* shows it as "Would block (audit)".
   - The **Approvals** nav entry shows a pending badge (it refreshes every 15 s).
   - *Approvals → Pending* lists it with the path, signer, policy name,
     Devices = 1, Events ≥ 1.
3. **Repeat reports aggregate.** Run the same program again. The same row's
   *Events* count increases; no second row appears. If a second VM on the
   same policy runs it, *Devices* becomes 2.
4. **Approve it.** Click **Approve**. A toast confirms "Approved — added to
   <policy>"; the row leaves *Pending* and appears under *Approved* with a
   decided time. The badge count drops.
5. **Rule and version.** On the policy's page, a `hash` rule with that
   SHA-256 exists, described "approved from request … (<path>)", and the
   policy version has changed.
6. **Agent picks it up.** Within ~5 min the device page shows the new policy
   version, and `C:\ProgramData\FreeLocker\policy.xml` on the VM contains the
   approved hash.
7. **No more would-blocks.** Run the program again: no new "Would block
   (audit)" entry for it on *Blocked programs*.
8. **Audit log.** *Audit log* shows `approval.approve` by your admin, with
   the policy id and hash.

## Deny

1. Run a different disallowed program; wait for its pending request.
2. Click **Deny** and confirm the prompt. The row moves to *Denied*; the
   policy's rules are unchanged; *Audit log* shows `approval.deny`.
3. Run the program again. *Blocked programs* still records the event, but
   the request stays *Denied* — it does not reappear under *Pending*.

## Permissions

Sign in as a **readonly** admin: *Approvals* lists requests, but shows no
Approve / Deny buttons (the API returns 403 if called directly).

## Covered by automated tests
- Store: aggregation per (policy, hash), distinct device counts, empty-hash
  events skipped, decided requests never reopened, conflict on double
  decide, tenant isolation.
- `ReportBlocks` creates requests only for devices with an effective policy,
  and always acks.
- Console API: list/count/approve/deny, approve adds the rule and changes the
  policy version, 409 on double decide, 404 unknown, 400 bad filter, readonly
  gets 403.
- **Not** covered here: real WDAC audit events flowing from CodeIntegrity
  through the agent, the console UI itself, and the agent applying the
  recompiled policy — steps 1–7 of *Approve* verify those on the VM.

## Enforce mode (optional)

With the policy in **Enforce** (see the appcontrol doc's opt-in flag and
recovery path), the disallowed program is actually blocked and the request
arrives the same way. After Approve and the agent's re-apply, the program
launches. Keep the recovery steps from `docs/appcontrol-manual-test.md`
at hand.
