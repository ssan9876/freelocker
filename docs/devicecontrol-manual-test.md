# Device control manual test (Windows VM)

Three per-group controls, all default-allow and reversible; the agent
applies them from **Groups** in the console. Do this on a disposable VM,
and **snapshot before the network test** — a firewall mistake is fastest to
undo by restoring the snapshot.

## USB mass-storage
Enforced via `HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR\Start`
(3 = allowed, 4 = blocked).

1. Set the group's *USB storage* to **Blocked**.
2. Within ~5 min: `reg query HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR /v Start` shows `0x4`.
3. Insert a USB mass-storage device — Windows does not mount it. (Already-loaded drivers may need a replug/reboot.)
4. Set back to **Allowed** → `Start=0x3`, storage mounts again.

## Elevation
Enforced via `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`
(3 = prompt standard users, 0 = auto-deny). Administrators are unaffected
(that's `ConsentPromptBehaviorAdmin`, which we don't touch), so this never
locks admins out.

1. Set the group's *Elevation* to **Blocked**.
2. `reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorUser` shows `0x0`.
3. As a **standard** user, a UAC elevation request is auto-denied.
4. Set back to **Allowed** → `0x3`.

## Network  (snapshot first — self-lockout risk)
Enforced by setting the Windows Firewall default **outbound action to
block** and adding allow rules for the FreeLocker server, DNS (UDP 53) and
DHCP (UDP 67/68), so the agent keeps its management link. The agent
**refuses to block** if it can't resolve the server address, rather than
risk cutting itself off.

1. Set the group's *Network* to **Blocked**.
2. On the VM: `netsh advfirewall show allprofiles` shows outbound = Block; `netsh advfirewall firewall show rule name=all | findstr FreeLocker-Net` lists the allow rules.
3. The device stays online in the console (server traffic is allowed); general internet access (e.g. a browser) is blocked.
4. Set back to **Allowed** → default outbound returns to Allow and the `FreeLocker-Net-*` rules are removed.

### Recovery if network blocking cuts something off
- Restore the pre-test snapshot, or on the VM: `netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound` then delete the `FreeLocker-Net-*` rules. Setting the group back to *Allowed* in the console does the same automatically once the agent can reach the server.

## Covered by automated tests
- Controls store (all three fields, partial updates, default-allow resolution, tenant isolation), the GetControls RPC, the console controls API + RBAC, and the agent sync loop with a recording enforcer.
- **Not** covered here: that the registry/firewall changes take effect on real Windows — the steps above verify that on the VM.

## Deferred
- Per-device (not just per-group) control overrides.
