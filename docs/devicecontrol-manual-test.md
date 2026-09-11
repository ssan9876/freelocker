# Device control manual test (Windows VM)

v1 covers **USB mass-storage control**. The agent enforces it by setting
the USBSTOR service Start value in the registry
(`HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR\Start`): 3 = allowed,
4 = blocked. This is reversible and default-allow.

Do this on a disposable VM.

1. In the console, open **Groups** and set the VM's group's *USB storage* to **Blocked**.
2. Within ~5 min the agent applies it. On the VM: `reg query HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR /v Start` shows `0x4`.
3. Insert a USB mass-storage device: Windows does not mount it. (Already-loaded drivers may require a replug or reboot to take full effect.)
4. Set the group back to **Allowed**; the agent restores `Start=0x3`; USB storage mounts again.

## Covered by automated tests
- Controls store (set/get, effective resolution default-allow, tenant isolation), the GetControls RPC, the console controls API + RBAC, and the full agent sync loop with a recording enforcer.
- **Not** covered here: that the registry change actually blocks USB on Windows — steps 2–4 verify that on the VM.

## Deferred (future controls, same pattern)
- Network restrictions (Windows Firewall rules), elevation control, per-device overrides.
