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
7. **Command:** issue Ping from the console -> succeeds within seconds.
8. **Kill test:** `taskkill /f /im freelocker-agent.exe` -> service restarts within ~5 s; device returns to online (console shows "unexpected_offline" briefly).
9. **Cert renewal:** (optional, clock-advance) not part of the smoke test.
10. **Self-update:** upload a new build via `POST /api/releases`; issue UpdateAgent; the service swaps to the new version and reports the new version in inventory; a deliberately broken build rolls back within 2 minutes.
11. **Uninstall needs code:** `freelocker-agent uninstall` -> refused; `freelocker-agent uninstall -code <wrong>` -> refused; `-code <correct>` -> service removed, data dir gone.
12. **Server-driven uninstall:** issue Uninstall from the console -> agent removes itself.
13. **Revoke:** revoke the device -> live stream drops and the agent stops retrying.
