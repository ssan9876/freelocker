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

## Staged rollout (VM)

1. Upload two builds on **Agent releases** (e.g. 0.2.1 and 0.2.2).
2. With the VM agent online and on 0.2.1, click **Start rollout** on 0.2.2, batch 1, pause after 1 failure.
3. Within a minute the card shows 1 in flight; the agent downloads, stages, and the swap helper restarts the service. On the next heartbeat the device reports 0.2.2 and the card shows 1 updated → state completed.
4. Roll back: pick 0.2.1 in **Roll back to** and click **Roll back**. The old rollout shows as cancelled in history and a new one runs to 0.2.1.
5. Failure path: upload a build whose file you then delete from `release_dir`. Start a rollout; the agent's download 404s, the device shows failed with the agent's message, and the rollout auto-pauses.

## Notifications

1. **Webhook channel:** On the Notifications page, create a webhook channel pointed at a request-bin style URL (e.g., https://webhook.site/<unique-id>). Press **Test send** and confirm the webhook receives a POST with headers `X-FreeLocker-Event`, `X-FreeLocker-Delivery`, and `X-FreeLocker-Signature: sha256=<hex HMAC-SHA256>` (when a signing secret is set).
2. **Alert rule:** Create an alert rule with a CPU % threshold of 1 so a real agent running on the VM immediately trips it. Confirm the signed POST arrives on the webhook with event kind `alert.raised`.
3. **Rollout auto-pause:** Run the staged rollout failure drill (step 5 above). When the rollout auto-pauses due to the download failure, confirm that email and/or webhook notifications fire with event kind `rollout.auto_paused`.
