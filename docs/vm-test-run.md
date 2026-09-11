# Full VM test run

One pass that exercises everything that needs real Windows, in an order
where each stage sets up the next. The detailed steps live in the
per-feature docs; this page is the running order, the setup, and a place to
record results.

**Use a disposable Windows 11 / Server 2022+ VM. Take a snapshot before
stage 1** and again before stage 6 (enforce mode) — restoring a snapshot is
the fastest recovery from anything below.

## Setup (dev box)

1. **Postgres:** `docker compose -f deploy/docker-compose.dev.yml up -d` (port 55432).
2. **Server config:** copy `deploy/server.example.yaml` to `server.yaml` and set:
   - `database_url: postgres://freelocker:freelocker@localhost:55432/freelocker?sslmode=disable` (the dev Postgres from `docker-compose.dev.yml`).
   - `public_hostnames` to include the dev box's IP **as the VM sees it** (it goes into the server certificate; enrollment fails if the VM dials a name not listed).
   - `insecure_cookies: true` only if you open the console over plain HTTP at a non-localhost address.
3. **Build:** `npm --prefix web run build` (embeds the console), then `go build -o bin/freelocker-server.exe ./cmd/server`, and run `bin/freelocker-server.exe serve -config server.yaml`. Open the console on `:8080`, complete setup, enroll MFA.
4. **Firewall:** allow inbound TCP 8443 (agent gRPC) on the dev box from the VM.
5. **Agent artifacts** (already built; rebuild if the code changed):
   - `bin/FreeLocker.msi` — agent **0.2.0** (`deploy/msi/build.ps1 -Version 0.2.0`).
   - `bin/freelocker-agent-0.2.1.exe` — the self-update target (stage 7).
6. In the console create a group (e.g. `VM`) and an install token for it.

## Stages

| # | Stage | Doc | Pass? | Notes |
|---|---|---|---|---|
| 1 | Install & enroll | `agent-manual-test.md` steps 1–8 | | |
| 2 | App control, audit mode | `appcontrol-manual-test.md` *Audit mode* | | |
| 3 | Learning hashes match WDAC | below | | |
| 4 | Approvals | `approvals-manual-test.md` | | |
| 5 | USB storage control | `devicecontrol-manual-test.md` | | |
| 6 | Enforce mode (snapshot first) | `appcontrol-manual-test.md` *Enforce mode* | | |
| 7 | Self-update to 0.2.1 | `agent-manual-test.md` step 10 | | |
| 8 | Uninstall / revoke | `agent-manual-test.md` steps 11–13 | | |

### What to expect from policies
Every policy includes Microsoft's DefaultWindows baseline, so Windows'
own programs and drivers are always allowed. In audit mode only
third-party software shows up as "Would block (audit)" and in
*Approvals*. Enforce mode likewise blocks only third-party software that
isn't allowed. The server recompiles every stored policy at startup, so
restart it after upgrading before starting the run.

### Stage 1 notes
Install the MSI from Setup step 5 with `SERVERURL=<dev-box-ip>:8443` and the
token from Setup step 6. The device page should show agent version **0.2.0**.

### Stage 3: learning hashes match WDAC
Checks the Authenticode fix (commit `2ebf51f`) end to end.
1. Leave the VM running a few minutes; on its device page, *Observed
   applications* fills in.
2. Pick an observed app, e.g. `C:\Windows\System32\notepad.exe`. On the VM,
   in **64-bit** Windows PowerShell:
   `(Get-AppLockerFileInformation -Path C:\Windows\System32\notepad.exe).Hash.HashDataString`
   The value (without `0x`) must equal the console's SHA-256 for it.
3. *Add as rule* on an app that is not yet allowed and is currently a
   would-block. After the agent applies the new policy version (~5 min),
   running it no longer produces a "Would block (audit)" event.

### Stage 7 notes
Upload `bin/freelocker-agent-0.2.1.exe` as version `0.2.1` via the console's
*Agent releases* page (owner only), then click **Update agent** on the
device page. It installs the most recently *uploaded* release, so make sure
0.2.1 is the last upload. The device page should then report **0.2.1**.

## If something fails
Capture: the VM's `C:\ProgramData\FreeLocker\` logs, the server log, the
relevant console page, and for WDAC issues `CiTool --list-policies` plus the
*Microsoft-Windows-CodeIntegrity/Operational* event log. Restore the
snapshot rather than hand-repairing the VM.
