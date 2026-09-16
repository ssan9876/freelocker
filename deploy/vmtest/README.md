# VM test harness

Automation for the manual test runs in `docs/vm-test-run.md`. The checklists
stay the source of truth for *what* is verified; these scripts remove the
repetitive parts of *getting there*.

**The VM these scripts build is disposable.** Every stage applies real WDAC
policy, real Defender ASR machine policy and real Windows Firewall rules to
it. Never point the harness at a machine you rely on — `Assert-DisposableGuest`
refuses to run against this host, but it cannot tell a spare laptop from a
scratch VM.

## Prerequisites

1. **Hyper-V access.** Run once from an elevated PowerShell, then sign out
   and back in — group membership only applies to a new login token:

   ```powershell
   Add-LocalGroupMember -Group "Hyper-V Administrators" -Member "$env:USERNAME"
   ```

2. **An evaluation ISO**, free and unlicensed for 180 days, from the
   Microsoft Evaluation Center:
   - *Windows Server 2025 Standard (Desktop Experience)* — no TPM required,
     the simpler path.
   - *Windows 11 Enterprise* — closer to a real endpoint, but needs
     `-EnableTPM`, which in turn usually needs a full administrator to
     create the HGS guardian.

   Drop it anywhere under `D:\` and the scripts will find it.

## Running

```powershell
cd deploy/vmtest
./New-TestVM.ps1                      # create + start; finds the newest ISO
vmconnect.exe localhost FreeLocker-Test   # click through Setup, ~10 min
./Initialize-TestVM.ps1               # baseline + 'clean' checkpoint
```

Reset to a clean guest between runs:

```powershell
Restore-VMCheckpoint -VMName FreeLocker-Test -Name clean -Confirm:$false
```

## Why the OS install is not automated

Unattended setup needs an `autounattend.xml` baked into bootable media,
which means rebuilding the ISO with `oscdimg` from the Windows ADK — another
dependency, and a brittle one. The install is a one-time ten minutes, and
the `clean` checkpoint means it is paid exactly once. Everything after it is
automated.

## Why PowerShell Direct

Control travels over the VMBus, so it needs no guest networking, no WinRM
listener and no firewall exception. That is not a convenience — it is
required. Several stages deliberately block network traffic inside the
guest, and a WinRM- or SSH-based harness would sever its own control channel
the moment ringfencing started working.

## Baseline

`Initialize-TestVM.ps1` records the guest's pre-FreeLocker state to
`baseline.json`: Defender status, any ASR policy values already present, any
`FreeLocker-RF-*` firewall rules, and whether the agent is installed.

Several checklist items assert that reverting leaves no residue — unassigning
a ringfence, leaving enforce mode. That claim is only checkable against a
recorded before-state. The ASR values matter most: on a managed guest they
belong to GPO or Intune, and the agent is required to leave them alone.

## Status

Built so far: VM creation, guest session handling, baseline capture,
checkpointing. The per-stage automation is written against a real guest
rather than in advance, so that it is verified rather than merely plausible.

Stage 5 (USB storage control) cannot be automated — it needs a physical USB
device inserted into the host and passed through to the guest.
