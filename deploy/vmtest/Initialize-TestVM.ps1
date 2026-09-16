<#
.SYNOPSIS
    Prepares a freshly installed test VM and snapshots it as the clean baseline.

.DESCRIPTION
    Runs after Windows Setup has been clicked through once. Connects over
    PowerShell Direct (no guest networking or WinRM needed), checks the guest
    is fit for the tests, records the pre-FreeLocker state of everything the
    agent touches, and takes the 'clean' checkpoint that every later run
    resets to.

    The baseline matters more than it looks. Several checklist items assert
    that unassigning a ringfence or leaving enforce mode "leaves no residue".
    That claim is only checkable against a recorded before-state: a guest
    whose ASR key was already populated by its own policy would otherwise
    make our cleanup look broken, or hide that it is.

.EXAMPLE
    ./Initialize-TestVM.ps1 -VMName FreeLocker-Test
#>
[CmdletBinding()]
param(
    [string]$VMName = "FreeLocker-Test",

    # Guest local administrator. Prompted for when omitted.
    [pscredential]$Credential,

    [string]$BaselinePath = "$PSScriptRoot\baseline.json",

    [string]$CheckpointName = "clean",

    [int]$TimeoutMinutes = 10
)

$ErrorActionPreference = "Stop"

. "$PSScriptRoot\VMTest.Common.ps1"

$vm = Get-TestVM -VMName $VMName
if ($vm.State -ne 'Running') {
    Write-Host "Starting '$VMName'..."
    Start-VM -VM $vm
}

if (-not $Credential) {
    $Credential = Get-Credential -UserName "Administrator" `
        -Message "Local administrator account you created during Windows Setup in '$VMName'"
}

$session = Wait-TestVMSession -VMName $VMName -Credential $Credential -TimeoutMinutes $TimeoutMinutes

try {
    Write-Host "Collecting guest baseline..."

    $baseline = Invoke-Command -Session $session -ScriptBlock {
        $asrKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'

        # Pre-existing ASR values are the interesting case: if this guest is
        # domain-joined or Intune-managed, values here belong to that policy
        # and the agent must never delete them.
        $asr = @{}
        if (Test-Path $asrKey) {
            $props = Get-ItemProperty -Path $asrKey
            foreach ($p in $props.PSObject.Properties) {
                if ($p.Name -notmatch '^PS') { $asr[$p.Name] = $p.Value }
            }
        }

        $defender = $null
        try {
            $s = Get-MpComputerStatus -ErrorAction Stop
            $defender = @{
                AMServiceEnabled     = $s.AMServiceEnabled
                RealTimeProtection   = $s.RealTimeProtectionEnabled
                AntivirusEnabled     = $s.AntivirusEnabled
                IsTamperProtected    = $s.IsTamperProtected
                AMRunningMode        = $s.AMRunningMode
            }
        } catch {
            $defender = @{ error = $_.Exception.Message }
        }

        [pscustomobject]@{
            CollectedAt      = (Get-Date).ToString('o')
            ComputerName     = $env:COMPUTERNAME
            OSCaption        = (Get-CimInstance Win32_OperatingSystem).Caption
            OSBuild          = (Get-CimInstance Win32_OperatingSystem).BuildNumber
            Defender         = $defender
            AsrRules         = $asr
            # The agent names every rule it creates FreeLocker-RF-*, so a
            # non-empty list here means a previous run left residue behind.
            RingfenceRules   = @(Get-NetFirewallRule -DisplayName 'FreeLocker-RF-*' -ErrorAction SilentlyContinue |
                                    Select-Object -ExpandProperty DisplayName)
            FreeLockerService = [bool](Get-Service -Name 'FreeLocker*' -ErrorAction SilentlyContinue)
            InstallDirExists = (Test-Path 'C:\Program Files\FreeLocker')
            ProgramDataExists = (Test-Path 'C:\ProgramData\FreeLocker')
        }
    }

    $warnings = @()

    if ($baseline.FreeLockerService -or $baseline.InstallDirExists) {
        $warnings += "The agent appears to be installed already - this is not a clean guest."
    }
    if ($baseline.RingfenceRules.Count -gt 0) {
        $warnings += "Guest already has FreeLocker-RF-* firewall rules: $($baseline.RingfenceRules -join ', ')"
    }
    if ($baseline.AsrRules.Count -gt 0) {
        $warnings += "Guest already has ASR policy values set (likely GPO/Intune). The agent must leave these alone; record them: $($baseline.AsrRules.Keys -join ', ')"
    }
    if ($baseline.Defender.error) {
        $warnings += "Could not read Defender status: $($baseline.Defender.error). ASR tests need Defender as the ACTIVE antivirus."
    } elseif (-not $baseline.Defender.RealTimeProtection) {
        $warnings += "Defender real-time protection is OFF. ASR rules are inert without it, so child-process containment cannot be verified."
    } elseif ($baseline.Defender.AMRunningMode -and $baseline.Defender.AMRunningMode -ne 'Normal') {
        $warnings += "Defender is running in '$($baseline.Defender.AMRunningMode)' mode. ASR rules are inert unless Defender is the active AV."
    }

    $baseline | ConvertTo-Json -Depth 6 | Set-Content -Path $BaselinePath -Encoding UTF8
    Write-Host "Baseline written to $BaselinePath" -ForegroundColor Green
    Write-Host "  Guest: $($baseline.OSCaption) (build $($baseline.OSBuild))"

    foreach ($w in $warnings) { Write-Warning $w }
} finally {
    Remove-PSSession $session -ErrorAction SilentlyContinue
}

if (Get-VMCheckpoint -VMName $VMName -Name $CheckpointName -ErrorAction SilentlyContinue) {
    Write-Host "Checkpoint '$CheckpointName' already exists; leaving it as-is."
} else {
    Write-Host "Taking checkpoint '$CheckpointName'..."
    Checkpoint-VM -Name $VMName -SnapshotName $CheckpointName
    Write-Host "Checkpoint '$CheckpointName' created." -ForegroundColor Green
}

Write-Host ""
Write-Host "Ready. Reset to this state at any time with:"
Write-Host "    Restore-VMCheckpoint -VMName `"$VMName`" -Name `"$CheckpointName`" -Confirm:`$false"
