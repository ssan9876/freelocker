<#
    Shared helpers for the FreeLocker VM test scripts. Dot-sourced, not a
    module, to keep the harness to plain files that run from a clone with no
    install step.
#>

Set-StrictMode -Version Latest

function Get-TestVM {
    <#
        Resolves a VM by name with an error that says what to do next, rather
        than the raw Hyper-V authorization failure, which is the single most
        common way these scripts fail on a fresh box.
    #>
    param([Parameter(Mandatory)][string]$VMName)

    try {
        $vm = Get-VM -Name $VMName -ErrorAction Stop
    } catch [Microsoft.HyperV.PowerShell.VirtualizationOperationFailedException] {
        throw "VM '$VMName' not found. Create it with ./New-TestVM.ps1."
    } catch {
        if ($_.Exception.Message -match 'permission|authorization') {
            throw @"
Cannot manage Hyper-V as the current user.

Run this once from an ELEVATED PowerShell, then sign out and back in:

    Add-LocalGroupMember -Group "Hyper-V Administrators" -Member "`$env:USERNAME"
"@
        }
        throw
    }
    return $vm
}

function Wait-TestVMSession {
    <#
        Opens a PowerShell Direct session, retrying until the guest is far
        enough through boot to accept one.

        PowerShell Direct goes over the VMBus, so it works with no guest
        networking, no WinRM listener and no firewall exception. That is
        exactly what we need: several stages deliberately block the network
        inside the guest, and an SSH- or WinRM-based harness would cut its
        own control channel the moment ringfencing started working.
    #>
    param(
        [Parameter(Mandatory)][string]$VMName,
        [Parameter(Mandatory)][pscredential]$Credential,
        [int]$TimeoutMinutes = 10
    )

    $deadline = (Get-Date).AddMinutes($TimeoutMinutes)
    $lastError = $null
    Write-Host "Waiting for PowerShell Direct on '$VMName' (up to $TimeoutMinutes min)..."

    while ((Get-Date) -lt $deadline) {
        try {
            return New-PSSession -VMName $VMName -Credential $Credential -ErrorAction Stop
        } catch {
            $lastError = $_
            Start-Sleep -Seconds 10
        }
    }

    throw @"
Timed out opening a PowerShell Direct session to '$VMName'.

Common causes, in the order they actually happen:
  - Windows Setup is not finished, or the guest is sitting at a prompt.
    Check with: vmconnect.exe localhost "$VMName"
  - The credential is wrong. It must be a LOCAL administrator in the guest;
    for a local account use the bare name (Administrator), not HOST\name.
  - The guest OS predates Windows 10 / Server 2016, which PowerShell Direct
    requires.

Last error: $($lastError.Exception.Message)
"@
}

function Invoke-TestVMScript {
    <#
        Runs a scriptblock in the guest and returns its result, turning a
        non-terminating guest failure into a terminating one here so a stage
        cannot silently "pass" on an error.
    #>
    param(
        [Parameter(Mandatory)][System.Management.Automation.Runspaces.PSSession]$Session,
        [Parameter(Mandatory)][scriptblock]$ScriptBlock,
        [object[]]$ArgumentList = @(),
        [string]$Description = "guest command"
    )

    $result = Invoke-Command -Session $Session -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList -ErrorVariable guestErrors
    if ($guestErrors) {
        throw "$Description failed in the guest: $($guestErrors[0].Exception.Message)"
    }
    return $result
}

function Assert-DisposableGuest {
    <#
        A guard against the worst possible accident: pointing this harness at
        a machine someone depends on. Every stage below writes real WDAC
        policy, real Defender ASR machine policy and real firewall rules.

        Checks the session is genuinely a Hyper-V guest and is not the host.
    #>
    param([Parameter(Mandatory)][System.Management.Automation.Runspaces.PSSession]$Session)

    $info = Invoke-Command -Session $Session -ScriptBlock {
        [pscustomobject]@{
            Name         = $env:COMPUTERNAME
            Manufacturer = (Get-CimInstance Win32_ComputerSystem).Manufacturer
            Model        = (Get-CimInstance Win32_ComputerSystem).Model
            Domain       = (Get-CimInstance Win32_ComputerSystem).Domain
            PartOfDomain = (Get-CimInstance Win32_ComputerSystem).PartOfDomain
        }
    }

    if ($info.Name -eq $env:COMPUTERNAME) {
        throw "Refusing to continue: the session's computer name matches this host ($($info.Name)). These tests must never run on the dev box."
    }
    if ($info.Model -notmatch 'Virtual Machine' -and $info.Manufacturer -notmatch 'Microsoft') {
        throw "Refusing to continue: guest does not look like a Hyper-V VM (Manufacturer='$($info.Manufacturer)', Model='$($info.Model)')."
    }
    if ($info.PartOfDomain) {
        Write-Warning "Guest is domain-joined ($($info.Domain)). Domain policy can fight the agent's ASR and WDAC writes, and this VM may not be as disposable as intended."
    }

    return $info
}
