<#
.SYNOPSIS
    Adds a user to the local Hyper-V Administrators group, self-elevating.

.DESCRIPTION
    Managing Hyper-V needs either full administrator rights or membership of
    the local "Hyper-V Administrators" group. The group is the better choice
    for a test harness: it grants VM management and nothing else.

    Run this WITHOUT elevation - it re-launches itself through UAC and passes
    the original user's name across, because the elevated session can run as
    a different account and would otherwise add the wrong one.

    Uses net.exe rather than the *-LocalGroupMember cmdlets on purpose: those
    live in the LocalAccounts module, which ships with Windows PowerShell 5.1
    but not with PowerShell 7, so the cmdlet version fails outright under
    pwsh. net.exe is present on every Windows install.

.EXAMPLE
    powershell.exe -ExecutionPolicy Bypass -File .\Grant-HyperVAccess.ps1
#>
[CmdletBinding()]
param(
    # Defaults to whoever launched this, captured BEFORE elevation.
    [string]$UserName = "$env:USERDOMAIN\$env:USERNAME"
)

$ErrorActionPreference = "Stop"

$group = "Hyper-V Administrators"

function Get-GroupMembers {
    param([string]$Group)

    $out = & net localgroup $Group 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Could not read local group '$Group'. Is the Hyper-V role installed? ($out)"
    }

    # net localgroup prints a banner, a dashed rule, one member per line, then
    # a trailing success sentence. Take what sits between the rule and the end.
    $lines = @($out | ForEach-Object { "$_" })
    $start = ($lines | Select-String -SimpleMatch '---' | Select-Object -First 1).LineNumber
    if (-not $start) { return @() }

    return @($lines[$start..($lines.Count - 1)] |
        Where-Object { $_.Trim() -and $_ -notmatch 'The command completed successfully' } |
        ForEach-Object { $_.Trim() })
}

function Test-Member {
    param([string]$Group, [string]$User)

    $bare = $User.Split('\')[-1]
    foreach ($m in Get-GroupMembers -Group $Group) {
        if ($m -eq $User -or $m -eq $bare) { return $true }
    }
    return $false
}

$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    if (Test-Member -Group $group -User $UserName) {
        Write-Host "$UserName is already a member of '$group'." -ForegroundColor Green
        Write-Host "If Hyper-V still refuses, sign out and back in - group"
        Write-Host "membership is baked into your login token at sign-in."
        return
    }

    Write-Host "Elevation required - accept the UAC prompt."
    Write-Host "Adding: $UserName"

    try {
        Start-Process -FilePath (Get-Process -Id $PID).Path -Verb RunAs -Wait -ArgumentList @(
            "-NoProfile", "-ExecutionPolicy", "Bypass",
            "-File", "`"$PSCommandPath`"",
            "-UserName", "`"$UserName`""
        )
    } catch {
        throw "Elevation was declined or failed: $($_.Exception.Message)"
    }

    # Re-read from this unelevated session rather than trusting the child's
    # exit code, so a UAC dialog that was dismissed cannot report success.
    if (Test-Member -Group $group -User $UserName) {
        Write-Host ""
        Write-Host "$UserName added to '$group'." -ForegroundColor Green
        Write-Host ""
        Write-Host "SIGN OUT AND BACK IN before this takes effect -" -ForegroundColor Yellow
        Write-Host "group membership is baked into your login token." -ForegroundColor Yellow
    } else {
        Write-Warning "Membership not confirmed - the elevated run may have been cancelled."
    }
    return
}

# --- elevated from here ---

if (Test-Member -Group $group -User $UserName) {
    Write-Host "$UserName is already a member of '$group'."
} else {
    & net localgroup $group $UserName /add
    if ($LASTEXITCODE -ne 0) { throw "net localgroup add failed with exit code $LASTEXITCODE" }
    Write-Host "Added $UserName to '$group'."
}

Start-Sleep -Seconds 2
