<#
.SYNOPSIS
    Creates the disposable Hyper-V VM used for FreeLocker's manual test runs.

.DESCRIPTION
    Creates a Generation 2 VM, attaches an evaluation ISO, and starts it so
    Windows Setup can be clicked through once. Everything after the OS
    install is automated over PowerShell Direct (see Initialize-TestVM.ps1),
    which needs no network and no WinRM configuration inside the guest.

    This VM is DISPOSABLE. It exists to have real WDAC policy, real Defender
    ASR machine policy and real firewall rules applied to it. Never point
    these scripts at a machine you rely on.

.EXAMPLE
    ./New-TestVM.ps1 -IsoPath D:\iso\server2025.iso

.EXAMPLE
    ./New-TestVM.ps1 -IsoPath D:\iso\win11.iso -EnableTPM
#>
[CmdletBinding()]
param(
    [string]$VMName = "FreeLocker-Test",

    # Evaluation ISO. When omitted, the newest .iso under $SearchRoot is used.
    [string]$IsoPath,

    [string]$SearchRoot = "D:\",

    # Where the VM's disk lives. Defaults beside the ISO's drive, not on C:,
    # because a test VM churning WDAC policy grows.
    [string]$VhdPath,

    [int]$MemoryGB = 4,
    [int]$CpuCount = 2,
    [int]$VhdSizeGB = 64,

    # Default Switch gives the guest NAT'd access to the host, which is how
    # the agent reaches the dev box's gRPC listener on 8443.
    [string]$SwitchName = "Default Switch",

    # Windows 11 refuses to install without a TPM. Server 2022/2025 does not
    # need one, and enabling it requires creating an HGS guardian, which
    # wants full administrator rights rather than Hyper-V Administrators.
    [switch]$EnableTPM
)

$ErrorActionPreference = "Stop"

function Assert-HyperVAccess {
    if (-not (Get-Command Get-VM -ErrorAction SilentlyContinue)) {
        throw "The Hyper-V PowerShell module is not present. Enable the 'Hyper-V Module for Windows PowerShell' optional feature."
    }
    try {
        Get-VM -ErrorAction Stop | Out-Null
    } catch {
        throw @"
Cannot manage Hyper-V as the current user.

Run this once from an ELEVATED PowerShell, then sign out and back in:

    Add-LocalGroupMember -Group "Hyper-V Administrators" -Member "`$env:USERNAME"

Group membership only applies to a new login token, so the sign-out matters.
Original error: $($_.Exception.Message)
"@
    }
}

function Resolve-Iso {
    param([string]$Path, [string]$Root)

    if ($Path) {
        if (-not (Test-Path -LiteralPath $Path)) { throw "ISO not found: $Path" }
        return (Resolve-Path -LiteralPath $Path).Path
    }

    Write-Host "No -IsoPath given; searching $Root for an ISO..."
    $iso = Get-ChildItem -Path $Root -Filter *.iso -Recurse -Depth 3 -ErrorAction SilentlyContinue |
        Sort-Object Length -Descending | Select-Object -First 1
    if (-not $iso) {
        throw @"
No .iso found under $Root.

Download a free evaluation image (no product key, 180 days) from the
Microsoft Evaluation Center and drop it anywhere under ${Root}:
  - Windows Server 2025 Standard (Desktop Experience) — no TPM needed
  - Windows 11 Enterprise — closer to a real endpoint, needs -EnableTPM
"@
    }
    Write-Host "Using ISO: $($iso.FullName)"
    return $iso.FullName
}

Assert-HyperVAccess

if (Get-VM -Name $VMName -ErrorAction SilentlyContinue) {
    throw "A VM named '$VMName' already exists. Remove it first, or pass -VMName for a second one."
}

$IsoPath = Resolve-Iso -Path $IsoPath -Root $SearchRoot

if (-not $VhdPath) {
    $isoDrive = [System.IO.Path]::GetPathRoot($IsoPath)
    $VhdPath = Join-Path $isoDrive "VMs\$VMName\$VMName.vhdx"
}
$vhdDir = Split-Path -Parent $VhdPath
if (-not (Test-Path $vhdDir)) { New-Item -ItemType Directory -Force -Path $vhdDir | Out-Null }
if (Test-Path -LiteralPath $VhdPath) { throw "Disk already exists: $VhdPath" }

if (-not (Get-VMSwitch -Name $SwitchName -ErrorAction SilentlyContinue)) {
    $available = (Get-VMSwitch | Select-Object -ExpandProperty Name) -join ", "
    throw "Virtual switch '$SwitchName' not found. Available: $available"
}

Write-Host "Creating VM '$VMName' ($MemoryGB GB RAM, $CpuCount vCPU, $VhdSizeGB GB disk)..."

# Dynamic memory is off on purpose: WDAC policy evaluation and a Defender
# scan in the same guest make ballooning noisy, and a fixed assignment makes
# a hang easier to attribute to our code than to host pressure.
$vm = New-VM -Name $VMName -Generation 2 `
    -MemoryStartupBytes ($MemoryGB * 1GB) `
    -NewVHDPath $VhdPath -NewVHDSizeBytes ($VhdSizeGB * 1GB) `
    -SwitchName $SwitchName

Set-VM -VM $vm -ProcessorCount $CpuCount -StaticMemory `
    -AutomaticCheckpointsEnabled $false `
    -CheckpointType Production

# Production checkpoints use VSS in the guest, so a restored snapshot is a
# consistent machine rather than one resumed mid-write. That matters here:
# every stage that reverts (enforce -> audit, ringfence unassign) is checked
# for leftover residue, and a crash-consistent restore would muddy that.

$dvd = Add-VMDvdDrive -VM $vm -Path $IsoPath -Passthru
Set-VMFirmware -VM $vm -FirstBootDevice $dvd -EnableSecureBoot On `
    -SecureBootTemplate "MicrosoftWindows"

if ($EnableTPM) {
    Write-Host "Enabling vTPM (required by Windows 11)..."
    try {
        if (-not (Get-HgsGuardian -Name UntrustedGuardian -ErrorAction SilentlyContinue)) {
            New-HgsGuardian -Name UntrustedGuardian -GenerateCertificates | Out-Null
        }
        $kp = New-HgsKeyProtector -Owner (Get-HgsGuardian -Name UntrustedGuardian) -AllowUntrustedRoot
        Set-VMKeyProtector -VM $vm -KeyProtector $kp.RawData
        Enable-VMTPM -VM $vm
    } catch {
        Remove-VM -VM $vm -Force
        Remove-Item -LiteralPath $VhdPath -Force -ErrorAction SilentlyContinue
        throw @"
Could not enable the vTPM: $($_.Exception.Message)

Creating an HGS guardian writes to the local certificate store and usually
needs a full administrator, not just Hyper-V Administrators. Either run this
script from an elevated shell, or use a Server evaluation ISO, which does
not require a TPM and needs no -EnableTPM.
"@
    }
}

Start-VM -VM $vm

Write-Host ""
Write-Host "VM '$VMName' created and started." -ForegroundColor Green
Write-Host ""
Write-Host "Next: connect and click through Windows Setup (~10 minutes)."
Write-Host "    vmconnect.exe localhost `"$VMName`""
Write-Host ""
Write-Host "During setup:"
Write-Host "  - Choose the Desktop Experience edition if offered."
Write-Host "  - Skip the product key (evaluation editions do not need one)."
Write-Host "  - Set a local Administrator password you will pass to"
Write-Host "    Initialize-TestVM.ps1 — PowerShell Direct authenticates with it."
Write-Host ""
Write-Host "Then run: ./Initialize-TestVM.ps1 -VMName `"$VMName`""
