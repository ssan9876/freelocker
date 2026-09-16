<#
.SYNOPSIS
    Builds and runs the decision-core tests.

.DESCRIPTION
    The decision core is portable C with no dependencies, so this needs only
    a C compiler - no WDK, no signed driver, no VM. It finds MSVC, clang or
    gcc, whichever is present.

    Run it after any change to fl_decision.c. The logic that decides whether
    a program is allowed to run is the part of the driver most worth testing
    and the part that is hardest to test once it is in the kernel, which is
    why it lives here rather than inside freelocker.sys.

.PARAMETER Mutate
    Also runs mutation testing: rebuilds the suite against deliberately
    broken copies of the core and fails if any of them PASS. A test suite
    that cannot fail is not evidence of anything, and these tests were
    written alongside the implementation rather than before it, so this is
    what stands in for having watched them go red.
#>
[CmdletBinding()]
param([switch]$Mutate)

$ErrorActionPreference = "Stop"

$core = Split-Path -Parent $PSScriptRoot
$out = Join-Path ([System.IO.Path]::GetTempPath()) "freelocker-core-tests"
New-Item -ItemType Directory -Force $out | Out-Null

function Find-MSVC {
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (-not (Test-Path $vswhere)) { return $null }
    $paths = & $vswhere -all -prerelease -products * -property installationPath 2>$null
    foreach ($p in $paths) {
        $vcvars = Join-Path $p "VC\Auxiliary\Build\vcvars64.bat"
        # A Build Tools install without the C++ workload has no vcvars64.
        if (Test-Path $vcvars) { return $vcvars }
    }
    return $null
}

function Invoke-Build {
    param([string]$CoreSource, [string]$OutDir, [string]$ExeName)

    New-Item -ItemType Directory -Force $OutDir | Out-Null
    $test = Join-Path $PSScriptRoot "fl_decision_test.c"

    $vcvars = Find-MSVC
    if ($vcvars) {
        # /I is required: a mutated copy of the core lives outside the source
        # directory and its #include "fl_decision.h" must still resolve.
        $cmd = "`"$vcvars`" >nul 2>&1 && cd /d `"$OutDir`" && cl /nologo /W4 /WX /I `"$core`" /Fe:$ExeName `"$CoreSource`" `"$test`""
        cmd /c $cmd 2>&1 | Out-Null
        $exe = Join-Path $OutDir $ExeName
        if (Test-Path $exe) { return $exe }
        # Re-run without swallowing output so the failure is visible.
        cmd /c $cmd
        throw "MSVC build failed"
    }

    foreach ($cc in @("clang", "gcc")) {
        if (Get-Command $cc -ErrorAction SilentlyContinue) {
            $exe = Join-Path $OutDir $ExeName
            & $cc -std=c99 -Wall -Wextra -Werror -I $core -o $exe $CoreSource $test
            if ($LASTEXITCODE -ne 0) { throw "$cc build failed" }
            return $exe
        }
    }

    throw @"
No C compiler found.

Install one of:
  - Visual Studio Build Tools with the "Desktop development with C++" workload
  - clang or gcc on PATH
"@
}

Write-Host "Building decision-core tests..."
$exe = Invoke-Build -CoreSource (Join-Path $core "fl_decision.c") -OutDir $out -ExeName "fl_test.exe"

& $exe
if ($LASTEXITCODE -ne 0) {
    throw "decision-core tests FAILED"
}
Write-Host "Decision-core tests passed." -ForegroundColor Green

if (-not $Mutate) { exit 0 }

Write-Host ""
Write-Host "Mutation testing (each mutant MUST fail the suite)..."

$source = Get-Content (Join-Path $core "fl_decision.c") -Raw

# Each entry breaks one property the suite claims to guarantee. The find
# strings are exact source text; if one stops matching after a refactor the
# script says so rather than silently testing nothing.
$mutants = @(
    @{ Name = "no_fail_open"
       Find = "    if (fl_ruleset_is_empty(rs)) {`n        why = FL_REASON_NO_RULESET;`n        verdict = FL_ALLOW;`n        goto done;`n    }"
       Replace = "    /* MUTANT */" }
    @{ Name = "no_boundary"
       Find = "    return path[rule->len] == '\\' || path[rule->len] == '/';"
       Replace = "    return 1; /* MUTANT */" }
    @{ Name = "unverified_ok"
       Find = "    if (req->signer_verified && req->signer_tbs != 0 &&"
       Replace = "    if (req->signer_tbs != 0 && /* MUTANT */" }
    @{ Name = "search_off_by_one"
       Find = "            hi = mid;"
       Replace = "            hi = mid - 1;" }
    @{ Name = "no_self"
       Find = "    if (fl_any_path_match(rs->self, rs->self_count, req->path, req->path_len)) {"
       Replace = "    if (0) { /* MUTANT */" }
    @{ Name = "audit_blocks"
       Find = "    verdict = (rs->mode == FL_MODE_ENFORCE) ? FL_BLOCK : FL_WOULD_BLOCK;"
       Replace = "    verdict = FL_BLOCK; /* MUTANT */" }
)

$survivors = @()
foreach ($m in $mutants) {
    $normalised = $source -replace "`r`n", "`n"
    if (-not $normalised.Contains($m.Find)) {
        throw "mutation '$($m.Name)' no longer matches the source - update run-tests.ps1"
    }
    $mutated = $normalised.Replace($m.Find, $m.Replace)

    $dir = Join-Path $out "mutant_$($m.Name)"
    New-Item -ItemType Directory -Force $dir | Out-Null
    $file = Join-Path $dir "fl_decision.c"
    Set-Content -Path $file -Value $mutated -NoNewline

    # /WX is dropped for mutants: a mutant can legitimately produce an
    # unused-variable warning, and that is not what is being measured.
    $mexe = $null
    try {
        $vcvars = Find-MSVC
        $test = Join-Path $PSScriptRoot "fl_decision_test.c"
        if ($vcvars) {
            cmd /c "`"$vcvars`" >nul 2>&1 && cd /d `"$dir`" && cl /nologo /W4 /I `"$core`" /Fe:t.exe `"$file`" `"$test`"" 2>&1 | Out-Null
            if (Test-Path (Join-Path $dir "t.exe")) { $mexe = Join-Path $dir "t.exe" }
        } else {
            foreach ($cc in @("clang", "gcc")) {
                if (Get-Command $cc -ErrorAction SilentlyContinue) {
                    $mexe = Join-Path $dir "t.exe"
                    & $cc -std=c99 -I $core -o $mexe $file $test 2>$null
                    if ($LASTEXITCODE -ne 0) { $mexe = $null }
                    break
                }
            }
        }
    } catch { $mexe = $null }

    if (-not $mexe) {
        # A mutant that will not build proves nothing about the tests, so it
        # is an error in this harness rather than a pass.
        throw "mutant '$($m.Name)' failed to build - the harness is broken, not the tests"
    }

    & $mexe | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  $($m.Name): SURVIVED - the suite does not cover this" -ForegroundColor Red
        $survivors += $m.Name
    } else {
        Write-Host "  $($m.Name): killed" -ForegroundColor DarkGray
    }
}

if ($survivors.Count -gt 0) {
    throw "mutants survived: $($survivors -join ', ')"
}
Write-Host "All $($mutants.Count) mutants killed." -ForegroundColor Green

# Explicit: the last thing run above was a MUTANT's test binary, which exits
# nonzero by design. Without this the script would report its own success as
# a failure and break any CI step that checks the exit code.
exit 0
