param([string]$Version = "0.1.0")
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$stage = Join-Path $env:TEMP "fl-msi-stage"
Remove-Item -Recurse -Force $stage -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $stage | Out-Null

$env:GOOS = "windows"; $env:GOARCH = "amd64"
& go build -ldflags "-s -w -X freelocker/internal/agent/version.Version=$Version" -o (Join-Path $stage "freelocker-agent.exe") "$root/cmd/agent"
if ($LASTEXITCODE) { throw "agent build failed" }
& go build -ldflags "-s -w" -o (Join-Path $stage "agent-updater.exe") "$root/cmd/agent-updater"
if ($LASTEXITCODE) { throw "updater build failed" }
"" | Set-Content (Join-Path $stage "config.yaml")   # placeholder; filled by WriteConfig custom action

Copy-Item "$root/deploy/msi/Package.wxs" $stage
$binDir = Join-Path $root "bin"
New-Item -ItemType Directory -Force $binDir | Out-Null
Push-Location $stage
try {
    & wix build Package.wxs -o (Join-Path $binDir "FreeLocker.msi")
    if ($LASTEXITCODE) { throw "wix build failed" }
} finally { Pop-Location }
Write-Host "Built bin/FreeLocker.msi (version $Version)"
