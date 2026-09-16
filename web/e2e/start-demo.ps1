<#
.SYNOPSIS
    Starts a demo FreeLocker instance with content in it, and leaves it running.

.DESCRIPTION
    For looking at the console by hand. Recreates a throwaway database, builds
    the console so the server embeds the current build, starts the server, then
    seeds an organisation, an admin with MFA, groups, policies and ringfences.

    Prints the sign-in details including the TOTP secret, since the account has
    MFA enrolled and whoever signs in needs a code.

    Unlike capture-shots.ps1 this LEAVES THE SERVER RUNNING. Stop it with
    -Stop when you are done.

.EXAMPLE
    ./start-demo.ps1
    ./start-demo.ps1 -Stop
#>
[CmdletBinding()]
param(
    [int]$Port = 8080,
    [string]$Database = "freelocker_demo",
    [switch]$Stop
)

$ErrorActionPreference = "Stop"

$web = Split-Path -Parent $PSScriptRoot
$root = Split-Path -Parent $web
$compose = Join-Path $root "deploy\docker-compose.dev.yml"

function Stop-OnPort {
    param([int]$P)
    foreach ($c in @(Get-NetTCPConnection -LocalPort $P -State Listen -ErrorAction SilentlyContinue)) {
        Stop-Process -Id $c.OwningProcess -Force -ErrorAction SilentlyContinue
    }
}

if ($Stop) {
    Stop-OnPort -P $Port
    Write-Host "Demo server on port $Port stopped." -ForegroundColor Green
    return
}

function Invoke-Psql {
    param([string]$Sql)
    # psql writes NOTICE to stderr, which ErrorActionPreference=Stop would
    # otherwise turn into a terminating error.
    $prev = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        & docker compose -f $compose exec -T postgres psql -U freelocker -c $Sql 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "psql failed ($LASTEXITCODE): $Sql" }
    } finally { $ErrorActionPreference = $prev }
}

Stop-OnPort -P $Port

Write-Host "Building the console..."
Push-Location $web
try {
    & npm run build 2>&1 | Select-Object -Last 1
    if ($LASTEXITCODE -ne 0) { throw "console build failed" }
} finally { Pop-Location }

Write-Host "Recreating database '$Database'..."
Invoke-Psql "DROP DATABASE IF EXISTS $Database WITH (FORCE)"
Invoke-Psql "CREATE DATABASE $Database"

Write-Host "Starting the server..."
# ${Database} must be brace-delimited: "?" is legal in a PowerShell variable
# name, so "$Database?sslmode" parses as one undefined variable.
$env:FREELOCKER_DATABASE_URL = "postgres://freelocker:freelocker@localhost:55432/${Database}?sslmode=disable"
$env:FREELOCKER_INSECURE_COOKIES = "true"
$log = Join-Path $env:TEMP "freelocker-demo-server.log"
Remove-Item $log, "$log.err" -ErrorAction SilentlyContinue
Start-Process -FilePath "go" -ArgumentList @("run", "./cmd/server", "serve") `
    -WorkingDirectory $root -WindowStyle Hidden `
    -RedirectStandardOutput $log -RedirectStandardError "$log.err" | Out-Null

$deadline = (Get-Date).AddMinutes(2)
$up = $false
while ((Get-Date) -lt $deadline) {
    try {
        Invoke-WebRequest -Uri "http://localhost:$Port/" -UseBasicParsing -TimeoutSec 3 | Out-Null
        $up = $true; break
    } catch { Start-Sleep -Seconds 2 }
}
if (-not $up) {
    Get-Content "$log.err" -ErrorAction SilentlyContinue | Select-Object -Last 15
    throw "server did not come up on port $Port"
}

Write-Host "Seeding content..."
Push-Location $web
try {
    $env:E2E_BASE_URL = "http://localhost:$Port"
    & npx playwright test --config=playwright.demo.config.ts
    if ($LASTEXITCODE -ne 0) { throw "demo setup failed" }
} finally { Pop-Location }

Write-Host "Server is still running. Stop it with: ./start-demo.ps1 -Stop" -ForegroundColor Green
