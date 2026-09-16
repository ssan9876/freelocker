<#
.SYNOPSIS
    Captures console screenshots against a throwaway server and database.

.DESCRIPTION
    Design review needs a running console with content in it, and the capture
    only works from a genuinely fresh install: the spec walks first-run setup
    and MFA enrolment, and a database that already has an account skips those
    branches and then cannot sign in, because the enrolment secret existed
    only in the previous run.

    So this script owns the whole cycle - drop the database, recreate it,
    start the server with the freshly built console embedded, capture, and
    stop the server again.

    Screenshots land in e2e/__shots__ and are git-ignored. They are for
    looking at, not for asserting against: there are no reference images and
    nothing here fails on a visual difference.

.EXAMPLE
    ./capture-shots.ps1
#>
[CmdletBinding()]
param(
    [int]$Port = 8080,
    [string]$Database = "freelocker_shots"
)

$ErrorActionPreference = "Stop"

$web = Split-Path -Parent $PSScriptRoot
$root = Split-Path -Parent $web
$compose = Join-Path $root "deploy\docker-compose.dev.yml"

function Invoke-Psql {
    param([string]$Sql)
    # psql writes NOTICE lines to stderr ("database does not exist, skipping"
    # on a first run), and with ErrorActionPreference=Stop PowerShell turns
    # any native stderr into a terminating error. Relaxing it here keeps a
    # harmless notice from aborting the script, while a real failure still
    # surfaces through the exit code below.
    $prev = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        & docker compose -f $compose exec -T postgres psql -U freelocker -c $Sql 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "psql failed ($LASTEXITCODE): $Sql" }
    } finally {
        $ErrorActionPreference = $prev
    }
}

Write-Host "Building the console so the server embeds the current build..."
Push-Location $web
try {
    & npm run build 2>&1 | Select-Object -Last 1
    if ($LASTEXITCODE -ne 0) { throw "console build failed" }
} finally { Pop-Location }

Write-Host "Recreating database '$Database'..."
# WITH (FORCE) so a server still holding a connection cannot block the drop.
Invoke-Psql "DROP DATABASE IF EXISTS $Database WITH (FORCE)"
Invoke-Psql "CREATE DATABASE $Database"

Write-Host "Starting the server on port $Port..."
# ${Database} must be brace-delimited: "?" is a legal character in a
# PowerShell variable name, so "$Database?sslmode" parses as one undefined
# variable and the URL silently collapses to ".../=disable".
$env:FREELOCKER_DATABASE_URL = "postgres://freelocker:freelocker@localhost:55432/${Database}?sslmode=disable"
$env:FREELOCKER_INSECURE_COOKIES = "true"
# Output goes to a file so a startup failure is diagnosable; with the window
# hidden and no redirect, a crash looks identical to a slow start.
$log = Join-Path $env:TEMP "freelocker-shots-server.log"
Remove-Item $log -ErrorAction SilentlyContinue
$server = Start-Process -FilePath "go" -ArgumentList @("run", "./cmd/server", "serve") `
    -WorkingDirectory $root -PassThru -WindowStyle Hidden `
    -RedirectStandardOutput $log -RedirectStandardError "$log.err"

try {
    $deadline = (Get-Date).AddMinutes(2)
    $up = $false
    while ((Get-Date) -lt $deadline) {
        try {
            Invoke-WebRequest -Uri "http://localhost:$Port/" -UseBasicParsing -TimeoutSec 3 | Out-Null
            $up = $true
            break
        } catch { Start-Sleep -Seconds 2 }
    }
    if (-not $up) {
        Write-Host "--- server stdout ---"; Get-Content $log -ErrorAction SilentlyContinue | Select-Object -Last 20
        Write-Host "--- server stderr ---"; Get-Content "$log.err" -ErrorAction SilentlyContinue | Select-Object -Last 20
        throw "server did not come up on port $Port"
    }

    Write-Host "Capturing..."
    Push-Location $web
    try {
        Remove-Item -Recurse -Force "e2e\__shots__" -ErrorAction SilentlyContinue
        $env:E2E_BASE_URL = "http://localhost:$Port"
        & npx playwright test --config=playwright.shots.config.ts
        if ($LASTEXITCODE -ne 0) { throw "capture failed" }
    } finally { Pop-Location }

    Write-Host ""
    Write-Host "Screenshots in web/e2e/__shots__" -ForegroundColor Green
} finally {
    if ($server -and -not $server.HasExited) {
        Write-Host "Stopping the server..."
        # The go run parent spawns the actual server binary, so kill the tree.
        & taskkill /PID $server.Id /T /F 2>&1 | Out-Null
    }
    # Whatever happened above, leave nothing listening on the port.
    foreach ($c in @(Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue)) {
        Stop-Process -Id $c.OwningProcess -Force -ErrorAction SilentlyContinue
    }
}
