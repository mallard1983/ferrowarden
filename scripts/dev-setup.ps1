#Requires -Version 7
# scripts/dev-setup.ps1
#
# Windows PowerShell equivalent of scripts/dev-setup.sh
# Full automated dev/test environment setup for Ferrowarden.
# Run once on a fresh checkout (or after wiping test data).
#
# What this script does:
#   1. Generates secrets (master password, admin key) if they don't exist
#   2. Starts Vaultwarden with signups enabled
#   3. Runs vault-setup: registers the Vaultwarden account and writes
#      bw_client_id + bw_client_secret to secrets\
#   4. Disables Vaultwarden signups
#   5. Runs vault-seeder: populates the vault with test credentials
#   6. Starts the full test stack: bw-serve, mock-api and two Ferrowarden
#      instances against the same vault, one per vault backend
#      (docs/native-vault.md): ferrowarden (bw serve, port 3000) and
#      ferrowarden-native (port 3003)
#   7. Creates a test agent key on each, in secrets\
#   8. Writes .env.test (bw serve instance) and .env.test.native (native
#      instance) files with ready-to-use environment variables
#
# Usage:
#   .\scripts\dev-setup.ps1
#
# To reset and start over:
#   docker compose -f docker-compose.test.yml down -v
#   Remove-Item secrets\bw_client_id, secrets\bw_client_secret, secrets\test_agent_key -ErrorAction SilentlyContinue
#   .\scripts\dev-setup.ps1

$ErrorActionPreference = 'Stop'

# Always operate from the repository root, whatever directory the script was
# started from, and keep .NET's working directory in step with PowerShell's.
# .NET file APIs ([IO.File], [IO.Path]::GetFullPath) resolve relative paths
# against the process directory, not PowerShell's location, so without this
# a run started elsewhere could check one secrets\ folder and write another.
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Set-Location $repoRoot
[System.Environment]::CurrentDirectory = $repoRoot

$secretsDir = Join-Path $repoRoot 'secrets'
$ferroUrl   = if ($env:FERROWARDEN_URL) { $env:FERROWARDEN_URL } else { 'http://localhost:3000' }
$nativeUrl   = if ($env:FERROWARDEN_NATIVE_URL) { $env:FERROWARDEN_NATIVE_URL } else { 'http://localhost:3003' }
$nativeUiUrl = if ($env:FERROWARDEN_NATIVE_UI_URL) { $env:FERROWARDEN_NATIVE_UI_URL } else { 'http://localhost:3004' }
$metricsUrl       = if ($env:FERROWARDEN_METRICS_URL) { $env:FERROWARDEN_METRICS_URL } else { 'http://localhost:9095' }
$nativeMetricsUrl = if ($env:FERROWARDEN_NATIVE_METRICS_URL) { $env:FERROWARDEN_NATIVE_METRICS_URL } else { 'http://localhost:9096' }

function Write-Step([string]$msg) { Write-Host ""; Write-Host $msg }
function Write-Sub([string]$msg)  { Write-Host "  $msg" }

# Wrapper so every docker compose call uses the same compose file
function Invoke-Compose {
    docker compose -f docker-compose.test.yml @args
}

# Write a file as UTF-8 without BOM and without a trailing newline.
# Docker reads secrets with cat, so a trailing newline would break the value.
function Write-Secret([string]$path, [string]$value) {
    # Resolve with PowerShell's path rules, not .NET's process directory.
    $fullPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($path)
    [System.IO.File]::WriteAllText($fullPath, $value, [System.Text.UTF8Encoding]::new($false))
}

# Generate a cryptographically random alphanumeric token of the given length.
function New-RandomToken([int]$length = 48) {
    $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'.ToCharArray()
    $rng   = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $buf   = [byte[]]::new(1)
    -join (1..$length | ForEach-Object {
        $rng.GetBytes($buf)
        $chars[$buf[0] % $chars.Length]
    })
}

Write-Host '=================================================='
Write-Host ' Ferrowarden Dev Environment Setup (Windows)'
Write-Host '=================================================='

# ── Check prerequisites ───────────────────────────────────────────────────────

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Error 'docker is not installed or not on PATH'; exit 1
}
try { docker compose version | Out-Null } catch {
    Write-Error 'docker compose (v2) is required'; exit 1
}

New-Item -ItemType Directory -Force -Path $secretsDir | Out-Null
New-Item -ItemType Directory -Force -Path '.\certs'   | Out-Null

# ── Generate secrets (if not already present) ────────────────────────────────

Write-Step '[1/7] Generating secrets...'

$masterPwFile = "$secretsDir\bw_master_password"
if (-not (Test-Path $masterPwFile)) {
    # Fixed test password — intentional. This protects only fake credentials.
    # Never use in production.
    Write-Secret $masterPwFile 'ferrowarden-test-master-pw'
    Write-Sub 'Generated: bw_master_password (test fixture — intentionally simple)'
} else {
    Write-Sub 'Skipping: bw_master_password already exists'
}

$adminKeyFile = "$secretsDir\ferrowarden_admin_key"
if (-not (Test-Path $adminKeyFile)) {
    Write-Secret $adminKeyFile (New-RandomToken 48)
    Write-Sub 'Generated: ferrowarden_admin_key'
} else {
    Write-Sub 'Skipping: ferrowarden_admin_key already exists'
}

# Bearer token for the notifier's webhook to the mock API's notification sink
# (docker-compose.test.yml). Test fixture; the secret gate checks for it.
$notifyTokenFile = "$secretsDir\notify_webhook_token"
if (-not (Test-Path $notifyTokenFile)) {
    Write-Secret $notifyTokenFile (New-RandomToken 40)
    Write-Sub 'Generated: notify_webhook_token'
} else {
    Write-Sub 'Skipping: notify_webhook_token already exists'
}

# Bearer token for the Prometheus metrics listeners of both Ferrowarden
# instances (docs/metrics.md, docker-compose.test.yml). Test fixture; the
# secret gate checks for it, and it must never appear in a scrape.
$metricsTokenFile = "$secretsDir\metrics_token"
if (-not (Test-Path $metricsTokenFile)) {
    Write-Secret $metricsTokenFile (New-RandomToken 40)
    Write-Sub 'Generated: metrics_token'
} else {
    Write-Sub 'Skipping: metrics_token already exists'
}

# ── Generate self-signed TLS certificate (if not already present) ────────────

Write-Step '[1b/7] Generating TLS certificate...'

$certPath = '.\certs\server.crt'
$keyPath  = '.\certs\server.key'

if (-not (Test-Path $certPath) -or -not (Test-Path $keyPath)) {
    $openssl = Get-Command openssl -ErrorAction SilentlyContinue
    if ($openssl) {
        # -subj with a forward-slash subject works on Windows openssl too.
        # Redirect stderr to suppress the "Generating key" noise.
        # EC P-256 (not Ed25519): Windows Schannel — used by curl.exe and
        # PowerShell — cannot validate Ed25519 certificates. The SAN is required
        # by most modern clients; CN alone is ignored.
        & openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 `
            -keyout $keyPath -out $certPath `
            -days 365 -nodes `
            -subj '/CN=ferrowarden-test' `
            -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' 2>$null
        Write-Sub 'Generated: certs/server.crt + certs/server.key (self-signed, 1 year)'
        Write-Sub 'NOTE: Import certs/server.crt into your HTTP client to skip cert errors.'
    } else {
        Write-Sub 'WARNING: openssl not found (install Git for Windows to get it).'
        Write-Sub 'TLS cert generation skipped — generate manually if needed.'
    }
} else {
    Write-Sub 'Skipping: certs/server.crt and certs/server.key already exist'
}

# ── Start Vaultwarden with signups enabled ───────────────────────────────────

Write-Step '[2/7] Starting Vaultwarden (signups enabled)...'
$env:VAULTWARDEN_SIGNUPS_ALLOWED = 'true'
Invoke-Compose up -d vaultwarden

# Give Vaultwarden a moment to initialize before the setup container connects
Start-Sleep 3

# ── Run vault-setup (register account + create API key) ──────────────────────

Write-Step '[3/7] Creating Vaultwarden account and API key...'

$masterPw    = [System.IO.File]::ReadAllText([System.IO.Path]::GetFullPath($masterPwFile))
$setupEmail  = if ($env:SETUP_EMAIL) { $env:SETUP_EMAIL } else { 'admin@ferrowarden.test' }

Invoke-Compose run --rm `
    -e "VAULTWARDEN_SIGNUPS_ALLOWED=true" `
    -e "SETUP_EMAIL=$setupEmail" `
    -e "SETUP_MASTER_PASSWORD=$masterPw" `
    vault-setup

Write-Sub 'API credentials written to secrets\'

# Docker Desktop keeps the owner and mode a container gave a bind-mounted file:
# vault-setup wrote these two as UID 1000 with mode 600, which the ferrowarden
# containers (UID 999) cannot read. Rewrite them from Windows (same bytes), which
# makes them world-readable like the other test secrets.
foreach ($name in 'bw_client_id', 'bw_client_secret') {
    $path = Join-Path $secretsDir $name
    $bytes = [System.IO.File]::ReadAllBytes($path)
    $tmp = "$path.tmp"
    [System.IO.File]::WriteAllBytes($tmp, $bytes)
    Move-Item -Force $tmp $path
}

# ── Disable Vaultwarden signups ───────────────────────────────────────────────

Write-Step '[4/7] Disabling Vaultwarden signups...'
Invoke-Compose stop vaultwarden
$env:VAULTWARDEN_SIGNUPS_ALLOWED = 'false'
Invoke-Compose up -d vaultwarden
Remove-Item env:VAULTWARDEN_SIGNUPS_ALLOWED -ErrorAction SilentlyContinue
Start-Sleep 2
Write-Sub 'Signups disabled.'

# ── Run vault-seeder ─────────────────────────────────────────────────────────

Write-Step '[5/7] Seeding test credentials...'
Invoke-Compose run --rm vault-seeder

# ── Start the full test stack ────────────────────────────────────────────────

Write-Step '[6/7] Starting full test stack (bw-serve, ferrowarden, ferrowarden-native, mock-api)...'
Invoke-Compose up -d bw-serve mock-api

# bw-serve runs on the internal Docker network only — not reachable from the
# host. Wait 15 seconds for it to initialize before starting ferrowarden.
Write-Sub 'Waiting for bw-serve to initialize (~15s)...'
Start-Sleep 15

Invoke-Compose up -d ferrowarden ferrowarden-native

$adminKey = [System.IO.File]::ReadAllText([System.IO.Path]::GetFullPath($adminKeyFile))
foreach ($instance in @(@{ Url = $ferroUrl; Service = 'ferrowarden' }, @{ Url = $nativeUrl; Service = 'ferrowarden-native' })) {
    Write-Sub "Waiting for $($instance.Service) to unlock and start accepting requests..."
    $elapsed = 0
    $ready   = $false
    while (-not $ready -and $elapsed -lt 90) {
        try {
            $null = Invoke-RestMethod "$($instance.Url)/v1/admin/status" `
                -Headers @{ 'X-Admin-Key' = $adminKey } `
                -ErrorAction Stop
            $ready = $true
        } catch {
            Start-Sleep 3
            $elapsed += 3
        }
    }
    if (-not $ready) {
        Write-Host ''
        Write-Error "$($instance.Service) did not become ready within 90s"
        Invoke-Compose logs $instance.Service
        exit 1
    }
}
Write-Sub 'Stack is healthy.'

# ── Create test agent key ─────────────────────────────────────────────────────

Write-Step '[7/7] Creating test agent keys...'

# One key per instance (each has its own key store).
function New-AgentKey([string]$url, [string]$file) {
    try {
        $resp = Invoke-RestMethod "$url/v1/admin/keys" `
            -Method POST `
            -Headers @{ 'X-Admin-Key' = $adminKey; 'Content-Type' = 'application/json' } `
            -Body '{"name":"integration-test-agent","credentials":["*"],"methods":["*"]}' `
            -ErrorAction Stop
        Write-Secret $file $resp.token
        Write-Sub "Agent key written to $file"
        return $resp.token
    } catch {
        Write-Warning "Failed to create the agent key at ${url}: $_"
        Write-Warning 'Check logs: docker compose -f docker-compose.test.yml logs ferrowarden ferrowarden-native'
        return ''
    }
}
$agentKeyVal       = New-AgentKey $ferroUrl "$secretsDir\test_agent_key"
$nativeAgentKeyVal = New-AgentKey $nativeUrl "$secretsDir\test_agent_key_native"

# ── Write .env.test ───────────────────────────────────────────────────────────

$envContent = @"
# Auto-generated by scripts\dev-setup.ps1
# Load before running integration tests.
#
# PowerShell:
#   scripts\load-env.ps1; cargo +stable-x86_64-pc-windows-msvc test --test integration -- --test-threads=1
#
# Bash / sh (Linux/Mac):
#   source .env.test && cargo test --test integration -- --test-threads=1

FERROWARDEN_INTEGRATION=1
FERROWARDEN_TEST_URL=$ferroUrl
FERROWARDEN_TEST_ADMIN_KEY=$($adminKey.Trim())
FERROWARDEN_TEST_AGENT_KEY=$($agentKeyVal.Trim())
FERROWARDEN_TEST_NOTIFY_TOKEN=$((Get-Content -Raw $notifyTokenFile).Trim())
FERROWARDEN_TEST_METRICS_URL=$metricsUrl
FERROWARDEN_TEST_METRICS_TOKEN=$((Get-Content -Raw $metricsTokenFile).Trim())
MOCK_API_URL=http://localhost:7777
"@

[System.IO.File]::WriteAllText(
    [System.IO.Path]::GetFullPath('.env.test'),
    $envContent,
    [System.Text.UTF8Encoding]::new($false)
)

# The same for the native instance: run the whole suite against it by loading
# this file instead (scripts\load-env.ps1 .env.test.native).
$nativeEnvContent = @"
# Auto-generated by scripts\dev-setup.ps1: the integration tests against the
# ferrowarden-native instance (vault.backend = native). Test environment only.

FERROWARDEN_INTEGRATION=1
FERROWARDEN_TEST_URL=$nativeUrl
FERROWARDEN_TEST_UI_URL=$nativeUiUrl
FERROWARDEN_TEST_ADMIN_KEY=$($adminKey.Trim())
FERROWARDEN_TEST_AGENT_KEY=$($nativeAgentKeyVal.Trim())
FERROWARDEN_TEST_NOTIFY_TOKEN=$((Get-Content -Raw $notifyTokenFile).Trim())
FERROWARDEN_TEST_METRICS_URL=$nativeMetricsUrl
FERROWARDEN_TEST_METRICS_TOKEN=$((Get-Content -Raw $metricsTokenFile).Trim())
MOCK_API_URL=http://localhost:7777
FERROWARDEN_NATIVE_URL=$nativeUrl
"@

[System.IO.File]::WriteAllText(
    [System.IO.Path]::GetFullPath('.env.test.native'),
    $nativeEnvContent,
    [System.Text.UTF8Encoding]::new($false)
)

# ── Done ──────────────────────────────────────────────────────────────────────

Write-Host ''
Write-Host '=================================================='
Write-Host ' Setup complete.'
Write-Host '=================================================='
Write-Host ''
Write-Host 'Services running:'
Invoke-Compose ps
Write-Host ''
Write-Host 'To run integration tests (bw serve instance), then the equivalence suite and the'
Write-Host 'same suite against the native instance:'
Write-Host '  scripts\load-env.ps1'
Write-Host '  cargo +stable-x86_64-pc-windows-msvc test --test integration -- --test-threads=1'
Write-Host '  cargo +stable-x86_64-pc-windows-msvc test --test equivalence -- --nocapture --test-threads=1'
Write-Host '  scripts\load-env.ps1 .env.test.native'
Write-Host '  cargo +stable-x86_64-pc-windows-msvc test --test integration -- --test-threads=1'
Write-Host ''
Write-Host 'To stop the stack:'
Write-Host '  docker compose -f docker-compose.test.yml down'
Write-Host ''
Write-Host 'To reset everything:'
Write-Host '  docker compose -f docker-compose.test.yml down -v'
Write-Host '  Remove-Item secrets\bw_client_id, secrets\bw_client_secret, secrets\test_agent_key -ErrorAction SilentlyContinue'
Write-Host '  .\scripts\dev-setup.ps1'
