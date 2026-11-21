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
#   6. Starts the full test stack (bw-serve + ferrowarden + mock-api)
#   7. Creates a test agent key and writes it to secrets\test_agent_key
#   8. Writes a .env.test file with ready-to-use environment variables
#
# Usage:
#   .\scripts\dev-setup.ps1
#
# To reset and start over:
#   docker compose -f docker-compose.test.yml down -v
#   Remove-Item secrets\bw_client_id, secrets\bw_client_secret, secrets\test_agent_key -ErrorAction SilentlyContinue
#   .\scripts\dev-setup.ps1

$ErrorActionPreference = 'Stop'

$secretsDir = '.\secrets'
$ferroUrl   = if ($env:FERROWARDEN_URL) { $env:FERROWARDEN_URL } else { 'http://localhost:3000' }

function Write-Step([string]$msg) { Write-Host ""; Write-Host $msg }
function Write-Sub([string]$msg)  { Write-Host "  $msg" }

# Wrapper so every docker compose call uses the same compose file
function Invoke-Compose {
    docker compose -f docker-compose.test.yml @args
}

# Write a file as UTF-8 without BOM and without a trailing newline.
# Docker reads secrets with cat, so a trailing newline would break the value.
function Write-Secret([string]$path, [string]$value) {
    $fullPath = [System.IO.Path]::GetFullPath($path)
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

# ── Generate self-signed TLS certificate (if not already present) ────────────

Write-Step '[1b/7] Generating TLS certificate...'

$certPath = '.\certs\server.crt'
$keyPath  = '.\certs\server.key'

if (-not (Test-Path $certPath) -or -not (Test-Path $keyPath)) {
    $openssl = Get-Command openssl -ErrorAction SilentlyContinue
    if ($openssl) {
        # -subj with a forward-slash subject works on Windows openssl too.
        # Redirect stderr to suppress the "Generating key" noise.
        & openssl req -x509 -newkey ed25519 `
            -keyout $keyPath -out $certPath `
            -days 365 -nodes `
            -subj '/CN=ferrowarden-test' 2>$null
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

Write-Step '[6/7] Starting full test stack (bw-serve, ferrowarden, mock-api)...'
Invoke-Compose up -d bw-serve mock-api

# bw-serve runs on the internal Docker network only — not reachable from the
# host. Wait 15 seconds for it to initialize before starting ferrowarden.
Write-Sub 'Waiting for bw-serve to initialize (~15s)...'
Start-Sleep 15

Invoke-Compose up -d ferrowarden

Write-Sub 'Waiting for ferrowarden to unlock and start accepting requests...'
$adminKey = [System.IO.File]::ReadAllText([System.IO.Path]::GetFullPath($adminKeyFile))
$elapsed  = 0
$ready    = $false
while (-not $ready -and $elapsed -lt 60) {
    try {
        $null = Invoke-RestMethod "$ferroUrl/v1/admin/status" `
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
    Write-Error 'ferrowarden did not become ready within 60s'
    Invoke-Compose logs ferrowarden
    exit 1
}
Write-Sub 'Stack is healthy.'

# ── Create test agent key ─────────────────────────────────────────────────────

Write-Step '[7/7] Creating test agent key...'

$agentKeyFile = "$secretsDir\test_agent_key"
$agentKeyVal  = ''
try {
    $resp = Invoke-RestMethod "$ferroUrl/v1/admin/keys" `
        -Method POST `
        -Headers @{ 'X-Admin-Key' = $adminKey; 'Content-Type' = 'application/json' } `
        -Body '{"name":"integration-test-agent"}' `
        -ErrorAction Stop
    $agentKeyVal = $resp.token
    Write-Secret $agentKeyFile $agentKeyVal
    Write-Sub 'Agent key written to secrets\test_agent_key'
} catch {
    Write-Warning "Failed to create agent key: $_"
    Write-Warning 'Check logs: docker compose -f docker-compose.test.yml logs ferrowarden'
}

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
MOCK_API_URL=http://localhost:7777
"@

[System.IO.File]::WriteAllText(
    [System.IO.Path]::GetFullPath('.env.test'),
    $envContent,
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
Write-Host 'To run integration tests:'
Write-Host '  scripts\load-env.ps1'
Write-Host '  cargo +stable-x86_64-pc-windows-msvc test --test integration -- --test-threads=1'
Write-Host ''
Write-Host 'To stop the stack:'
Write-Host '  docker compose -f docker-compose.test.yml down'
Write-Host ''
Write-Host 'To reset everything:'
Write-Host '  docker compose -f docker-compose.test.yml down -v'
Write-Host '  Remove-Item secrets\bw_client_id, secrets\bw_client_secret, secrets\test_agent_key -ErrorAction SilentlyContinue'
Write-Host '  .\scripts\dev-setup.ps1'
