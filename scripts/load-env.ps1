# scripts/load-env.ps1
#
# Load .env.test into the current PowerShell session so integration tests
# can find the Ferrowarden test URL, admin key, and agent key.
#
# Usage:
#   . .\scripts\load-env.ps1
#   cargo +stable-x86_64-pc-windows-msvc test --test integration -- --test-threads=1
#
# Note the leading dot (dot-sourcing) — this is required for the variables
# to be set in the calling shell session, not just inside this script.

$envFile = Join-Path $PSScriptRoot '..' '.env.test'

if (-not (Test-Path $envFile)) {
    Write-Error ".env.test not found. Run .\scripts\dev-setup.ps1 first."
    return
}

Get-Content $envFile | Where-Object { $_ -match '^\w' -and $_ -notmatch '^#' } | ForEach-Object {
    $key, $value = $_ -split '=', 2
    [System.Environment]::SetEnvironmentVariable($key, $value, 'Process')
    Write-Host "  Set: $key"
}

Write-Host ""
Write-Host "Environment loaded from .env.test"
Write-Host "Run: cargo +stable-x86_64-pc-windows-msvc test --test integration -- --test-threads=1"
