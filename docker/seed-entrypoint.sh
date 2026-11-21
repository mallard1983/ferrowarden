#!/bin/sh
# seed-entrypoint.sh
#
# One-shot credential seeder. Seeds test credentials into Vaultwarden.
# Idempotent: credentials that already exist by name are skipped.
#
# Uses bw-seed.js (Node.js, built-in modules only) for direct Vaultwarden API
# calls. The Bitwarden CLI 2023.12.1 is incompatible with Vaultwarden 2026.x
# for item creation (missing 'encryptedFor' field); the Node.js script bypasses
# the CLI and handles the cipher crypto and API calls directly.
#
# Requires:
#   /run/secrets/bw_master_password — Vault master password
#   /seed/credentials.json          — Credential definitions to seed
#
# Environment:
#   BW_SERVER_URL  — Vaultwarden base URL (e.g. http://vaultwarden:80)
#   SETUP_EMAIL    — Vault account email (default: admin@ferrowarden.test)

set -e

CREDENTIALS_FILE="${CREDENTIALS_FILE:-/seed/credentials.json}"
MAX_WAIT="${VAULTWARDEN_WAIT_SECONDS:-60}"
SETUP_EMAIL="${SETUP_EMAIL:-admin@ferrowarden.test}"

# ── Validate inputs ───────────────────────────────────────────────────────────

if [ ! -f /run/secrets/bw_master_password ]; then
    echo "ERROR: required secret not found: /run/secrets/bw_master_password" >&2
    exit 1
fi

if [ ! -f "$CREDENTIALS_FILE" ]; then
    echo "ERROR: credentials file not found: $CREDENTIALS_FILE" >&2
    exit 1
fi

# ── Wait for Vaultwarden ──────────────────────────────────────────────────────

echo "Waiting for Vaultwarden at $BW_SERVER_URL ..."
elapsed=0
until wget -q --spider "$BW_SERVER_URL" 2>/dev/null; do
    if [ "$elapsed" -ge "$MAX_WAIT" ]; then
        echo "ERROR: Vaultwarden did not become ready within ${MAX_WAIT}s" >&2
        exit 1
    fi
    sleep 2
    elapsed=$((elapsed + 2))
done
echo "Vaultwarden is ready."

# ── Seed credentials via bw-seed.js ──────────────────────────────────────────
# bw-seed.js derives the master key from the password, authenticates,
# decrypts the vault key, and creates each credential as an encrypted cipher.

SETUP_MASTER_PASSWORD="$(cat /run/secrets/bw_master_password)"
export SETUP_MASTER_PASSWORD SETUP_EMAIL BW_SERVER_URL CREDENTIALS_FILE

echo "Seeding credentials from $CREDENTIALS_FILE ..."
exec node /home/node/bw-seed.js
