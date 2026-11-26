#!/bin/sh
# seed-entrypoint.sh
#
# One-shot credential seeder. Seeds test credentials into Vaultwarden.
# Idempotent: credentials that already exist by name are skipped.
#
# Uses bw-seed.js (Node.js, built-in modules only) for direct Vaultwarden API
# calls, handling the cipher crypto itself. It was written when the pinned
# CLI (2023.12.1) could not create items on current Vaultwarden; it is kept so
# test fixtures do not depend on CLI item-creation behaviour.
#
# Requires:
#   /run/secrets/bw_master_password — Vault master password
#   /seed/credentials.json          — Credential definitions to seed
#
# Environment:
#   BW_SERVER_URL  — Vaultwarden base URL (e.g. https://vaultwarden)
#   SETUP_EMAIL    — Vault account email (default: admin@ferrowarden.test)
#   HIDDEN_OWNER_EMAIL — Owner of the restricted organisation, a second account
#                        (default: org-owner@ferrowarden.test)

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
CA_CERT="${BW_CA_CERT:-${NODE_EXTRA_CA_CERTS:-/pki/ca.crt}}"
WGET_CA=""
[ -f "$CA_CERT" ] && WGET_CA="--ca-certificate=$CA_CERT"
until wget -q $WGET_CA --spider "$BW_SERVER_URL" 2>/dev/null; do
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
node /usr/local/share/ferrowarden/bw-seed.js

# An item whose collection hides passwords from the account, owned by the
# second account that vault-setup registered (docs/native-vault.md).
echo "Seeding the hidden-password item ..."
exec node /usr/local/share/ferrowarden/bw-seed-hidden.js
