#!/bin/sh
# setup-entrypoint.sh
#
# One-shot setup container. Runs inside a bitwarden/cli container.
# Performs full automated Vaultwarden account creation without any
# manual steps. Writes client_id and client_secret to /secrets/.
#
# Flow:
#   1. Wait for Vaultwarden to be ready
#   2. Register a new account (bw-register.js — Node.js built-in crypto)
#   3. Register a second account that owns the restricted organisation, whose
#      collection hides passwords from the first (bw-seed-hidden.js)
#   4. Log in with the account's own KDF and create its API key
#      (bw-apikey.js), and write client_id and client_secret to /secrets/
#
# Environment variables (all required):
#   BW_SERVER_URL          — Vaultwarden base URL (e.g. https://vaultwarden)
#   BW_CA_CERT             — CA that signs Vaultwarden's certificate
#                            (default: $NODE_EXTRA_CA_CERTS, i.e. /pki/ca.crt)
#   SETUP_EMAIL            — Email address for the vault account
#   SETUP_MASTER_PASSWORD  — Master password for the vault account
#   SETUP_MAX_WAIT         — Seconds to wait for Vaultwarden (default: 90)
#   TEST_KDF               — pbkdf2 (default) or argon2id: the KDF both accounts
#                            are registered with (bw-register.js)
#   HIDDEN_OWNER_EMAIL     — The second account (default:
#                            org-owner@ferrowarden.test; same master password)

set -e

EMAIL="${SETUP_EMAIL:?SETUP_EMAIL is required}"
MASTER_PASSWORD="${SETUP_MASTER_PASSWORD:?SETUP_MASTER_PASSWORD is required}"
MAX_WAIT="${SETUP_MAX_WAIT:-90}"
SECRETS_DIR="${SECRETS_DIR:-/secrets}"
CA_CERT="${BW_CA_CERT:-${NODE_EXTRA_CA_CERTS:-/pki/ca.crt}}"

# wget/curl trust the internal CA explicitly (Node.js uses NODE_EXTRA_CA_CERTS).
WGET_CA=""
CURL_CA=""
if [ -f "$CA_CERT" ]; then
    WGET_CA="--ca-certificate=$CA_CERT"
    CURL_CA="--cacert $CA_CERT"
fi

# ── 1. Wait for Vaultwarden ──────────────────────────────────────────────────

echo "[setup] Waiting for Vaultwarden at $BW_SERVER_URL ..."
elapsed=0
until wget -q $WGET_CA --spider "$BW_SERVER_URL" 2>/dev/null; do
    if [ "$elapsed" -ge "$MAX_WAIT" ]; then
        echo "[setup] ERROR: Vaultwarden did not become ready within ${MAX_WAIT}s" >&2
        exit 1
    fi
    sleep 2
    elapsed=$((elapsed + 2))
done
echo "[setup] Vaultwarden is ready."

# ── 2. Register account via bw-register.js ───────────────────────────────────
# There is no Bitwarden CLI command to register an account. bw-register.js performs the
# equivalent client-side crypto (PBKDF2 key derivation, symmetric key
# generation, RSA-2048 key pair, AES-256-CBC encryption) and calls
# POST /api/accounts/register directly. Uses only Node.js built-in modules.

echo "[setup] Registering account: $EMAIL"
if node /usr/local/share/ferrowarden/bw-register.js; then
    echo "[setup] Account registration step complete."
else
    echo "[setup] bw-register.js returned non-zero — will attempt to continue." >&2
fi

# The owner of the restricted organisation (bw-seed-hidden.js): a second
# account, so that the first one is an ordinary member of that organisation
# and a collection can hide passwords from it (owners and admins always see
# them). Same master password, same KDF.
HIDDEN_OWNER_EMAIL="${HIDDEN_OWNER_EMAIL:-org-owner@ferrowarden.test}"
echo "[setup] Registering account: $HIDDEN_OWNER_EMAIL"
if SETUP_EMAIL="$HIDDEN_OWNER_EMAIL" node /usr/local/share/ferrowarden/bw-register.js; then
    echo "[setup] Second account registration step complete."
else
    echo "[setup] bw-register.js returned non-zero for the second account — will attempt to continue." >&2
fi

# ── 4. Log in and create the API key (bw-apikey.js) ──────────────────────────
# The identity token endpoint wants the master password hash, which depends on
# the account's KDF (PBKDF2-SHA256 or Argon2id): bw-apikey.js reads it from
# prelogin and derives the hash with Node's built-in crypto (the same code that
# registered the account, bw-lib.js), logs in, and creates the API key
# (client_id + client_secret) used by the native backend and the
# seeder. It writes bw_client_id and bw_client_secret to $SECRETS_DIR.

mkdir -p "$SECRETS_DIR"
if ! node /usr/local/share/ferrowarden/bw-apikey.js; then
    echo "[setup] ERROR: failed to log in and create the API key." >&2
    exit 1
fi

echo "[setup] Wrote:"
echo "  $SECRETS_DIR/bw_client_id"
echo "  $SECRETS_DIR/bw_client_secret"
echo "[setup] Setup complete."
