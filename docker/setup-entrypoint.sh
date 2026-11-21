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
#   3. Obtain an access token (pure HTTP + PBKDF2 via Python stdlib)
#   4. Create an API key for bw serve / the seeder
#   5. Write client_id and client_secret to /secrets/
#
# Environment variables (all required):
#   BW_SERVER_URL          — Vaultwarden base URL (e.g. http://vaultwarden:80)
#   SETUP_EMAIL            — Email address for the vault account
#   SETUP_MASTER_PASSWORD  — Master password for the vault account
#   SETUP_MAX_WAIT         — Seconds to wait for Vaultwarden (default: 90)

set -e

EMAIL="${SETUP_EMAIL:?SETUP_EMAIL is required}"
MASTER_PASSWORD="${SETUP_MASTER_PASSWORD:?SETUP_MASTER_PASSWORD is required}"
MAX_WAIT="${SETUP_MAX_WAIT:-90}"
SECRETS_DIR="${SECRETS_DIR:-/secrets}"

# ── 1. Wait for Vaultwarden ──────────────────────────────────────────────────

echo "[setup] Waiting for Vaultwarden at $BW_SERVER_URL ..."
elapsed=0
until wget -q --spider "$BW_SERVER_URL" 2>/dev/null; do
    if [ "$elapsed" -ge "$MAX_WAIT" ]; then
        echo "[setup] ERROR: Vaultwarden did not become ready within ${MAX_WAIT}s" >&2
        exit 1
    fi
    sleep 2
    elapsed=$((elapsed + 2))
done
echo "[setup] Vaultwarden is ready."

# ── 2. Register account via bw-register.js ───────────────────────────────────
# The bw CLI does not have a `register` command. bw-register.js performs the
# equivalent client-side crypto (PBKDF2 key derivation, symmetric key
# generation, RSA-2048 key pair, AES-256-CBC encryption) and calls
# POST /api/accounts/register directly. Uses only Node.js built-in modules.

echo "[setup] Registering account: $EMAIL"
if node /home/node/bw-register.js; then
    echo "[setup] Account registration step complete."
else
    echo "[setup] bw-register.js returned non-zero — will attempt to continue." >&2
fi

# ── 3. Derive master password hash (pure Python stdlib, no extra packages) ───
# The Bitwarden identity token endpoint requires the master password hash,
# not the plaintext password. The hash is PBKDF2-SHA256(masterKey, password, 1).
# masterKey itself is PBKDF2-SHA256(password, email, 100000).
# This is the standard Bitwarden KDF chain (kdf=0, kdfIterations=100000).

MASTER_HASH=$(python3 - <<PYEOF
import hashlib, base64
email    = "$EMAIL".lower()
password = "$MASTER_PASSWORD"
master_key = hashlib.pbkdf2_hmac('sha256', password.encode(), email.encode(), 100000, 32)
master_hash = base64.b64encode(
    hashlib.pbkdf2_hmac('sha256', master_key, password.encode(), 1, 32)
).decode()
print(master_hash, end='')
PYEOF
)

# ── 4. Obtain access token from Vaultwarden identity endpoint ─────────────────
# Standard OAuth2 resource-owner password flow as used by Bitwarden clients.
# We identify as a generic "SDK" device (deviceType=6) so Vaultwarden does
# not enforce email verification for this device type.

DEVICE_ID=$(python3 -c "import uuid; print(uuid.uuid4())")

echo "[setup] Obtaining access token..."
TOKEN_RESPONSE=$(curl -sf -X POST "$BW_SERVER_URL/identity/connect/token" \
    --data-urlencode "grant_type=password" \
    --data-urlencode "username=$EMAIL" \
    --data-urlencode "password=$MASTER_HASH" \
    --data-urlencode "scope=api offline_access" \
    --data-urlencode "client_id=web" \
    --data-urlencode "deviceType=6" \
    --data-urlencode "deviceIdentifier=$DEVICE_ID" \
    --data-urlencode "deviceName=ferrowarden-setup")

ACCESS_TOKEN=$(python3 -c "
import sys, json
data = json.loads('$TOKEN_RESPONSE')
print(data.get('access_token', ''))
" 2>/dev/null)

if [ -z "$ACCESS_TOKEN" ]; then
    echo "[setup] ERROR: failed to obtain access token." >&2
    echo "[setup] Response: $TOKEN_RESPONSE" >&2
    exit 1
fi

echo "[setup] Access token obtained."

# ── 5. Create API key for programmatic access ────────────────────────────────
# The API key (client_id + client_secret) is used by bw serve and the seeder
# for non-interactive login. Creating it requires authenticating with the
# master password hash — not just the access token — to confirm operator intent.
#
# API response format changed in Vaultwarden 2026.x:
#   Old: {"clientId": "user.<uuid>", "clientSecret": "..."}
#   New: {"apiKey": "<secret>", "object": "apiKey"}
#
# In the new format, clientId is derived as "user.<sub>" where <sub> is the
# user UUID from the JWT access token. We decode it without verification using
# Python's stdlib (base64 + json) since we obtained the token ourselves.

echo "[setup] Creating API key..."
APIKEY_RESPONSE=$(curl -sf -X POST "$BW_SERVER_URL/api/accounts/api-key" \
    -H "Authorization: Bearer $ACCESS_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"masterPasswordHash\": \"$MASTER_HASH\"}")

CLIENT_ID=$(python3 -c "
import sys, json, base64
data = json.loads('$APIKEY_RESPONSE')
# New format returns apiKey only; clientId is derived from the JWT sub claim
if 'clientId' in data:
    print(data['clientId'])
elif 'apiKey' in data:
    # Decode JWT to get user UUID (no verification needed — we issued this request)
    payload = '$ACCESS_TOKEN'.split('.')[1]
    payload += '=' * (-len(payload) % 4)
    sub = json.loads(base64.b64decode(payload))['sub']
    print('user.' + sub)
" 2>/dev/null)

CLIENT_SECRET=$(python3 -c "
import sys, json
data = json.loads('$APIKEY_RESPONSE')
# New format uses 'apiKey'; old format uses 'clientSecret'
print(data.get('clientSecret') or data.get('apiKey', ''))
" 2>/dev/null)

if [ -z "$CLIENT_ID" ] || [ -z "$CLIENT_SECRET" ]; then
    echo "[setup] ERROR: failed to create API key." >&2
    echo "[setup] Response: $APIKEY_RESPONSE" >&2
    exit 1
fi

echo "[setup] API key created: $CLIENT_ID"

# ── 6. Write secrets ─────────────────────────────────────────────────────────

mkdir -p "$SECRETS_DIR"
printf '%s' "$CLIENT_ID"     > "$SECRETS_DIR/bw_client_id"
printf '%s' "$CLIENT_SECRET" > "$SECRETS_DIR/bw_client_secret"
chmod 600 "$SECRETS_DIR/bw_client_id" "$SECRETS_DIR/bw_client_secret"

echo "[setup] Wrote:"
echo "  $SECRETS_DIR/bw_client_id"
echo "  $SECRETS_DIR/bw_client_secret"
echo "[setup] Setup complete."
