#!/bin/sh
# seed-entrypoint.sh
#
# Seed test credentials into Vaultwarden using the Bitwarden CLI.
# Idempotent: credentials that already exist by name are skipped.
#
# Runs as a one-shot Docker Compose service. Exits 0 on success.
# Exits non-zero if Vaultwarden is unreachable or login fails.
#
# Requires:
#   /run/secrets/bw_client_id       — Vaultwarden API client ID
#   /run/secrets/bw_client_secret   — Vaultwarden API client secret
#   /run/secrets/bw_master_password — Vault master password (for unlock)
#   /seed/credentials.json          — Credential definitions to seed

set -e

CREDENTIALS_FILE="${CREDENTIALS_FILE:-/seed/credentials.json}"
MAX_WAIT="${VAULTWARDEN_WAIT_SECONDS:-60}"

# ── Validate inputs ───────────────────────────────────────────────────────────

for f in /run/secrets/bw_client_id /run/secrets/bw_client_secret /run/secrets/bw_master_password; do
    if [ ! -f "$f" ]; then
        echo "ERROR: required secret not found: $f" >&2
        exit 1
    fi
done

if [ ! -f "$CREDENTIALS_FILE" ]; then
    echo "ERROR: credentials file not found: $CREDENTIALS_FILE" >&2
    exit 1
fi

BW_CLIENTID="$(cat /run/secrets/bw_client_id)"
BW_CLIENTSECRET="$(cat /run/secrets/bw_client_secret)"
export BW_CLIENTID BW_CLIENTSECRET

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

# ── Configure and log in ──────────────────────────────────────────────────────

bw config server "$BW_SERVER_URL"

# Login creates a local encrypted copy of the vault. Subsequent runs will
# see "already logged in" — that is fine; we proceed to unlock.
bw login --apikey 2>&1 | grep -v "clientSecret" || true

# Unlock to get a session token. The session token authorises item operations.
SESSION="$(bw unlock --passwordenv BW_MASTER_PASSWORD --raw)"
export BW_SESSION="$SESSION"
export BW_MASTER_PASSWORD
BW_MASTER_PASSWORD="$(cat /run/secrets/bw_master_password)"

# bw needs BW_MASTER_PASSWORD as an env var for --passwordenv
# Re-export after the unlock call that consumed it
unset BW_MASTER_PASSWORD

# ── Sync vault to pick up any existing items ──────────────────────────────────

bw sync --session "$SESSION" > /dev/null

# ── Seed credentials ──────────────────────────────────────────────────────────

echo "Seeding credentials from $CREDENTIALS_FILE ..."

# Parse credentials.json and iterate. We use awk to extract name/value pairs
# without requiring jq (which may not be in the base image).
# Format expected: array of {"name":"...","value":"...","note":"..."} objects.
# We use python3 which is available in the bitwarden/cli image.

python3 - "$CREDENTIALS_FILE" "$SESSION" <<'PYEOF'
import json
import subprocess
import sys
import os

credentials_file = sys.argv[1]
session = sys.argv[2]

with open(credentials_file) as f:
    credentials = json.load(f)

# Get list of existing item names (to skip duplicates)
result = subprocess.run(
    ["bw", "list", "items", "--session", session],
    capture_output=True, text=True
)
try:
    existing_items = json.loads(result.stdout)
    existing_names = {item["name"] for item in existing_items}
except (json.JSONDecodeError, KeyError):
    existing_names = set()

created = 0
skipped = 0

for cred in credentials:
    name = cred["name"]
    value = cred["value"]
    note = cred.get("note", "")

    if name in existing_names:
        print(f"  skip (exists): {name}")
        skipped += 1
        continue

    # Build a Bitwarden Login item. Type 1 = Login.
    # bw serve GET /object/password/:name returns item.login.password.
    item = {
        "type": 1,
        "name": name,
        "notes": note,
        "login": {
            "username": None,
            "password": value,
            "uris": []
        }
    }

    # bw create item requires the JSON to be base64-encoded
    encoded = subprocess.run(
        ["bw", "encode"],
        input=json.dumps(item),
        capture_output=True, text=True
    ).stdout.strip()

    create_result = subprocess.run(
        ["bw", "create", "item", encoded, "--session", session],
        capture_output=True, text=True
    )

    if create_result.returncode == 0:
        print(f"  created: {name}")
        created += 1
    else:
        print(f"  ERROR creating {name}: {create_result.stderr}", file=sys.stderr)
        sys.exit(1)

print(f"\nDone. Created: {created}, Skipped (already existed): {skipped}")
PYEOF

# ── Lock the vault ────────────────────────────────────────────────────────────
# Leave bw serve in its pre-startup locked state. Ferrowarden will unlock it
# via its configured unlock mode when it starts.

bw lock --session "$SESSION" > /dev/null || true

echo "Seed complete."
