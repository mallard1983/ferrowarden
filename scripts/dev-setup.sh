#!/bin/sh
# scripts/dev-setup.sh
#
# Full automated dev/test environment setup.
# Run this once on a fresh checkout (or after wiping test data).
# After it completes, `docker compose -f docker-compose.test.yml up -d`
# will start the full test stack with no further manual steps.
#
# What this script does:
#   1. Generates secrets (master password, admin key) if they don't exist
#   2. Starts Vaultwarden with signups enabled
#   3. Runs vault-setup: registers the Vaultwarden account and writes
#      bw_client_id + bw_client_secret to secrets/
#   4. Disables Vaultwarden signups
#   5. Runs vault-seeder: populates the vault with test credentials
#   6. Starts the full test stack: bw-serve, mock-api and two Ferrowarden
#      instances against the same vault, one per vault backend (docs/native-vault.md):
#      `ferrowarden` (bw serve, port 3000) and `ferrowarden-native` (port 3003)
#   7. Creates a test agent key on each and writes them to secrets/
#   8. Writes .env.test (bw serve instance) and .env.test.native (native
#      instance) files with ready-to-use environment variable exports
#
# Usage:
#   ./scripts/dev-setup.sh
#
# To reset and start over:
#   docker compose -f docker-compose.test.yml down -v
#   rm -f secrets/bw_client_id secrets/bw_client_secret secrets/test_agent_key
#   ./scripts/dev-setup.sh

# Windows users: run scripts\dev-setup.ps1 instead (PowerShell 7+).
# This script requires bash and openssl or python3.

set -e

COMPOSE="docker compose -f docker-compose.test.yml"
SECRETS_DIR="./secrets"

# vault-setup runs as this user so it can write into ./secrets (see
# docker-compose.test.yml). Ignored by Docker Desktop.
HOST_UID="$(id -u)"
HOST_GID="$(id -g)"
export HOST_UID HOST_GID
FERROWARDEN_URL="${FERROWARDEN_URL:-http://localhost:3000}"
FERROWARDEN_NATIVE_URL="${FERROWARDEN_NATIVE_URL:-http://localhost:3003}"
FERROWARDEN_NATIVE_UI_URL="${FERROWARDEN_NATIVE_UI_URL:-http://localhost:3004}"

echo "=================================================="
echo " Ferrowarden Dev Environment Setup"
echo "=================================================="
echo ""

# ── Check prerequisites ───────────────────────────────────────────────────────

if ! command -v docker > /dev/null 2>&1; then
    echo "ERROR: docker is not installed or not on PATH" >&2
    exit 1
fi

if ! docker compose version > /dev/null 2>&1; then
    echo "ERROR: docker compose (v2) is required" >&2
    exit 1
fi

if ! command -v openssl > /dev/null 2>&1 && ! command -v python3 > /dev/null 2>&1; then
    echo "ERROR: openssl or python3 is required to generate secrets" >&2
    exit 1
fi

mkdir -p "$SECRETS_DIR"
mkdir -p ./certs

# ── Generate secrets (if not already present) ────────────────────────────────

echo "[1/7] Generating secrets..."

if [ ! -f "$SECRETS_DIR/bw_master_password" ]; then
    # For the test environment, we use a fixed well-known test password.
    # This is intentional: test fixtures need reproducibility.
    # This password protects only fake test credentials — never use it in production.
    printf 'ferrowarden-test-master-pw' > "$SECRETS_DIR/bw_master_password"
    echo "  Generated: bw_master_password (test fixture — intentionally simple)"
else
    echo "  Skipping: bw_master_password already exists"
fi

if [ ! -f "$SECRETS_DIR/ferrowarden_admin_key" ]; then
    if command -v openssl > /dev/null 2>&1; then
        openssl rand -base64 48 | tr -dc 'A-Za-z0-9' | head -c 48 \
            > "$SECRETS_DIR/ferrowarden_admin_key"
    else
        python3 -c "
import secrets, string
chars = string.ascii_letters + string.digits
print(''.join(secrets.choice(chars) for _ in range(48)), end='')
" > "$SECRETS_DIR/ferrowarden_admin_key"
    fi
    echo "  Generated: ferrowarden_admin_key"
else
    echo "  Skipping: ferrowarden_admin_key already exists"
fi

# Bearer token for the notifier's webhook to the mock API's notification sink
# (docker-compose.test.yml). Test fixture; the secret gate checks for it.
if [ ! -f "$SECRETS_DIR/notify_webhook_token" ]; then
    if command -v openssl > /dev/null 2>&1; then
        openssl rand -base64 48 | tr -dc 'A-Za-z0-9' | head -c 40 \
            > "$SECRETS_DIR/notify_webhook_token"
    else
        python3 -c "
import secrets, string
chars = string.ascii_letters + string.digits
print(''.join(secrets.choice(chars) for _ in range(40)), end='')
" > "$SECRETS_DIR/notify_webhook_token"
    fi
    echo "  Generated: notify_webhook_token"
else
    echo "  Skipping: notify_webhook_token already exists"
fi

# TEST FIXTURES ONLY: the test stack's containers run as UID 999
# (ferrowarden) and 1000 (bw serve), and Compose mounts file secrets with
# their host owner and mode, so make them readable to every UID. These
# protect only fake credentials. Production uses chown instead — see
# docs/setup.md.
chmod 644 "$SECRETS_DIR"/* 2>/dev/null || true

# ── Generate self-signed TLS certificate (if not already present) ────────────

echo ""
echo "[1b/7] Generating TLS certificate..."

if [ ! -f ./certs/server.crt ] || [ ! -f ./certs/server.key ]; then
    if command -v openssl > /dev/null 2>&1; then
        # EC P-256 (not Ed25519): Windows Schannel clients cannot validate
        # Ed25519 certificates. Most modern clients require the SAN.
        MSYS_NO_PATHCONV=1 openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
            -keyout ./certs/server.key \
            -out ./certs/server.crt \
            -days 365 -nodes \
            -subj "/CN=ferrowarden-test" \
            -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
            > /dev/null 2>&1
        # Dev-only throwaway key: world-readable so the container user (UID 999)
        # can read it through the bind mount (docker-compose.test-tls.yml).
        # Production keys must instead be chowned to 999 — see docs/setup.md.
        chmod 644 ./certs/server.key
        echo "  Generated: certs/server.crt + certs/server.key (self-signed, 1 year)"
        echo "  NOTE: This is a dev-only certificate. Import certs/server.crt into"
        echo "        your test HTTP client to skip certificate verification, or use"
        echo "        FERROWARDEN_TLS_ACCEPT_INVALID_CERTS=1 in test environments."
    else
        echo "  WARNING: openssl not found — skipping TLS cert generation."
        echo "  To use TLS, generate certs/server.crt and certs/server.key manually."
        echo "  See certs/README.md for instructions."
    fi
else
    echo "  Skipping: certs/server.crt and certs/server.key already exist"
fi

# ── Start Vaultwarden (signups enabled for initial account creation) ──────────

echo ""
echo "[2/7] Starting Vaultwarden (signups enabled)..."
VAULTWARDEN_SIGNUPS_ALLOWED=true $COMPOSE up -d vaultwarden

# Give Vaultwarden a moment to initialize before the setup container connects
sleep 3

# ── Run vault-setup (register account + create API key) ───────────────────────

echo ""
echo "[3/7] Creating Vaultwarden account and API key..."

# VAULTWARDEN_SIGNUPS_ALLOWED must be set for compose itself (not just with -e):
# `run` re-applies the vaultwarden service config, and without it compose would
# recreate Vaultwarden with signups disabled before registration runs.
VAULTWARDEN_SIGNUPS_ALLOWED=true $COMPOSE run --rm \
    -e SETUP_EMAIL="${SETUP_EMAIL:-admin@ferrowarden.test}" \
    -e SETUP_MASTER_PASSWORD="$(cat "$SECRETS_DIR/bw_master_password")" \
    vault-setup

chmod 644 "$SECRETS_DIR/bw_client_id" "$SECRETS_DIR/bw_client_secret"   # test fixtures; see above
echo "  API credentials written to secrets/"

# ── Disable signups ────────────────────────────────────────────────────────────

echo ""
echo "[4/7] Disabling Vaultwarden signups..."
$COMPOSE stop vaultwarden
VAULTWARDEN_SIGNUPS_ALLOWED=false $COMPOSE up -d vaultwarden
sleep 2
echo "  Signups disabled."

# ── Run vault-seeder ──────────────────────────────────────────────────────────

echo ""
echo "[5/7] Seeding test credentials..."
$COMPOSE run --rm vault-seeder

# ── Start the full test stack ─────────────────────────────────────────────────

echo ""
echo "[6/7] Starting full test stack (bw-serve, ferrowarden, ferrowarden-native, mock-api)..."
$COMPOSE up -d bw-serve mock-api

echo "  Waiting for bw-serve to initialize (this takes ~15s)..."
elapsed=0
until curl -sf "http://localhost:8087/status" > /dev/null 2>&1 || [ "$elapsed" -ge 60 ]; do
    sleep 3
    elapsed=$((elapsed + 3))
done

$COMPOSE up -d ferrowarden ferrowarden-native

# Both instances: the bw serve one on 3000, the native one on 3003.
wait_for_ferrowarden() {
    url="$1"; service="$2"
    echo "  Waiting for $service to unlock and start accepting requests..."
    elapsed=0
    until curl -sf "$url/v1/admin/status" \
            -H "X-Admin-Key: $(cat "$SECRETS_DIR/ferrowarden_admin_key")" > /dev/null 2>&1; do
        if [ "$elapsed" -ge 90 ]; then
            echo "  ERROR: $service did not become ready within 90s" >&2
            $COMPOSE logs "$service" >&2
            exit 1
        fi
        sleep 3
        elapsed=$((elapsed + 3))
    done
}
wait_for_ferrowarden "$FERROWARDEN_URL" ferrowarden
wait_for_ferrowarden "$FERROWARDEN_NATIVE_URL" ferrowarden-native

echo "  Stack is healthy."

# ── Create test agent key ─────────────────────────────────────────────────────

echo ""
echo "[7/7] Creating test agent keys..."

ADMIN_KEY="$(cat "$SECRETS_DIR/ferrowarden_admin_key")"

# One key per instance (each has its own key store).
create_agent_key() {
    url="$1"; out="$2"
    response=$(curl -sf -X POST "$url/v1/admin/keys" \
        -H "X-Admin-Key: $ADMIN_KEY" \
        -H "Content-Type: application/json" \
        -d '{"name": "integration-test-agent", "credentials": ["*"], "methods": ["*"]}')
    token=$(printf '%s' "$response" | python3 -c "
import sys, json
print(json.load(sys.stdin).get('token', ''), end='')
" 2>/dev/null)
    if [ -z "$token" ]; then
        echo "  WARNING: failed to create the agent key at $url — check the ferrowarden logs" >&2
    else
        printf '%s' "$token" > "$out"
        chmod 600 "$out"
        echo "  Agent key written to $out"
    fi
}
create_agent_key "$FERROWARDEN_URL" "$SECRETS_DIR/test_agent_key"
create_agent_key "$FERROWARDEN_NATIVE_URL" "$SECRETS_DIR/test_agent_key_native"

# ── Write .env.test ───────────────────────────────────────────────────────────

cat > .env.test <<EOF
# Auto-generated by scripts/dev-setup.sh
# Source this file to configure integration tests:
#   source .env.test && cargo test --test integration
#
# These values are for the test environment only. Never use in production.

FERROWARDEN_INTEGRATION=1
FERROWARDEN_TEST_URL=$FERROWARDEN_URL
FERROWARDEN_TEST_ADMIN_KEY=$(cat "$SECRETS_DIR/ferrowarden_admin_key")
FERROWARDEN_TEST_AGENT_KEY=$(cat "$SECRETS_DIR/test_agent_key" 2>/dev/null || echo "")
FERROWARDEN_TEST_NOTIFY_TOKEN=$(cat "$SECRETS_DIR/notify_webhook_token")
MOCK_API_URL=http://localhost:7777
EOF

# The same for the native instance: run the whole suite against it with
#   set -a; . ./.env.test.native; set +a; cargo test --test integration -- --test-threads=1
cat > .env.test.native <<EOF
# Auto-generated by scripts/dev-setup.sh: the integration tests against the
# ferrowarden-native instance (vault.backend = native). Test environment only.

FERROWARDEN_INTEGRATION=1
FERROWARDEN_TEST_URL=$FERROWARDEN_NATIVE_URL
FERROWARDEN_TEST_UI_URL=$FERROWARDEN_NATIVE_UI_URL
FERROWARDEN_TEST_ADMIN_KEY=$(cat "$SECRETS_DIR/ferrowarden_admin_key")
FERROWARDEN_TEST_AGENT_KEY=$(cat "$SECRETS_DIR/test_agent_key_native" 2>/dev/null || echo "")
FERROWARDEN_TEST_NOTIFY_TOKEN=$(cat "$SECRETS_DIR/notify_webhook_token")
MOCK_API_URL=http://localhost:7777
FERROWARDEN_NATIVE_URL=$FERROWARDEN_NATIVE_URL
EOF

echo ""
echo "=================================================="
echo " Setup complete."
echo "=================================================="
echo ""
echo "Services running:"
$COMPOSE ps
echo ""
echo "To run integration tests (bw serve instance), then the same suite and the"
echo "equivalence suite against the native instance:"
echo "  set -a; . ./.env.test; set +a; cargo test --test integration -- --test-threads=1"
echo "  cargo test --test equivalence -- --nocapture --test-threads=1"
echo "  set -a; . ./.env.test.native; set +a; cargo test --test integration -- --test-threads=1"
echo ""
echo "To stop the stack:"
echo "  docker compose -f docker-compose.test.yml down"
echo ""
echo "To reset everything:"
echo "  docker compose -f docker-compose.test.yml down -v"
echo "  rm -f secrets/bw_client_id secrets/bw_client_secret secrets/test_agent_key"
echo "  ./scripts/dev-setup.sh"
