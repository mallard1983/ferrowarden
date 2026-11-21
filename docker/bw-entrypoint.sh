#!/bin/sh
# bw-entrypoint.sh
#
# Configure the Bitwarden CLI to point at Vaultwarden, log in using the
# API key from Docker secrets, and start bw serve.
#
# bw serve starts LOCKED — ferrowarden will unlock it via POST /unlock
# on startup (file mode) or on operator request (manual mode).
#
# BW_SERVER_URL must be https:// — current CLI releases refuse plain HTTP.
# The internal CA that signs Vaultwarden's certificate is trusted through
# NODE_EXTRA_CA_CERTS (set in bw-cli.Dockerfile).

set -e

BW_CLIENT_ID_FILE="/run/secrets/bw_client_id"
BW_CLIENT_SECRET_FILE="/run/secrets/bw_client_secret"

if [ ! -f "$BW_CLIENT_ID_FILE" ] || [ ! -f "$BW_CLIENT_SECRET_FILE" ]; then
    echo "ERROR: bw_client_id and bw_client_secret secrets must be mounted" >&2
    exit 1
fi

if [ -n "$NODE_EXTRA_CA_CERTS" ] && [ ! -f "$NODE_EXTRA_CA_CERTS" ]; then
    echo "ERROR: internal CA certificate not found at $NODE_EXTRA_CA_CERTS" >&2
    echo "       (is the internal-pki volume mounted and internal-certs done?)" >&2
    exit 1
fi

BW_CLIENTID="$(cat "$BW_CLIENT_ID_FILE")"
BW_CLIENTSECRET="$(cat "$BW_CLIENT_SECRET_FILE")"
export BW_CLIENTID BW_CLIENTSECRET

# Point the CLI at Vaultwarden, not bitwarden.com. The CLI refuses to change
# the server while logged in, so with a persistent bw-data volume we only
# change it (logging out first) when it actually differs — e.g. after the
# move from http://vaultwarden:80 to https://vaultwarden.
CURRENT_SERVER="$(bw config server 2>/dev/null || true)"
if [ "$CURRENT_SERVER" != "$BW_SERVER_URL" ]; then
    if bw login --check > /dev/null 2>&1; then
        echo "Server URL changed ($CURRENT_SERVER -> $BW_SERVER_URL); logging out first."
        bw logout > /dev/null 2>&1 || true
    fi
    bw config server "$BW_SERVER_URL"
fi

# Log in using the API key (non-interactive, scriptable).
# This stores an encrypted local vault copy — the master password is NOT
# required for login, only for unlock.
#
# With a persistent bw-data volume the CLI is still logged in after a
# container restart, and `bw login` would then fail ("You are already logged
# in"), which under `set -e` would crash-loop the container. Only log in when
# needed.
if bw login --check > /dev/null 2>&1; then
    echo "bw CLI already logged in; skipping login."
else
    bw login --apikey
fi

# bw serve starts with the vault locked. Ferrowarden will POST /unlock
# with the master password once it starts.
#
# bw serve rejects requests whose Host header is not localhost/127.0.0.1/[::1]
# or the --hostname below (DNS-rebinding protection), so BW_SERVE_HOSTNAME must
# be the name clients use: "bw-serve" in Docker Compose.
exec bw serve \
    --hostname "${BW_SERVE_HOSTNAME:-localhost}" \
    --port "${BW_SERVE_PORT:-8087}"
