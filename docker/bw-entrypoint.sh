#!/bin/sh
# bw-entrypoint.sh
#
# Configure the Bitwarden CLI to point at Vaultwarden, log in using the
# API key from Docker secrets, and start bw serve.
#
# bw serve starts LOCKED — ferrowarden will unlock it via POST /unlock
# on startup (file mode) or on operator request (manual mode).

set -e

BW_CLIENT_ID_FILE="/run/secrets/bw_client_id"
BW_CLIENT_SECRET_FILE="/run/secrets/bw_client_secret"

if [ ! -f "$BW_CLIENT_ID_FILE" ] || [ ! -f "$BW_CLIENT_SECRET_FILE" ]; then
    echo "ERROR: bw_client_id and bw_client_secret secrets must be mounted" >&2
    exit 1
fi

BW_CLIENTID="$(cat "$BW_CLIENT_ID_FILE")"
BW_CLIENTSECRET="$(cat "$BW_CLIENT_SECRET_FILE")"
export BW_CLIENTID BW_CLIENTSECRET

# Point the CLI at Vaultwarden, not bitwarden.com
bw config server "$BW_SERVER_URL"

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
exec bw serve \
    --hostname "${BW_SERVE_HOSTNAME:-0.0.0.0}" \
    --port "${BW_SERVE_PORT:-8087}"
