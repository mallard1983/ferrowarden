#!/bin/sh
# ferrowarden-entrypoint.sh
#
# Read Docker secrets into environment variables before starting ferrowarden.
# Docker secrets are files, not env vars — this bridge is intentional:
# it keeps secret values out of `docker inspect` output and process listings
# while still making them available to the application.

set -e

# Admin key: required. Read from secret file if FERROWARDEN_ADMIN_KEY is not
# already set directly (direct env var takes precedence for non-Docker use).
if [ -z "$FERROWARDEN_ADMIN_KEY" ] && [ -n "$FERROWARDEN_ADMIN_KEY_FILE" ]; then
    if [ ! -f "$FERROWARDEN_ADMIN_KEY_FILE" ]; then
        echo "ERROR: FERROWARDEN_ADMIN_KEY_FILE does not exist: $FERROWARDEN_ADMIN_KEY_FILE" >&2
        exit 1
    fi
    FERROWARDEN_ADMIN_KEY="$(cat "$FERROWARDEN_ADMIN_KEY_FILE")"
    export FERROWARDEN_ADMIN_KEY
fi

if [ -z "$FERROWARDEN_ADMIN_KEY" ]; then
    echo "ERROR: FERROWARDEN_ADMIN_KEY must be set (directly or via FERROWARDEN_ADMIN_KEY_FILE)" >&2
    exit 1
fi

exec /app/ferrowarden
