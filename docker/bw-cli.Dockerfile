FROM node:20-slim

# The entrypoint scripts use curl, wget, and python3 for Vaultwarden API calls
# and health checks. The slim image ships with none of these.
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
        wget \
        python3 \
    && rm -rf /var/lib/apt/lists/*

# Install the Bitwarden CLI globally.
# Pin to 2023.12.1 — the last version that accepts HTTP server URLs.
# Versions 2024.x+ require HTTPS, breaking the HTTP-only test stack.
# Account registration uses bw-register.js (see below) instead of a bw command,
# because `bw register` was removed before the 2023.x series.
RUN npm install -g @bitwarden/cli@2023.12.1 \
    && bw --version

# bw-register.js: performs Bitwarden-compatible account registration using
# only Node.js built-in crypto (no npm deps). The bw CLI never had a register
# command; this script calls POST /api/accounts/register directly.
COPY bw-register.js /home/node/bw-register.js

# bw-seed.js: seeds vault items via direct Vaultwarden API calls.
# bw CLI 2023.12.1 is incompatible with Vaultwarden 2026.x cipher format
# (missing encryptedFor field). This script bypasses the CLI entirely.
COPY bw-seed.js /home/node/bw-seed.js

# node:*-slim images ship with a non-root "node" user (UID 1000).
# bw stores its config in ~/.config/Bitwarden CLI. Create that directory now
# and chown it before switching users — Docker named volumes copy the image
# directory's ownership on first creation, so this ensures the node user can
# write to the volume mount.
RUN mkdir -p "/home/node/.config/Bitwarden CLI" \
    && chown -R node:node "/home/node/.config"
USER node
WORKDIR /home/node

ENTRYPOINT ["/bin/sh"]
