FROM node:26-slim

# The entrypoint scripts use curl, wget, and python3 for Vaultwarden API calls
# and health checks; openssl generates the internal CA and Vaultwarden
# certificate (gen-internal-certs.sh). The slim image ships with none of these.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        wget \
        python3 \
        openssl \
    && rm -rf /var/lib/apt/lists/*

# Install the Bitwarden CLI globally. Pinned: bump deliberately and re-run the
# integration tests (the bw serve API shape is part of ferrowarden's contract).
# The CLI requires Node 22+ and refuses plain-HTTP server URLs, which is why
# Vaultwarden is served over HTTPS on the internal network (see
# gen-internal-certs.sh and docker-compose.yml).
RUN npm install -g @bitwarden/cli@2026.11.0 \
    && bw --version

# Trust the internal CA (mounted from the internal-pki volume at /pki) for all
# Node.js HTTPS calls: the bw CLI, bw-register.js and bw-seed.js. If the file
# is absent Node logs a warning and continues with the system CAs.
ENV NODE_EXTRA_CA_CERTS=/pki/ca.crt

# bw-register.js: performs Bitwarden-compatible account registration using
# only Node.js built-in crypto (no npm deps). The bw CLI has no register
# command; this script calls POST /api/accounts/register directly.
COPY bw-register.js /home/node/bw-register.js

# bw-seed.js: seeds vault items via direct Vaultwarden API calls, so the test
# fixtures do not depend on CLI item-creation behaviour.
COPY bw-seed.js /home/node/bw-seed.js

# Internal certificate generator, run by the one-shot internal-certs service.
COPY gen-internal-certs.sh /usr/local/bin/gen-internal-certs.sh

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
