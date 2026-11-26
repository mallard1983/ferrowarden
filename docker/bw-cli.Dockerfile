FROM node:26-slim

# The entrypoint scripts use curl and wget for Vaultwarden health checks; the
# slim image ships with neither. (The account setup and the seeders are
# Node.js scripts: no Python. This image is only for the test setup scripts and
# the deprecated bw-serve: the default deployment runs no Node at all, and the
# internal CA is made by `ferrowarden internal-certs`.)
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        wget \
    && rm -rf /var/lib/apt/lists/*

# Install the Bitwarden CLI globally. Pinned: bump deliberately and re-run the
# integration tests (the bw serve API shape is part of ferrowarden's contract).
# BW_CLI_VERSION (docker-compose.test.yml, env BW_CLI_VERSION) selects another
# release: a CLI can only sync a vault written by a Vaultwarden release
# contemporary with it, so the CI job that tests the previous Vaultwarden
# minor uses the CLI of its time (docs/cicd.md).
# The CLI requires Node 22+ and refuses plain-HTTP server URLs, which is why
# Vaultwarden is served over HTTPS on the internal network (see
# docs/tls.md and docker-compose.yml).
ARG BW_CLI_VERSION=2026.11.0
RUN npm install -g @bitwarden/cli@${BW_CLI_VERSION} \
    && bw --version

# Trust the internal CA (mounted from the internal-pki volume at /pki) for all
# Node.js HTTPS calls: the bw CLI, bw-register.js and bw-seed.js. If the file
# is absent Node logs a warning and continues with the system CAs.
ENV NODE_EXTRA_CA_CERTS=/pki/ca.crt

# Helper scripts live in /usr/local/share/ferrowarden (world-readable), not in
# /home/node: setup containers may run as the invoking user's UID (see
# docker-compose.test.yml), and newer node images make /home/node private.
#
# bw-lib.js: the client cryptography (PBKDF2 and Argon2id key derivation,
# EncStrings, RSA) and HTTP helpers the scripts below share.
COPY bw-lib.js /usr/local/share/ferrowarden/bw-lib.js

# bw-register.js: performs Bitwarden-compatible account registration using
# only Node.js built-in crypto (no npm deps). The bw CLI has no register
# command; this script calls the registration endpoints directly. TEST_KDF
# selects PBKDF2 (default) or Argon2id.
COPY bw-register.js /usr/local/share/ferrowarden/bw-register.js

# bw-apikey.js: logs in (with the account's own KDF) and creates its API key.
COPY bw-apikey.js /usr/local/share/ferrowarden/bw-apikey.js

# bw-seed.js: seeds vault items via direct Vaultwarden API calls, so the test
# fixtures do not depend on CLI item-creation behaviour.
COPY bw-seed.js /usr/local/share/ferrowarden/bw-seed.js

# bw-seed-hidden.js: an item whose collection hides passwords from the test
# account (viewPassword = false), owned by a second account.
COPY bw-seed-hidden.js /usr/local/share/ferrowarden/bw-seed-hidden.js

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
