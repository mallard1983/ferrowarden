# The image of the test stack's one-shot setup and seed containers
# (docker-compose.test.yml: vault-setup and vault-seeder). It is only a Node.js
# runtime for the scripts below, which use Node's built-in crypto and HTTP
# client and nothing else: no npm packages and no Bitwarden CLI. Nothing in
# the default deployment runs Node; the internal CA is made by
# `ferrowarden internal-certs`.
FROM node:26-slim

# The entrypoint scripts use wget for Vaultwarden health checks; the slim
# image ships without it (nor curl).
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        wget \
    && rm -rf /var/lib/apt/lists/*

# Trust the internal CA (mounted from the internal-pki volume at /pki) for all
# Node.js HTTPS calls: bw-register.js, bw-apikey.js and the seeders. If the
# file is absent Node logs a warning and continues with the system CAs.
ENV NODE_EXTRA_CA_CERTS=/pki/ca.crt

# Helper scripts live in /usr/local/share/ferrowarden (world-readable), not in
# /home/node: setup containers may run as the invoking user's UID (see
# docker-compose.test.yml), and newer node images make /home/node private.
#
# bw-lib.js: the client cryptography (PBKDF2 and Argon2id key derivation,
# EncStrings, RSA) and HTTP helpers the scripts below share.
COPY bw-lib.js /usr/local/share/ferrowarden/bw-lib.js

# bw-register.js: performs Bitwarden-compatible account registration using
# only Node.js built-in crypto (no npm deps). TEST_KDF selects PBKDF2
# (default) or Argon2id.
COPY bw-register.js /usr/local/share/ferrowarden/bw-register.js

# bw-apikey.js: logs in (with the account's own KDF) and creates its API key.
COPY bw-apikey.js /usr/local/share/ferrowarden/bw-apikey.js

# bw-seed.js: seeds vault items via direct Vaultwarden API calls.
COPY bw-seed.js /usr/local/share/ferrowarden/bw-seed.js

# bw-seed-hidden.js: an item whose collection hides passwords from the test
# account (viewPassword = false), owned by a second account.
COPY bw-seed-hidden.js /usr/local/share/ferrowarden/bw-seed-hidden.js

# bw-read-item.js: the independent reader of the credential-create tests: it
# finds an item in the test account's sync and decrypts it with Node's crypto,
# printing only the SHA-256 of the password (docs/native-vault.md).
COPY bw-read-item.js /usr/local/share/ferrowarden/bw-read-item.js

# node:*-slim images ship with a non-root "node" user (UID 1000).
USER node
WORKDIR /home/node

ENTRYPOINT ["/bin/sh"]
