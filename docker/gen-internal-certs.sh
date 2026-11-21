#!/bin/sh
# gen-internal-certs.sh
#
# Creates the private CA and Vaultwarden server certificate used on the
# internal Docker network. The Bitwarden CLI (2024.x and later) refuses plain
# HTTP server URLs, so bw serve must reach Vaultwarden over HTTPS even though
# the hop never leaves the vault-internal network.
#
# Idempotent:
#   - the CA (10 years) is created once and reused;
#   - the Vaultwarden certificate is (re)issued when missing, when it expires
#     within 30 days, or when it was not signed by the current CA.
#
# Output (in $PKI_DIR, a named volume shared read-only with other services):
#   ca.crt            CA certificate — trusted by bw serve, setup and seeder
#   ca.key            CA private key — never leaves this volume
#   vaultwarden.crt   Server certificate, SAN DNS:${VW_HOSTNAME}
#   vaultwarden.key   Server private key
#
# These certificates are only for the internal hop. The agent-facing TLS
# certificate for ferrowarden is separate (certs/server.crt, or a reverse
# proxy such as Pangolin).

set -e

PKI_DIR="${PKI_DIR:-/pki}"
VW_HOSTNAME="${VW_HOSTNAME:-vaultwarden}"
umask 077
mkdir -p "$PKI_DIR"
cd "$PKI_DIR"

if [ ! -f ca.crt ] || [ ! -f ca.key ]; then
    echo "[certs] Creating internal CA"
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
        -days 3650 -subj "/CN=ferrowarden-internal-ca" \
        -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" \
        -keyout ca.key -out ca.crt 2>/dev/null
    rm -f vaultwarden.crt   # force a re-issue under the new CA
else
    echo "[certs] Internal CA exists"
fi

needs_issue=0
if [ ! -f vaultwarden.crt ] || [ ! -f vaultwarden.key ]; then
    needs_issue=1
elif ! openssl x509 -in vaultwarden.crt -noout -checkend 2592000 >/dev/null 2>&1; then
    echo "[certs] Vaultwarden certificate expires within 30 days"
    needs_issue=1
elif ! openssl verify -CAfile ca.crt vaultwarden.crt >/dev/null 2>&1; then
    echo "[certs] Vaultwarden certificate not signed by the current CA"
    needs_issue=1
elif ! openssl x509 -in vaultwarden.crt -noout -ext subjectAltName 2>/dev/null | grep -q "DNS:${VW_HOSTNAME}\$"; then
    echo "[certs] Vaultwarden certificate host name changed"
    needs_issue=1
fi

if [ "$needs_issue" = 1 ]; then
    echo "[certs] Issuing Vaultwarden certificate for ${VW_HOSTNAME}"
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
        -subj "/CN=${VW_HOSTNAME}" -keyout vaultwarden.key -out vaultwarden.csr 2>/dev/null
    printf 'subjectAltName=DNS:%s\nextendedKeyUsage=serverAuth\nkeyUsage=critical,digitalSignature\nbasicConstraints=critical,CA:FALSE\n' \
        "$VW_HOSTNAME" > vaultwarden.ext
    openssl x509 -req -in vaultwarden.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
        -days 825 -extfile vaultwarden.ext -out vaultwarden.crt 2>/dev/null
    rm -f vaultwarden.csr vaultwarden.ext
else
    echo "[certs] Vaultwarden certificate is valid"
fi

# The CA certificate is public; other containers (running as non-root users)
# must be able to read it. Private keys stay owner-only.
chmod 644 ca.crt vaultwarden.crt
chmod 600 ca.key vaultwarden.key
echo "[certs] Done"
