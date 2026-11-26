# TLS Configuration

Ferrowarden's proxy endpoint carries real credential values on every forwarded request. Encrypting that connection is mandatory whenever the agent and Ferrowarden communicate over a network. This document covers both ways to achieve that.

---

## Choosing an Approach

| Approach | When to use |
|---|---|
| **Option A: Behind a TLS proxy** (Pangolin, Caddy, Nginx, Traefik) | You already run a reverse proxy in your homelab, or you want a real certificate from Let's Encrypt without managing cert rotation. Recommended. |
| **Option B: Ferrowarden's built-in TLS** with a local CA | No existing reverse proxy; you want a direct TLS connection; or the agent is on a different host with no proxy in between. |
| **No TLS** (`tls_enabled = false`) | Only acceptable when the agent and Ferrowarden run on the same host with no network hop — e.g. two containers on the same Docker network on the same machine. Ferrowarden logs a prominent warning. |

---

## Option A: Behind a Reverse Proxy

When a TLS-terminating proxy sits in front of Ferrowarden, the proxy handles the certificate. Ferrowarden sees plain HTTP from the proxy.

### Pangolin

[Pangolin](https://github.com/fosrl/pangolin) is a self-hosted tunnelling and reverse proxy stack that provisions Let's Encrypt certificates automatically. It is a natural fit for homelab use where you do not want to manage certificate rotation yourself.

**Architecture:**

```
Agent  ──HTTPS──►  Pangolin (Let's Encrypt cert)  ──HTTP──►  Ferrowarden
                   (public or LAN interface)         (internal Docker network)
```

**When this is safe without internal TLS:**
Pangolin and Ferrowarden must run on the same host (same Docker Compose stack or same machine). The HTTP hop between Pangolin and Ferrowarden is then on `localhost` or an internal bridge network — it never crosses a physical network segment. If they are on different hosts, that internal segment must also be encrypted (use a WireGuard tunnel, which Pangolin can provide).

**Ferrowarden configuration (`docker-compose.yml`):**

```yaml
ferrowarden:
  environment:
    # TLS is terminated at Pangolin; the Pangolin → ferrowarden hop is
    # on the same Docker network. No certificate files are needed here.
    FERROWARDEN_TLS_ENABLED: "false"
    FERROWARDEN_BIND_ADDR: "0.0.0.0:3000"
  # Do NOT expose ferrowarden's port to the host — only Pangolin needs it.
  # Remove the `ports:` section and let Pangolin reach it by service name.
  networks:
    - vault-internal
    - pangolin-network   # whatever network Pangolin uses to reach backends
```

Point Pangolin at `http://ferrowarden:3000` as the upstream. Pangolin provides the public HTTPS endpoint; your agent connects to Pangolin's URL.

**Match the target scheme to Ferrowarden.** If the Pangolin target (site resource) is configured as `https://…:3000`, Pangolin opens a TLS connection to Ferrowarden. A plaintext Ferrowarden then answers with garbage and Pangolin returns a bare `500 Internal Server Error`. Either set the target to `http://`, or keep it `https://` and enable Ferrowarden's built-in TLS (`FERROWARDEN_TLS_ENABLED=true` with a certificate — a self-signed/local-CA certificate is accepted by Pangolin). The second option encrypts the Pangolin → Ferrowarden hop too, which is what you want whenever that hop crosses a network. Both setups were tested end to end with a Let's Encrypt certificate at Pangolin.

A `504 Gateway Timeout` from Pangolin usually means it cannot reach the port at all — e.g. Ferrowarden is published on `127.0.0.1` only while Pangolin's connector reaches the host on another interface.

**Putting the site behind SSO.** Agents cannot complete an SSO login, so add a bypass rule (in Pangolin, a resource rule that allows a path without authentication) for the agent endpoints only:

| Path | Who calls it | Bypass SSO? |
|---|---|---|
| `{prefix}/v1/forward`, `{prefix}/v1/credentials` | Agents (`X-Agent-Key`) | Yes |
| `/health` | Monitoring | Optional |
| `{prefix}/v1/admin/*`, `{prefix}/v1/unlock` | Operator (`X-Admin-Key`) | No — call these from inside your network, or add a separate rule |

`{prefix}` is `api_prefix` (empty by default). Setting a hard-to-guess prefix such as `/k7f3q9` means the bypass rule only matches a path scanners do not know — a cheap extra layer, though the agent key remains the real control.

**Rate limiting behind Pangolin.** Every request reaches Ferrowarden from Pangolin's connector address, so all agents would share one rate-limit bucket. Set `FERROWARDEN_TRUSTED_PROXIES` to that address (for a connector running on the Docker host and reaching a published port, typically the Docker bridge gateway, e.g. `172.17.0.1`) and Ferrowarden will rate-limit by the client IP in `X-Forwarded-For`. Only list the proxy itself — any client in that range could otherwise forge the header.

**Testing through Pangolin with the test stack:** `docker-compose.test-tls.yml` serves the test stack's Ferrowarden over TLS on all interfaces; see the comments in that file.

### Generic proxy (Caddy, Nginx, Traefik)

The same pattern applies to any TLS-terminating proxy:

1. Set `FERROWARDEN_TLS_ENABLED=false` and remove the cert volume mounts.
2. Put the proxy on a shared Docker network with Ferrowarden.
3. Configure the proxy to forward to `http://ferrowarden:3000` (or the internal IP/hostname).
4. Do **not** expose Ferrowarden's port to the host — only the proxy should reach it.

---

## The Vaultwarden Web Vault

The web vault (your password manager) is published separately from Ferrowarden, on `VAULTWARDEN_PUBLISH:VAULTWARDEN_PORT` (default `127.0.0.1:8443`). It always serves HTTPS, using a certificate from the stack's internal CA (the `internal-pki` volume).

**Behind Pangolin (or any reverse proxy):** in `.env` set

```sh
VAULTWARDEN_PUBLISH=0.0.0.0
VAULTWARDEN_DOMAIN=https://vault.example.com
```

and point the proxy at `https://<this-host>:8443`. Pangolin accepts the internal-CA certificate on the backend and presents its own Let's Encrypt certificate to browsers. Putting the site behind SSO works for the browser; Bitwarden mobile/desktop apps and browser extensions cannot complete an SSO login, so if you use them through the proxy, bypass SSO for `/api/*`, `/identity/*`, `/notifications/*` and `/icons/*` (the web vault UI itself can stay behind SSO). Enable two-step login on your Vaultwarden account either way.

**Directly on your LAN:** set `VAULTWARDEN_PUBLISH` to the host's LAN address (or `0.0.0.0`), add the names and IPs you browse with to `VAULTWARDEN_CERT_SANS` (e.g. `localhost,127.0.0.1,vault.lan,192.168.1.20`), and install the internal CA on your devices to avoid certificate warnings:

```sh
docker compose run --rm internal-certs                     # (re)issues the cert with the new names
docker compose cp internal-certs:/pki/ca.crt ./vault-ca.crt  # then trust vault-ca.crt (see Step 4 below)
docker compose restart vaultwarden
```

### The internal CA: how it is made

The internal CA and the web vault's certificate are made by `ferrowarden internal-certs`, a subcommand of the same static binary that runs the proxy. The `internal-certs` service in `docker-compose.yml` runs it once on every `docker compose up`, from the Ferrowarden image. The default deployment therefore contains no Node.js, no shell and no openssl for this job, and the code that handles the CA key is the code you already audit.

It reads the same settings as the shell script it replaced (set them in the service's `environment:`, or `VAULTWARDEN_CERT_SANS` in `.env`):

| Variable | Default | Meaning |
|---|---|---|
| `PKI_DIR` | `/pki` | The `internal-pki` volume: CA, certificate, keys. |
| `CA_PUBLIC_DIR` | `/ca-public` | The `internal-ca-public` volume: a copy of `ca.crt`, nothing else. Ferrowarden mounts this one. |
| `VW_HOSTNAME` | `vaultwarden` | The certificate's subject and first name. |
| `VW_EXTRA_SANS` | empty | Comma-separated extra names and IP addresses. An entry with `:` is an IPv6 address, an entry of only digits and dots is an IPv4 address, anything else is a DNS name. Spaces are ignored and empty entries skipped. An entry that does not parse is an error that names it, and nothing is written. |

Files in `PKI_DIR`, as before:

| File | Mode | What it is |
|---|---|---|
| `ca.crt` | 0644 | The CA certificate: ECDSA P-256, `CN=ferrowarden-internal-ca`, valid 10 years, `CA:TRUE, pathlen:0`. |
| `ca.key` | 0600 | The CA private key (PKCS#8). It never leaves this volume. |
| `vaultwarden.crt` | 0644 | The server certificate: ECDSA P-256, valid 825 days, `serverAuth` only, the names above as SANs. |
| `vaultwarden.key` | 0600 | The server private key (PKCS#8). |
| `vaultwarden.sans` | 0644 | The SAN list the certificate was issued for, for example `DNS:vaultwarden,DNS:localhost,IP:127.0.0.1`. |

Every file is written to a temporary file in the same directory, synced and renamed, so a reader never sees a half-written file, and a private key is created with mode 0600 from its first byte. Only `ca.crt` is copied to `CA_PUBLIC_DIR`, on every run. Nothing it prints or logs contains key material.

**Renewal rules.** The CA is created once and reused. That includes a CA made by an earlier release with openssl: an existing install keeps its CA, so Ferrowarden and anything you imported `ca.crt` into keep trusting it, and a certificate issued now under that CA verifies against it. The server certificate is issued again when:

- `vaultwarden.crt` or `vaultwarden.key` is missing;
- it would not verify against the current `ca.crt` 30 days from now: it is expiring, expired, or was signed by another CA (checked with rustls-webpki, for server authentication and for every configured name);
- `vaultwarden.sans` differs from the configured names; or
- the CA was just created.

Each run says which: `[certs] Internal CA exists`, `[certs] Vaultwarden certificate is valid`, or the reason followed by `[certs] Issuing Vaultwarden certificate for ...`. Vaultwarden loads its certificate at start, so restart it after a renewal (`docker compose restart vaultwarden`).

**Regenerating.** Delete `ca.crt` and `ca.key` from the `internal-pki` volume (or remove the volume) and run `docker compose up -d` again: a new CA and certificate are made and the public copy follows. Ferrowarden picks up the new CA on restart. Anyone who imported the old `ca.crt` must import the new one.

**The one-shot's hardening.** It runs with no network (`network_mode: none`), a read-only root filesystem, every capability dropped and `no-new-privileges`. It runs as root only because the `internal-pki` volume (also those made by earlier releases) is root-owned with mode-0600 keys and Vaultwarden runs as root; as root without `CAP_DAC_OVERRIDE` or `CAP_CHOWN` it can only write files it owns.

---

## Option B: Built-in TLS with a Local Certificate Authority

For direct TLS (no proxy), generate a local CA and sign a server certificate with it. Installing the CA once on every machine that connects means all future certs you issue from it are trusted automatically — you do not need to distribute individual server certs.

### Why a local CA instead of a bare self-signed cert

A bare self-signed certificate (the same cert that is both the CA and the server cert) must be explicitly trusted on every client machine for every server you run. With a local CA:

- Install the CA certificate **once** on each machine.
- Issue as many server certs as you need — they are all trusted immediately.
- When a cert expires, replace only the server cert; you do not need to re-trust anything.

### Step 1: Generate the Root CA

Run these commands once. Keep `ca.key` somewhere safe — anyone who has it can issue certs trusted by your machines.

**Linux/Mac:**
```sh
mkdir -p certs

# CA private key — keep this secret
openssl genrsa -out certs/ca.key 4096

# Self-signed CA certificate — 10 years is fine for a local CA
openssl req -x509 -new -nodes \
    -key certs/ca.key \
    -sha256 -days 3650 \
    -out certs/ca.crt \
    -subj "/CN=Homelab CA/O=Homelab"
```

**Windows (PowerShell):**
```powershell
New-Item -ItemType Directory -Force certs | Out-Null

openssl genrsa -out certs\ca.key 4096

openssl req -x509 -new -nodes `
    -key certs\ca.key `
    -sha256 -days 3650 `
    -out certs\ca.crt `
    -subj '/CN=Homelab CA/O=Homelab'
```

### Step 2: Generate the Server Certificate

Modern TLS stacks (curl, browsers, Go, Rust's rustls) reject certificates that do not include a Subject Alternative Name (SAN). The Common Name (CN) alone is no longer sufficient. The extension file below sets the SANs.

**Linux/Mac:**
```sh
# Server private key
openssl genrsa -out certs/server.key 2048

# Certificate signing request
openssl req -new \
    -key certs/server.key \
    -out certs/server.csr \
    -subj "/CN=ferrowarden"

# SAN extension file — list every hostname and IP the cert should cover
cat > certs/server.ext << 'EOF'
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=@alt_names

[alt_names]
DNS.1=ferrowarden
DNS.2=ferrowarden.lan
# Add your server's IP or hostname here:
IP.1=192.168.1.100
EOF

# Sign with the CA — 825 days keeps macOS/iOS happy (they cap server certs)
openssl x509 -req \
    -in certs/server.csr \
    -CA certs/ca.crt \
    -CAkey certs/ca.key \
    -CAcreateserial \
    -out certs/server.crt \
    -days 825 \
    -sha256 \
    -extfile certs/server.ext

chmod 400 certs/server.key
```

**Windows (PowerShell):**
```powershell
openssl genrsa -out certs\server.key 2048

openssl req -new `
    -key certs\server.key `
    -out certs\server.csr `
    -subj '/CN=ferrowarden'

# Write the extension file
@'
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=@alt_names

[alt_names]
DNS.1=ferrowarden
DNS.2=ferrowarden.lan
IP.1=192.168.1.100
'@ | Set-Content certs\server.ext -Encoding UTF8

openssl x509 -req `
    -in certs\server.csr `
    -CA certs\ca.crt `
    -CAkey certs\ca.key `
    -CAcreateserial `
    -out certs\server.crt `
    -days 825 `
    -sha256 `
    -extfile certs\server.ext
```

Edit `server.ext` to match your environment — replace the IP address and add any additional hostnames. If you access Ferrowarden by IP rather than hostname, the IP entry is what matters.

### Step 3: Configure Ferrowarden

The cert and key go in `certs/` and are bind-mounted into the container by `docker-compose.yml` (this is already set up by default):

```yaml
volumes:
  - ./certs/server.crt:/run/certs/server.crt:ro
  - ./certs/server.key:/run/certs/server.key:ro
environment:
  FERROWARDEN_TLS_ENABLED: "true"
  FERROWARDEN_TLS_CERT_FILE: "/run/certs/server.crt"
  FERROWARDEN_TLS_KEY_FILE:  "/run/certs/server.key"
```

The CA cert (`certs/ca.crt`) is not needed by Ferrowarden — only by the machines that connect to it.

### Step 4: Trust the CA on Each Connecting Machine

Do this on every machine where the agent runs (and any machine you will use to call the admin API).

**Debian / Ubuntu:**
```sh
sudo cp certs/ca.crt /usr/local/share/ca-certificates/homelab-ca.crt
sudo update-ca-certificates
```

**RHEL / Fedora / CentOS / Rocky:**
```sh
sudo cp certs/ca.crt /etc/pki/ca-trust/source/anchors/homelab-ca.crt
sudo update-ca-trust
```

**Arch Linux:**
```sh
sudo cp certs/ca.crt /etc/ca-certificates/trust-source/anchors/homelab-ca.crt
sudo trust extract-compat
```

**Windows (PowerShell — requires admin):**
```powershell
# Option 1: certutil (reliable, works in all PowerShell versions)
certutil -addstore -f "Root" "certs\ca.crt"

# Option 2: PowerShell cmdlet
Import-Certificate -FilePath "certs\ca.crt" -CertStoreLocation Cert:\LocalMachine\Root
```

Both options install to the Machine store (all users). After installing, `curl`, `Invoke-RestMethod`, browsers, and any other tool that uses the Windows certificate store will trust certs issued by this CA — no `--cacert` flag needed.

**macOS:**
```sh
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain certs/ca.crt
```

### Step 5: Verify

After starting the stack and trusting the CA:

```sh
# Should succeed without --cacert or -k
curl https://ferrowarden:3000/v1/admin/status \
  -H "X-Admin-Key: $(cat secrets/ferrowarden_admin_key)"
```

If you get a certificate error, check:
1. The hostname you are connecting to matches a DNS entry in `server.ext`.
2. The CA was installed correctly (`update-ca-certificates` or `certutil` returned success).
3. The CA cert in `/usr/local/share/ca-certificates/` has a `.crt` extension (not `.pem`).

---

## Certificate Rotation

Ferrowarden reads the certificate files at startup and does not reload them live. To rotate:

1. Replace `certs/server.crt` and `certs/server.key` with the new files.
2. Restart the ferrowarden container: `docker compose restart ferrowarden`

If you are rotating because the CA is compromised, you must also re-issue the server cert from the new CA and re-install the new CA on all machines.

---

## Files Summary

| File | Tracked in git | Description |
|---|---|---|
| `certs/ca.key` | No | CA private key — keep secret, never share |
| `certs/ca.crt` | No | CA certificate — distribute to connecting machines |
| `certs/server.key` | No | Server private key — stays on the Ferrowarden host |
| `certs/server.crt` | No | Server certificate — mounted into the container |
| `certs/server.csr` | No | Certificate signing request — not needed after signing |
| `certs/server.ext` | No | SAN extension file — keep for re-issuance |
| `certs/README.md` | Yes | This directory's index |
