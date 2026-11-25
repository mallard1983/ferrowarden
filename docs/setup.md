<img src="../branding/assets/png/banners/ferrowarden-docs-header.png" width="100%" alt="">

# Setup Guide

This guide walks through a complete Ferrowarden deployment using Docker Compose. Ferrowarden runs as a sidecar to [Vaultwarden](https://github.com/dani-garcia/vaultwarden) (it is not a fork or replacement, and is not affiliated with Vaultwarden or Bitwarden) and reaches your vault through the Bitwarden CLI's `bw serve`. By the end you will have:

- Vaultwarden running and configured
- The Bitwarden CLI logged in and running `bw serve`
- Ferrowarden proxying credential requests
- One agent key ready to use

---

## Get the Code

```sh
git clone https://github.com/mallard1983/ferrowarden.git
cd ferrowarden
```

Run every command in this guide from the repository root.

---

## Prerequisites

- Docker and Docker Compose v2
- `openssl` (for generating the admin key and TLS certificate; ships with Git for Windows)
- A host where the agent will also run, or network access from the agent host to port 3000

### Windows development

If building Ferrowarden from source on Windows, the MSVC Rust toolchain is required. The `ring` crate (pulled in by TLS support) requires a C compiler that the GNU toolchain does not provide without MinGW. With the MSVC toolchain and Visual Studio Build Tools installed, the build works out of the box.

```powershell
rustup default stable-x86_64-pc-windows-msvc
cargo build
```

For the automated test environment setup, use the PowerShell script instead of the shell script:

```powershell
.\scripts\dev-setup.ps1
```

Both scripts perform identical steps. Use `dev-setup.sh` on Linux/Mac and `dev-setup.ps1` on Windows.

---

## Step 0: Set Up TLS

Ferrowarden requires TLS by default. The full TLS reference — including Pangolin/reverse-proxy setup, local CA generation, and installing the CA on Linux and Windows — is in **[docs/tls.md](tls.md)**.

For a quick self-signed certificate to get started (the setup scripts do this automatically). Use EC P-256 with a `subjectAltName`: Windows' TLS stack (Schannel, used by `curl.exe` and PowerShell) cannot validate Ed25519 certificates, and most clients ignore a certificate's CN without a SAN. Add the host name agents will use (e.g. `DNS:ferro.example.lan`) to the SAN list.

**Linux/Mac:**
```sh
mkdir -p certs
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
    -keyout certs/server.key -out certs/server.crt \
    -days 365 -nodes -subj "/CN=ferrowarden" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
# Ferrowarden runs as UID 999 inside its container, and Docker mounts the key
# with its host owner and mode, so give UID 999 ownership.
sudo chown 999:999 certs/server.key
chmod 400 certs/server.key
```

**Windows (PowerShell):**
```powershell
New-Item -ItemType Directory -Force certs | Out-Null
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 `
    -keyout certs\server.key -out certs\server.crt `
    -days 365 -nodes -subj '/CN=ferrowarden' `
    -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' 2>$null
```

`openssl` ships with Git for Windows. The `certs/` directory is gitignored — never commit cert files. (Docker Desktop on Windows/macOS does not enforce host file ownership, so no `chown` is needed there.)

If the agent and Ferrowarden run on the same host (no network hop), you can skip TLS entirely with `FERROWARDEN_TLS_ENABLED=false`. Ferrowarden logs a prominent warning when this is set. See [Security: TLS](security.md#10-native-tls-transport-security) for when it is acceptable. Behind a TLS reverse proxy such as Pangolin, see [docs/tls.md](tls.md#pangolin).

---

## Step 1: Create Secret Files

Secret values are mounted as Docker secrets — files on disk that the containers read at startup. Create the `secrets/` directory and populate it. **Do not commit this directory.** Each file holds only the value — no trailing newline.

**Linux/Mac:**
```sh
mkdir -p secrets

# Filled in after Step 2 (Vaultwarden setup).
touch secrets/bw_client_id secrets/bw_client_secret

# The master password you will use for your Vaultwarden account in Step 2
echo -n "YourMasterPasswordHere" > secrets/bw_master_password

# A strong admin key (48 random alphanumeric characters)
openssl rand -base64 48 | tr -dc 'A-Za-z0-9' | head -c 48 > secrets/ferrowarden_admin_key

# Docker mounts these with their host owner and mode. Ferrowarden runs as
# UID 999 and bw serve as UID 1000 inside their containers:
sudo chown 999:999   secrets/bw_master_password secrets/ferrowarden_admin_key
sudo chown 1000:1000 secrets/bw_client_id secrets/bw_client_secret
sudo chmod 600 secrets/*
```

You will need `sudo` to write `bw_client_id` and `bw_client_secret` in Step 2 after this, or create them in Step 2 and `chown` them then.

**Windows (PowerShell):**
```powershell
New-Item -ItemType Directory -Force secrets | Out-Null
# [IO.File] resolves relative paths against the process directory, which a
# `cd` in PowerShell does not change. Sync it first:
[Environment]::CurrentDirectory = (Get-Location).Path

# Filled in after Step 2.
[IO.File]::WriteAllText("secrets\bw_client_id",    "", [Text.UTF8Encoding]::new($false))
[IO.File]::WriteAllText("secrets\bw_client_secret","", [Text.UTF8Encoding]::new($false))

# The master password you will use for your Vaultwarden account in Step 2
[IO.File]::WriteAllText("secrets\bw_master_password", "YourMasterPasswordHere", [Text.UTF8Encoding]::new($false))

# A strong admin key (48 random alphanumeric characters)
$chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'.ToCharArray()
$key   = -join (1..48 | ForEach-Object { $chars[[Security.Cryptography.RandomNumberGenerator]::GetInt32($chars.Length)] })
[IO.File]::WriteAllText("secrets\ferrowarden_admin_key", $key, [Text.UTF8Encoding]::new($false))
```

Secret files must have no trailing newline — `[IO.File]::WriteAllText` with `UTF8Encoding($false)` handles this correctly on Windows (PowerShell's `Set-Content` and `Out-File` add a BOM or trailing newline by default).

---

## Step 2: First-Time Vaultwarden Setup

Vaultwarden is your password manager: its web vault is where you create and manage the credentials agents use (and any other passwords — Bitwarden apps and browser extensions work with it too). The web vault is published on **https://127.0.0.1:8443** by default. To publish it elsewhere — on all interfaces for a reverse proxy such as Pangolin, or on your LAN — copy [`.env.example`](../.env.example) to `.env` and set `VAULTWARDEN_PUBLISH`, `VAULTWARDEN_DOMAIN` and, for direct LAN access, `VAULTWARDEN_CERT_SANS`. See [docs/tls.md](tls.md#the-vaultwarden-web-vault).

New signups are disabled except while you create your first account. Start Vaultwarden with signups enabled:

```sh
VAULTWARDEN_SIGNUPS_ALLOWED=true docker compose up -d vaultwarden
```
```powershell
$env:VAULTWARDEN_SIGNUPS_ALLOWED = 'true'; docker compose up -d vaultwarden; Remove-Item env:VAULTWARDEN_SIGNUPS_ALLOWED
```

This first runs the one-shot `internal-certs` service, which creates a private CA and Vaultwarden's certificate in the `internal-pki` volume. Vaultwarden serves **HTTPS**, because the Bitwarden CLI that `bw serve` runs refuses plain-HTTP servers.

Browse to **https://127.0.0.1:8443** (or your `VAULTWARDEN_DOMAIN`). Browsing directly, the browser warns about the certificate because it is issued by the internal CA; accept it, or install `ca.crt` from the `internal-pki` volume as a trusted CA (`docker compose cp internal-certs:/pki/ca.crt .` after a run). Behind a reverse proxy with its own certificate there is no warning.

In the web vault:
1. **Create account** with your email and the master password you wrote to `secrets/bw_master_password`.
2. Go to **Settings → Security → Keys** and click **View API key**. Enter your master password.
3. Write the **client_id** and **client_secret** to the secrets files:

   ```sh
   echo -n "user.xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" > secrets/bw_client_id
   echo -n "YourClientSecretHere" > secrets/bw_client_secret
   ```
   ```powershell
   [IO.File]::WriteAllText("secrets\bw_client_id",     "user.xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx", [Text.UTF8Encoding]::new($false))
   [IO.File]::WriteAllText("secrets\bw_client_secret", "YourClientSecretHere", [Text.UTF8Encoding]::new($false))
   ```

4. Add at least one credential as a **Login** item (**Add → Login**). You can add more later.

   - The item **name** is what agents use in `{{vault:name}}` placeholders. Names must be unique across login items — a duplicated name is refused as ambiguous.
   - The item **password** is the default value substituted by `{{vault:name}}`. The username, TOTP code, notes and **custom fields** are available too (`{{vault:name:username}}`, `{{vault:name:field:api_key}}`, …) — store API keys as custom fields rather than separate items if you like. Secure notes work as well. Item and field names can contain any characters; agents get correctly quoted placeholders from the API.
   - Items with **master password re-prompt** enabled are not available to agents (until approvals are supported) — use it to mark credentials agents must never use.
- The item **Website (URI)** decides where the credential may be sent. Add one URI per service it belongs to, e.g. `https://api.example.com` or `https://proxmox.lan:8006`. Ferrowarden refuses to send a credential to any other host, and an item with no URIs cannot be used. See [Security Model §13](security.md#13-credential-host-binding) for the matching rules.

   If the service lives on your private network (e.g. `192.168.1.0/24` or `proxmox.lan`), also add it to `allowed_targets` (`FERROWARDEN_ALLOWED_TARGETS`) — private and internal addresses are blocked by default.

New items and URI changes are picked up automatically within `refresh_interval_secs` (default 5 minutes) — this is the day-to-day workflow: add or change a credential in the web vault, and agents can use it shortly after, without ever seeing it.

---

## Step 3: Start the Full Stack

```sh
docker compose up -d
```

Because `VAULTWARDEN_SIGNUPS_ALLOWED` is not set this time, this also restarts Vaultwarden with signups disabled. The web vault stays available for managing your credentials. Turn on two-step login for your account (**Settings → Security → Two-step login**) now that it is reachable.

Check that all services started cleanly:

```sh
docker compose ps
docker compose logs ferrowarden
```

Ferrowarden's log should show:

```
{"level":"INFO","message":"Ferrowarden starting"}
{"level":"INFO","message":"File unlock mode: reading password from ..."}
{"level":"INFO","message":"Vault unlocked via file mode"}
{"level":"INFO","message":"Credential host binding enforced: ..."}
{"level":"INFO","message":"Listening on https://0.0.0.0:3000 (TLS)"}
```

If you see `VaultLocked` or connection errors, see [Troubleshooting](operations.md#troubleshooting).

---

## Step 4: Create an Agent Key

The admin key (from `secrets/ferrowarden_admin_key`) is for operator use only. Create a separate key for each agent.

```sh
ADMIN_KEY="$(cat secrets/ferrowarden_admin_key)"

curl -s -X POST https://localhost:3000/v1/admin/keys \
  -H "X-Admin-Key: $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name": "homelab-agent", "credentials": ["*"], "methods": ["*"]}' \
  --cacert certs/server.crt    # omit if the certificate is from a trusted CA
```

Response:
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "homelab-agent",
  "token": "AbCdEf1234567890AbCdEf1234567890AbCdEf1234567890",
  "created_at": "2026-11-20T12:00:00Z",
  "credentials": ["*"],
  "methods": ["*"],
  "policy_set": true
}
```

`credentials` and `methods` are **required**: a key has no access until you say what it may use. `["*"]` allows everything (fine for a first test); `[]` allows nothing. For real agents, scope each key to the credentials it needs, for example `"credentials": ["uptime_kuma_*"], "methods": ["GET"]`. See [Staged rollout with scoped keys](operations.md#staged-rollout-with-scoped-keys).

**The token is shown exactly once. Copy it and store it in your agent's configuration as an environment variable. It cannot be retrieved again — if it is lost, revoke it and create a new one.

---

## Step 5: Verify the Setup

This walkthrough assumes the Login item from Step 2 is named `httpbin_token`, with any password and the URI `https://httpbin.org` — httpbin is a public service that echoes requests back, which makes the protections visible.

List available credentials (what the agent sees):

```sh
AGENT_TOKEN="the-token-from-step-4"

curl -s https://localhost:3000/v1/credentials \
  -H "X-Agent-Key: $AGENT_TOKEN" \
  --cacert certs/server.crt
```

Response:
```json
["httpbin_token"]
```

Make a proxied request. `/bearer` returns the token it received:

```sh
curl -s -X POST https://localhost:3000/v1/forward \
  -H "X-Agent-Key: $AGENT_TOKEN" \
  -H "Content-Type: application/json" \
  --cacert certs/server.crt \
  -d '{
    "request": {
      "method": "GET",
      "url": "https://httpbin.org/bearer",
      "headers": { "Authorization": "Bearer {{vault:httpbin_token}}" }
    }
  }'
```

```json
{"status":200,"headers":{...},"body":"{\n  \"authenticated\": true, \n  \"token\": \"[REDACTED]\"\n}\n","body_encoding":"utf8"}
```

httpbin received the real value (`"authenticated": true`), but every copy of it in the response is replaced with `[REDACTED]` before it reaches the agent.

Now try sending the same credential to a host that is not in its URIs:

```sh
curl -s -X POST https://localhost:3000/v1/forward \
  -H "X-Agent-Key: $AGENT_TOKEN" \
  -H "Content-Type: application/json" \
  --cacert certs/server.crt \
  -d '{"request":{"method":"GET","url":"https://postman-echo.com/get","headers":{"X-Key":"{{vault:httpbin_token}}"}}}'
```

```json
{"error":"Credential httpbin_token may not be sent to postman-echo.com: the target does not match any URI on the vault item"}
```

The request is refused with `403` and nothing is sent.

---

## Configuration Reference

See [`ferrowarden.toml.example`](../ferrowarden.toml.example) for all available settings with inline documentation.

Environment variables mirror config file keys with the `FERROWARDEN_` prefix:

| Config key | Environment variable | Default |
|---|---|---|
| `bind_addr` | `FERROWARDEN_BIND_ADDR` | `0.0.0.0:3000` |
| `bw_serve_url` | `FERROWARDEN_BW_SERVE_URL` | `http://127.0.0.1:8087` |
| `unlock_mode` | `FERROWARDEN_UNLOCK_MODE` | *(required)* |
| `unlock_file` | `FERROWARDEN_UNLOCK_FILE` | *(required in file mode)* |
| *(env or file only)* | `FERROWARDEN_ADMIN_KEY` or `FERROWARDEN_ADMIN_KEY_FILE` | *(one required)*: the file variant names a file holding the key (the Compose files use `/run/secrets/ferrowarden_admin_key`). Ferrowarden reads the file itself and never puts the key in its environment; a plain `FERROWARDEN_ADMIN_KEY` wins if both are set |
| `keys_file` | `FERROWARDEN_KEYS_FILE` | *(optional — enables key persistence)* |
| `tls_enabled` | `FERROWARDEN_TLS_ENABLED` | `true` |
| `tls_cert_file` | `FERROWARDEN_TLS_CERT_FILE` | *(required when tls_enabled)* |
| `tls_key_file` | `FERROWARDEN_TLS_KEY_FILE` | *(required when tls_enabled)* |
| `allowed_targets` | `FERROWARDEN_ALLOWED_TARGETS` | *(empty)* — comma-separated CIDRs, IPs or host names of internal targets agents may reach |
| `allow_private_targets` | `FERROWARDEN_ALLOW_PRIVATE_TARGETS` | `false` — allow all private/internal targets (bw serve stays blocked) |
| `enforce_credential_hosts` | `FERROWARDEN_ENFORCE_CREDENTIAL_HOSTS` | `true` — only send credentials to hosts in their vault item URIs |
| `refresh_interval_secs` | `FERROWARDEN_REFRESH_INTERVAL_SECS` | `300` — sync/refresh interval; `0` disables |
| `max_response_bytes` | `FERROWARDEN_MAX_RESPONSE_BYTES` | `10485760` (10 MiB) |
| `forward_timeout_secs` | `FERROWARDEN_FORWARD_TIMEOUT_SECS` | `30` |
| `api_prefix` | `FERROWARDEN_API_PREFIX` | *(empty)* — path prefix for all API routes except `/health`, e.g. `/k7f3q9` |
| `agent_rate_limit_per_minute` | `FERROWARDEN_AGENT_RATE_LIMIT_PER_MINUTE` | `120` — sustained agent requests per minute per client IP |
| `agent_rate_limit_burst` | `FERROWARDEN_AGENT_RATE_LIMIT_BURST` | `20` — back-to-back agent requests allowed before the rate applies |
| `admin_rate_limit_per_minute` | `FERROWARDEN_ADMIN_RATE_LIMIT_PER_MINUTE` | `30` — sustained admin requests per minute per client IP |
| `admin_rate_limit_burst` | `FERROWARDEN_ADMIN_RATE_LIMIT_BURST` | `5` — keep low; slows admin key guessing |
| `trusted_proxies` | `FERROWARDEN_TRUSTED_PROXIES` | *(empty)* — CIDRs/IPs of reverse proxies whose `X-Forwarded-For` is trusted for rate limiting |
| `ui.bind` | `FERROWARDEN_UI__BIND` | *(empty: admin web UI disabled)* — e.g. `0.0.0.0:3001`; see [admin-ui.md](admin-ui.md) |
| `ui.vaultwarden_url` | `FERROWARDEN_UI__VAULTWARDEN_URL` | `https://vaultwarden` |
| `ui.vaultwarden_ca_file` | `FERROWARDEN_UI__VAULTWARDEN_CA_FILE` | *(empty; the Compose files set `/ca-public/ca.crt`)* |
| `ui.insecure_http` | `FERROWARDEN_UI__INSECURE_HTTP` | `false` — serve the sign-in form over plain HTTP (local testing only) |
| `ui.session_idle_minutes` | `FERROWARDEN_UI__SESSION_IDLE_MINUTES` | `15` |
| `ui.session_max_hours` | `FERROWARDEN_UI__SESSION_MAX_HOURS` | `8` |
| *(env only)* | `FERROWARDEN_LOG_LEVEL` | `info` — requires restart to change |

---

## Port Configuration

Ferrowarden defaults to port **3000**. In a homelab this commonly collides with other services:

| Service | Default port |
|---|---|
| Grafana | 3000 |
| Gitea / Gogs | 3000 |
| Node.js dev servers | 3000 |
| Home Assistant | 8123 |
| Portainer | 9443 / 9000 |

To change the port, set `FERROWARDEN_BIND_ADDR` in `docker-compose.yml`:

```yaml
# docker-compose.yml — ferrowarden service
environment:
  FERROWARDEN_BIND_ADDR: "0.0.0.0:3443"   # or any free port
ports:
  - "0.0.0.0:3443:3443"
```

Both values must match — the `ports` mapping and the `FERROWARDEN_BIND_ADDR` inside the container.

The agent then connects to `https://<ferrowarden-host>:3443` instead of the default `:3000`.

If you are running Ferrowarden directly on the host (not Docker), set `bind_addr` in `ferrowarden.toml`:

```toml
bind_addr = "0.0.0.0:3443"
```

---

## The Ferrowarden container

The `ferrowarden` image is a statically linked binary on `scratch`: no shell, no `curl`, no package manager. The Compose file runs it with a read-only root filesystem, no capabilities and `no-new-privileges`. Consequences you may notice:

- `docker compose exec ferrowarden sh` does not work. Use logs, `docker compose cp` and a temporary debug container; see [Operations: Debugging a container with no shell](operations.md#debugging-a-container-with-no-shell).
- The health check is `ferrowarden healthcheck`, not `curl`. If you wrote your own health check or monitoring around `curl` inside the container, switch to `["CMD", "/app/ferrowarden", "healthcheck"]`.
- Everything Ferrowarden writes must be on a volume. The agent key file (`/data/agent_keys.json`) is on the `ferrowarden-keys` volume; if you enable the event file sink, put it under `/data` too (for example `/data/events/events.jsonl`).
- Files you bind-mount (secrets, the TLS key) are still read as UID 999: see Steps 0 and 1.

What the hardening covers, and what it does not: [Deployment Profiles](deployment-profiles.md).

---

## Running Without Docker

If you are running Ferrowarden directly on a host (development or bare-metal):

```sh
# Install the Bitwarden CLI
# https://bitwarden.com/help/cli/

# Configure bw to point at your Vaultwarden instance. It must be https://:
# current CLI releases refuse plain HTTP. For a private CA, also
# export NODE_EXTRA_CA_CERTS=/path/to/ca.crt
bw config server https://your-vaultwarden-host

# Log in
bw login --apikey  # requires BW_CLIENTID and BW_CLIENTSECRET env vars

# Start bw serve (keep this running in a separate terminal or service).
# bw serve only accepts requests addressed to localhost/127.0.0.1 or this
# --hostname, so keep bw_serve_url = "http://127.0.0.1:8087".
bw serve --hostname 127.0.0.1 --port 8087

# In another terminal, start Ferrowarden
export FERROWARDEN_ADMIN_KEY="your-32-char-minimum-admin-key-here"
export FERROWARDEN_UNLOCK_MODE=manual
./ferrowarden
# Then POST /v1/unlock to unlock the vault
```
