# Setup Guide

This guide walks through a complete Ferrowarden deployment using Docker Compose. By the end you will have:

- Vaultwarden running and configured
- The Bitwarden CLI logged in and running `bw serve`
- Ferrowarden proxying credential requests
- One agent key ready to use

---

## Prerequisites

- Docker and Docker Compose v2
- `openssl` (for generating the admin key and TLS certificate)
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

For a quick self-signed cert to get started (the setup scripts do this automatically):

**Linux/Mac:**
```sh
mkdir -p certs
openssl req -x509 -newkey ed25519 \
    -keyout certs/server.key -out certs/server.crt \
    -days 365 -nodes -subj "/CN=ferrowarden"
chmod 400 certs/server.key
```

**Windows (PowerShell):**
```powershell
New-Item -ItemType Directory -Force certs | Out-Null
openssl req -x509 -newkey ed25519 `
    -keyout certs\server.key -out certs\server.crt `
    -days 365 -nodes -subj '/CN=ferrowarden' 2>$null
```

`openssl` ships with Git for Windows. The `certs/` directory is gitignored — never commit cert files.

If the agent and Ferrowarden run on the same host (no network hop), you can skip TLS entirely with `FERROWARDEN_TLS_ENABLED=false`. Ferrowarden logs a prominent warning when this is set. See [Security: TLS](security.md#10-native-tls-transport-security) for when it is acceptable.

---

## Step 1: Create Secret Files

Secret values are mounted as Docker secrets — files on disk that the containers read at startup. Create the `secrets/` directory and populate it. **Do not commit this directory.**

**Linux/Mac:**
```sh
mkdir secrets

# Leave these empty for now — fill them in after Step 2 (Vaultwarden setup).
touch secrets/bw_client_id
touch secrets/bw_client_secret

# Your Vaultwarden master password
echo -n "YourMasterPasswordHere" > secrets/bw_master_password

# Generate a strong admin key (48 random alphanumeric characters)
openssl rand -base64 48 | tr -dc 'A-Za-z0-9' | head -c 48 > secrets/ferrowarden_admin_key

chmod 600 secrets/*
```

**Windows (PowerShell):**
```powershell
New-Item -ItemType Directory -Force secrets | Out-Null

# Leave these empty for now — fill them in after Step 2.
[IO.File]::WriteAllText("secrets\bw_client_id",    "", [Text.UTF8Encoding]::new($false))
[IO.File]::WriteAllText("secrets\bw_client_secret","", [Text.UTF8Encoding]::new($false))

# Your Vaultwarden master password
[IO.File]::WriteAllText("secrets\bw_master_password", "YourMasterPasswordHere", [Text.UTF8Encoding]::new($false))

# Generate a strong admin key (48 random alphanumeric characters)
$chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'.ToCharArray()
$rng   = [Security.Cryptography.RandomNumberGenerator]::Create()
$buf   = [byte[]]::new(1)
$key   = -join (1..48 | ForEach-Object { $rng.GetBytes($buf); $chars[$buf[0] % $chars.Length] })
[IO.File]::WriteAllText("secrets\ferrowarden_admin_key", $key, [Text.UTF8Encoding]::new($false))
```

Secret files must have no trailing newline — `[IO.File]::WriteAllText` with `UTF8Encoding($false)` handles this correctly on Windows (PowerShell's `Set-Content` and `Out-File` add a BOM or trailing newline by default).

---

## Step 2: First-Time Vaultwarden Setup

Start Vaultwarden alone to register your account:

```sh
docker compose up -d vaultwarden
```

Access the web UI. If you are on the same host:

```sh
# Temporarily expose the port for initial setup
docker compose exec vaultwarden sh -c "echo 'Vaultwarden is running'"
# Or add a temporary port mapping to docker-compose.yml under vaultwarden:
#   ports:
#     - "127.0.0.1:8080:80"
```

In the web UI:
1. Create an account using the email and master password you wrote to `secrets/bw_master_password`.
2. Navigate to **Account Settings → Security → API Key**.
3. Click **View API Key** and authenticate.
4. Copy the **client_id** and **client_secret** values.

```sh
echo -n "user.xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" > secrets/bw_client_id
echo -n "YourClientSecretHere" > secrets/bw_client_secret
```

Add at least one credential to your vault via the web UI. You can add more later — the name you give it here is what you will use in `{{vault:name}}` placeholders.

---

## Step 3: Start the Full Stack

```sh
docker compose up -d
```

Check that all three services started cleanly:

```sh
docker compose ps
docker compose logs ferrowarden
```

Ferrowarden's log should show:

```
{"level":"INFO","message":"Ferrowarden starting"}
{"level":"INFO","message":"File unlock mode: reading password from ..."}
{"level":"INFO","message":"Vault unlocked via file mode"}
{"level":"INFO","message":"Listening on https://0.0.0.0:3000 (TLS)"}
```

If you see `VaultLocked` or connection errors, see [Troubleshooting](operations.md#troubleshooting).

---

## Step 4: Create an Agent Key

The admin key (from `secrets/ferrowarden_admin_key`) is for operator use only. Create a separate key for each agent.

```sh
ADMIN_KEY="$(cat secrets/ferrowarden_admin_key)"

curl -s -X POST https://<ferrowarden-host>:3000/v1/admin/keys \
  -H "X-Admin-Key: $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name": "homelab-agent"}' \
  --cacert certs/server.crt    # omit if using a trusted CA cert
```

Response:
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "homelab-agent",
  "token": "AbCdEf1234567890AbCdEf1234567890AbCdEf1234567890",
  "created_at": "2026-11-20T12:00:00Z"
}
```

**The token is shown exactly once.** Copy it and store it in your agent's configuration as an environment variable. It cannot be retrieved again — if it is lost, revoke it and create a new one.

---

## Step 5: Verify the Setup

List available credentials (what the agent sees):

```sh
AGENT_TOKEN="the-token-from-step-4"

curl -s https://localhost:3000/v1/credentials \
  -H "X-Agent-Key: $AGENT_TOKEN" \
  --cacert certs/server.crt    # omit if using a trusted CA cert
```

Response:
```json
["my_proxmox_token", "nas_api_key", "plex_token"]
```

Make a test proxy request:

```sh
curl -s -X POST https://localhost:3000/v1/forward \
  -H "X-Agent-Key: $AGENT_TOKEN" \
  --cacert certs/server.crt \
  -H "Content-Type: application/json" \
  -d '{
    "request": {
      "method": "GET",
      "url": "https://httpbin.org/get",
      "headers": {
        "X-Test-Header": "{{vault:my_proxmox_token}}"
      }
    }
  }'
```

The response will include httpbin's echo of your request. The `X-Test-Header` will contain the real credential value as sent to httpbin — but notice it is scrubbed from any credential-shaped patterns in the response before being returned to you.

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
| *(env only)* | `FERROWARDEN_ADMIN_KEY` | *(required)* |
| `keys_file` | `FERROWARDEN_KEYS_FILE` | *(optional — enables key persistence)* |
| `tls_enabled` | `FERROWARDEN_TLS_ENABLED` | `true` |
| `tls_cert_file` | `FERROWARDEN_TLS_CERT_FILE` | *(required when tls_enabled)* |
| `tls_key_file` | `FERROWARDEN_TLS_KEY_FILE` | *(required when tls_enabled)* |

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

## Running Without Docker

If you are running Ferrowarden directly on a host (development or bare-metal):

```sh
# Install the Bitwarden CLI
# https://bitwarden.com/help/cli/

# Configure bw to point at your Vaultwarden instance
bw config server http://your-vaultwarden-host

# Log in
bw login --apikey  # requires BW_CLIENTID and BW_CLIENTSECRET env vars

# Start bw serve (keep this running in a separate terminal or service)
bw serve --hostname 127.0.0.1 --port 8087

# In another terminal, start Ferrowarden
export FERROWARDEN_ADMIN_KEY="your-32-char-minimum-admin-key-here"
export FERROWARDEN_UNLOCK_MODE=manual
./ferrowarden
# Then POST /v1/unlock to unlock the vault
```
