# Ferrowarden

A credential proxy for AI agents. Agents send API calls with `{{vault:name}}` placeholders; Ferrowarden substitutes real credentials, forwards the call to the target service, scrubs credentials from the response, and returns the result. **The agent never sees a credential value.**

Built as a sidecar to [Vaultwarden](https://github.com/dani-garcia/vaultwarden), using the Bitwarden CLI (`bw serve`) as the vault API layer.

---

## The Problem

An AI agent that manages infrastructure needs credentials — API tokens, passwords, service keys. The straightforward approaches all have the same problem: the credential value ends up in the conversation context, where it can appear in logs, model outputs, or error messages.

Giving the agent a credential directly is not acceptable for a security-first deployment.

## The Solution

Ferrowarden gives the agent two things:

1. **A list of credential names** (`GET /v1/credentials`) — the agent knows what credentials exist, never their values.
2. **A proxy endpoint** (`POST /v1/forward`) — the agent sends the API call it wants to make, using `{{vault:name}}` as a placeholder wherever a credential belongs. Ferrowarden substitutes the real value, makes the call, and returns the response with any credential patterns scrubbed out.

The agent token itself is scoped only to ferrowarden — it cannot reach Vaultwarden, the vault CLI, or any other service directly.

---

## Architecture

```
  ┌─────────────────────────────────────────────────────────────┐
  │                        Host / Docker                         │
  │                                                             │
  │   ┌───────────┐    bw serve API    ┌──────────────────────┐ │
  │   │ Vaultwarden│◄──────────────────│    bw serve          │ │
  │   │ (storage)  │  (localhost only) │  (vault API layer)   │ │
  │   └───────────┘                   └──────────┬───────────┘ │
  │                                              │              │
  │                                   ┌──────────▼───────────┐  │
  │                                   │    Ferrowarden       │  │
  │                                   │  (credential proxy)  │  │
  │                                   └──────────┬───────────┘  │
  └──────────────────────────────────────────────┼─────────────┘
                                                 │ :3000
                                        ┌────────▼────────┐
                                        │   AI Agent      │
                                        │ (Claude, etc.)  │
                                        └─────────────────┘
```

The agent connects only to Ferrowarden. You manage credentials in Vaultwarden's web vault (published on `:8443`, or behind your reverse proxy) — it is a full Bitwarden-compatible password manager. bw serve, which holds the unlocked vault, is never reachable from outside the internal Docker network.

---

## Quick Start

### Try it in five minutes (test stack)

The setup scripts build a complete throwaway stack — Vaultwarden, bw serve, Ferrowarden and a mock API — with a test account and fake credentials, then write the keys you need to `.env.test`:

```sh
./scripts/dev-setup.sh            # Linux/Mac
.\scripts\dev-setup.ps1           # Windows (PowerShell 7)

# Run the integration tests against it
set -a; . ./.env.test; set +a
cargo test --test integration -- --test-threads=1
```

### Production deployment

The full walkthrough, with Linux and Windows commands for every step, is in **[docs/setup.md](docs/setup.md)**. In outline:

```sh
# 0. A TLS certificate for Ferrowarden (EC P-256 with a SAN for the host agents use)
mkdir -p certs
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 365 \
    -keyout certs/server.key -out certs/server.crt -subj "/CN=ferrowarden" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

# 1. Secrets: your future master password and an admin key
mkdir -p secrets
touch secrets/bw_client_id secrets/bw_client_secret
echo -n "your-vault-master-password" > secrets/bw_master_password
openssl rand -base64 48 | tr -dc 'A-Za-z0-9' | head -c 48 > secrets/ferrowarden_admin_key
# Linux hosts only — the containers run as UID 999 (ferrowarden) and 1000 (bw serve):
sudo chown 999:999   certs/server.key secrets/bw_master_password secrets/ferrowarden_admin_key
sudo chown 1000:1000 secrets/bw_client_id secrets/bw_client_secret
sudo chmod 600 secrets/* && sudo chmod 400 certs/server.key

# 2. Vaultwarden, with signups enabled just for creating your account.
#    The web vault is at https://127.0.0.1:8443 (cp .env.example .env to publish
#    it for a reverse proxy or your LAN and to set its URL).
VAULTWARDEN_SIGNUPS_ALLOWED=true docker compose up -d vaultwarden
#    In the web vault: create your account (same master password), then
#    Settings → Security → Keys → View API key → write client_id and
#    client_secret into secrets/bw_client_id and secrets/bw_client_secret
#    (with sudo on Linux, since step 1 chowned them).
#    Add Login items; each item's Website URI is the only host it may be sent to.

# 3. Start everything (this also turns signups back off; the web vault stays
#    available for managing credentials — enable two-step login on your account)
docker compose up -d

# 4. Create an agent key — the token is shown ONCE
curl -s -X POST https://localhost:3000/v1/admin/keys --cacert certs/server.crt \
  -H "X-Admin-Key: $(cat secrets/ferrowarden_admin_key)" \
  -H "Content-Type: application/json" -d '{"name": "my-agent"}'

# 5. Use the proxy (the item "my_api_token" must list https://api.example.com as a URI)
curl -s -X POST https://localhost:3000/v1/forward --cacert certs/server.crt \
  -H "X-Agent-Key: <token-from-step-4>" -H "Content-Type: application/json" \
  -d '{"request": {"method": "GET", "url": "https://api.example.com/status",
       "headers": {"Authorization": "Bearer {{vault:my_api_token}}"}}}'
```

Behind a TLS reverse proxy such as Pangolin, see [docs/tls.md](docs/tls.md#pangolin).

---

## Documentation

| Document | Contents |
|---|---|
| [Architecture](docs/architecture.md) | System design, data flow, component decisions |
| [Security Model](docs/security.md) | Threat model, security guarantees, design rationale |
| [Setup Guide](docs/setup.md) | Installation, Vaultwarden setup, first run |
| [API Reference](docs/api-reference.md) | All endpoints, request/response shapes, error codes |
| [Operations](docs/operations.md) | Unlock modes, key rotation, monitoring, troubleshooting |
| [Logging](docs/logging.md) | Log levels, Loki, Wazuh, retention |
| [TLS](docs/tls.md) | Pangolin reverse proxy and self-signed CA setup |
| [Agent Skill](docs/agent-skill.md) | Reference doc for agents using the proxy (non-skill format) |
| [Changelog](CHANGELOG.md) | Release notes and upgrade steps |
| [Security Policy](SECURITY.md) | How to report a vulnerability privately |

### Claude Code skill

If you use Claude Code, a ready-made skill is included at `.claude/skills/ferrowarden/`. Copy it to your personal skill directory to load it automatically whenever Claude needs to make a credentialed API call:

```sh
# Linux/Mac
cp -r .claude/skills/ferrowarden ~/.claude/skills/ferrowarden

# Windows (PowerShell)
Copy-Item -Recurse .claude\skills\ferrowarden $env:USERPROFILE\.claude\skills\ferrowarden
```

The skill covers endpoint schemas, placeholder syntax, error handling, and worked examples. It has `user-invocable: false` so Claude loads it automatically when the task involves credentialed API calls — no slash command needed.

---

## Security Summary

- Credential values are stored only in Vaultwarden (encrypted at rest).
- In Ferrowarden's process, values are held as `Zeroizing<String>` — wiped from memory when dropped.
- The agent API key grants access only to the proxy endpoints. It cannot read vault contents directly.
- Each credential is bound to the hosts in its vault item's URIs; it is never sent anywhere else.
- Outbound targets are checked at DNS-resolution time: bw serve is always refused, and private/internal addresses (including cloud metadata) are refused unless listed in `allowed_targets`.
- The admin key is enforced environment-only (minimum 32 characters); it cannot be set in a config file.
- All credential names (not values) used in a request are recorded in the audit log.
- Every credential value used in a request is scrubbed from the response body, headers and error messages (raw, JSON-escaped, URL-encoded and base64 forms), followed by common credential patterns.

See [Security Model](docs/security.md) for the full threat model and design rationale. To report a vulnerability, follow the [Security Policy](SECURITY.md) — please don't open a public issue.

---

## License

MIT — see [LICENSE](LICENSE).
