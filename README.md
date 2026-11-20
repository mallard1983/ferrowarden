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

The agent connects only to Ferrowarden. Vaultwarden and bw serve are never reachable from outside the host/container network.

---

## Quick Start

```sh
# 1. Create secret files
mkdir secrets
echo -n "your-vaultwarden-client-id"       > secrets/bw_client_id
echo -n "your-vaultwarden-client-secret"   > secrets/bw_client_secret
echo -n "your-vault-master-password"       > secrets/bw_master_password
openssl rand -base64 48 | tr -dc 'A-Za-z0-9' | head -c 48 > secrets/ferrowarden_admin_key
chmod 600 secrets/*

# 2. Copy and edit config
cp ferrowarden.toml.example ferrowarden.toml

# 3. Start the stack
docker compose up -d

# 4. Create an agent key
curl -X POST http://localhost:3000/v1/admin/keys \
  -H "X-Admin-Key: $(cat secrets/ferrowarden_admin_key)" \
  -H "Content-Type: application/json" \
  -d '{"name": "my-agent"}'
# → {"id":"...","name":"my-agent","token":"...","created_at":"..."}
# The token is shown ONCE. Store it securely.

# 5. Use the proxy
curl -X POST http://localhost:3000/v1/forward \
  -H "X-Agent-Key: <token-from-step-4>" \
  -H "Content-Type: application/json" \
  -d '{
    "request": {
      "method": "GET",
      "url": "https://api.example.com/status",
      "headers": {
        "Authorization": "Bearer {{vault:my_api_token}}"
      }
    }
  }'
```

---

## Documentation

| Document | Contents |
|---|---|
| [Architecture](docs/architecture.md) | System design, data flow, component decisions |
| [Security Model](docs/security.md) | Threat model, security guarantees, design rationale |
| [Setup Guide](docs/setup.md) | Installation, Vaultwarden setup, first run |
| [API Reference](docs/api-reference.md) | All endpoints, request/response shapes, error codes |
| [Operations](docs/operations.md) | Unlock modes, key rotation, monitoring, troubleshooting |

---

## Security Summary

- Credential values are stored only in Vaultwarden (encrypted at rest).
- In Ferrowarden's process, values are held as `Zeroizing<String>` — wiped from memory when dropped.
- The agent API key grants access only to the proxy endpoints. It cannot read vault contents directly.
- The admin key is enforced environment-only (minimum 32 characters); it cannot be set in a config file.
- All credential names (not values) used in a request are recorded in the audit log.
- Response bodies are scrubbed for common credential patterns before being returned to the agent.

See [Security Model](docs/security.md) for the full threat model and design rationale.

---

## License

MIT
