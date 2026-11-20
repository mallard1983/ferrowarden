# API Reference

All requests require an authentication header. The header name depends on the endpoint:

- **Agent endpoints** (`/v1/credentials`, `/v1/forward`): `X-Agent-Key: <token>`
- **Admin endpoints** (`/v1/admin/*`, `/v1/unlock`): `X-Admin-Key: <key>`

Responses are JSON. Errors follow a consistent shape:

```json
{ "error": "human-readable description" }
```

---

## Agent Endpoints

### `GET /v1/credentials`

List the names of credentials available in the vault. This is the only way for an agent to discover what credentials exist — values are never included.

**Headers**
- `X-Agent-Key: <token>` — required

**Response `200 OK`**
```json
["proxmox_api_token", "nas_key", "plex_token", "grafana_service_account"]
```

**Errors**
| Status | Condition |
|---|---|
| `401 Unauthorized` | Missing or invalid agent key |
| `503 Service Unavailable` | Vault is locked |

---

### `POST /v1/forward`

Proxy an API call to a target service with credential substitution.

The agent sends the request it wants to make, with `{{vault:name}}` placeholders wherever credentials belong. Ferrowarden substitutes values, forwards the request, and returns the scrubbed response.

**Headers**
- `X-Agent-Key: <token>` — required
- `Content-Type: application/json` — required

**Request Body**
```json
{
  "request": {
    "method": "GET",
    "url": "https://proxmox.lan:8006/api2/json/nodes",
    "headers": {
      "Authorization": "PVEAPIToken=user@pve!token={{vault:proxmox_api_token}}"
    },
    "body": null
  }
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `request.method` | string | yes | HTTP method (`GET`, `POST`, `PUT`, `DELETE`, `PATCH`) |
| `request.url` | string | yes | Target URL. Must be `http://` or `https://`. |
| `request.headers` | object | no | Headers to send. `x-fw-*` headers are stripped. |
| `request.body` | any JSON | no | Request body. Can be an object, array, string, or null. |

Placeholders (`{{vault:name}}`) may appear in the URL, any header value, or anywhere in the body (including nested inside JSON strings).

**Response `200 OK`**
```json
{
  "status": 200,
  "headers": {
    "content-type": "application/json",
    "x-request-id": "abc123"
  },
  "body": "{\"data\":[...]}"
}
```

The `body` is always a string. If the target returned JSON, it is a JSON string (not parsed). Hop-by-hop headers (`transfer-encoding`, `connection`, etc.) are excluded from the response headers.

**Errors**
| Status | Condition |
|---|---|
| `400 Bad Request` | Malformed request JSON |
| `401 Unauthorized` | Missing or invalid agent key |
| `422 Unprocessable Entity` | Placeholder references an unknown credential name |
| `503 Service Unavailable` | Vault is locked |
| `502 Bad Gateway` | Forward to target failed (network error, timeout) |
| `400 Bad Request` | Invalid target URL scheme (not http/https) or invalid HTTP method |

---

## Admin Endpoints

Admin endpoints require `X-Admin-Key: <key>` where the key matches `FERROWARDEN_ADMIN_KEY`.

### `POST /v1/unlock`

Unlock the vault by supplying the master password. Only valid when `unlock_mode = manual`.

Returns `404 Not Found` when `unlock_mode = file` (file mode unlocks automatically at startup; this endpoint is disabled to prevent confusion).

**Headers**
- `X-Admin-Key: <key>` — required
- `Content-Type: application/json` — required

**Request Body**
```json
{ "password": "your-vault-master-password" }
```

**Response `200 OK`**
```json
{ "message": "Vault unlocked successfully" }
```

**Errors**
| Status | Condition |
|---|---|
| `401 Unauthorized` | Invalid admin key |
| `404 Not Found` | Unlock mode is `file` |
| `503 Service Unavailable` | bw serve unreachable or unlock failed |

---

### `POST /v1/admin/keys`

Create a new agent API key.

**Request Body**
```json
{ "name": "homelab-agent" }
```

**Response `201 Created`**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "homelab-agent",
  "token": "AbCdEf1234567890AbCdEf1234567890AbCdEf1234567890",
  "created_at": "2026-11-20T12:00:00Z"
}
```

The `token` is shown exactly once. It cannot be retrieved after this response.

---

### `GET /v1/admin/keys`

List all active agent keys. Token values are never included.

**Response `200 OK`**
```json
[
  {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "name": "homelab-agent",
    "created_at": "2026-11-20T12:00:00Z"
  }
]
```

---

### `DELETE /v1/admin/keys/:id`

Revoke an agent key. The token is immediately removed from memory (zeroed).

**Response `200 OK`**
```json
{ "message": "Key revoked" }
```

**Errors**
| Status | Condition |
|---|---|
| `404 Not Found` | No key with that ID exists |

---

### `GET /v1/admin/audit`

Return the 100 most recent audit log entries, newest first.

**Response `200 OK`**
```json
[
  {
    "timestamp": "2026-11-20T14:32:11Z",
    "agent_id": "550e8400-e29b-41d4-a716-446655440000",
    "agent_name": "homelab-agent",
    "method": "GET",
    "target_url": "https://proxmox.lan:8006/api2/json/nodes",
    "credential_names": ["proxmox_api_token"],
    "outcome": "success",
    "response_status": 200
  }
]
```

**Outcome values**
| Value | Meaning |
|---|---|
| `success` | Request forwarded and response returned |
| `vault_locked` | Vault was locked when the request arrived |
| `unknown_credential` | Placeholder referenced a name not in the vault |
| `forward_failed` | Network error reaching the target service |
| `unauthorized` | Invalid or missing agent key |
| `internal_error` | Unexpected internal error |

---

### `GET /v1/admin/status`

Current operational status.

**Response `200 OK`**
```json
{
  "locked": false,
  "credential_count": 12,
  "agent_key_count": 2
}
```

---

## Placeholder Syntax

Placeholders use the format `{{vault:name}}` where `name` matches the pattern `[a-zA-Z0-9_\-\.]+`.

Names are case-sensitive and must exactly match the credential name in Vaultwarden.

**Examples**
```
{{vault:proxmox_api_token}}
{{vault:nas-key}}
{{vault:service.account.password}}
```

**Placement**
Placeholders may appear anywhere in:
- The request URL (e.g., in a query parameter)
- Any header value
- The request body (as part of a JSON string value or a plain string)

A single request may use multiple different placeholders. Duplicate placeholders in the same request (e.g., the same credential in two headers) are resolved with one vault call.
