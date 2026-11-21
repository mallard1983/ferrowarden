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
| `request.body` | any JSON | no | Request body. A JSON **string** is sent as raw text (e.g. form data). An object, array, number or boolean is serialized and sent as JSON, with `Content-Type: application/json` added if you did not set one. `null` sends no body. |

Placeholders (`{{vault:name}}`) may appear in the URL's path, query or user info, in any header value, and anywhere in the body (inside JSON string values and object keys). They may **not** appear in the URL's scheme, host or port.

In a JSON body, values are substituted into the parsed structure, so a credential containing `"` or `\` is escaped correctly.

**Checks before anything is sent** (failures return an error and nothing is forwarded):
- Every placeholder names exactly one vault login item (`422` unknown, `409` ambiguous).
- Each credential is bound to the target: the target's host (and scheme/port, if the item's URI states them) matches one of the URIs on the vault item (`403`). See [Security Model §13](security.md#13-credential-host-binding).
- The target is allowed by the outbound policy: never bw serve; private/internal addresses only if listed in `allowed_targets` (`403`). See [Security Model §14](security.md#14-outbound-target-policy-ssrf-protection).

**Response `200 OK`**
```json
{
  "status": 200,
  "headers": {
    "content-type": "application/json",
    "x-request-id": "abc123"
  },
  "body": "{\"data\":[...]}",
  "body_encoding": "utf8"
}
```

The `body` is always a string. If the target returned JSON, it is a JSON string (not parsed). If the response was not valid UTF-8 (an image, a binary file), `body` is its base64 encoding and `body_encoding` is `"base64"`. Hop-by-hop headers (`transfer-encoding`, `connection`, etc.) and `content-length` are excluded from the response headers.

Every credential value used in the request is redacted (`[REDACTED]`) wherever it appears in the response body or header values, in raw, JSON-escaped, URL-encoded or base64 form. Responses larger than `max_response_bytes` (default 10 MiB) are rejected.

**Errors**
| Status | Condition |
|---|---|
| `400 Bad Request` | Malformed request JSON; unparseable URL; scheme not http/https; invalid HTTP method; placeholder in the URL host/port |
| `401 Unauthorized` | Missing or invalid agent key |
| `403 Forbidden` | Credential not bound to the target host, or target refused by the outbound policy (bw serve, private/internal address not in `allowed_targets`) |
| `409 Conflict` | Placeholder name matches more than one vault item |
| `422 Unprocessable Entity` | Placeholder references an unknown credential name |
| `502 Bad Gateway` | Forward to target failed (connection error, timeout) or response exceeded `max_response_bytes`. The message never includes the target URL. |
| `503 Service Unavailable` | Vault is locked, or bw serve is unreachable |

---

## Admin Endpoints

Admin endpoints require `X-Admin-Key: <key>` where the key matches `FERROWARDEN_ADMIN_KEY`.

### `POST /v1/unlock`

Unlock the vault by supplying the master password. Only valid when `unlock_mode = manual`.

Returns `404 Not Found` when `unlock_mode = file` (file mode unlocks automatically at startup; this endpoint is disabled to prevent confusion).

**Headers**
- `X-Admin-Key: <key>` — required (`Authorization: Bearer <key>` is also accepted, for compatibility with earlier releases)
- `Content-Type: application/json` — required

**Request Body**
```json
{ "password": "your-vault-master-password" }
```

**Response `200 OK`**
```json
{ "status": "unlocked" }
```

On success Ferrowarden also syncs bw serve with Vaultwarden and reloads the credential list. This endpoint shares the admin rate limit (30/min, burst 5).

**Errors**
| Status | Condition |
|---|---|
| `401 Unauthorized` | Invalid admin key, or bw serve rejected the master password |
| `404 Not Found` | Unlock mode is `file` |
| `503 Service Unavailable` | bw serve unreachable |

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

### `DELETE /v1/admin/keys/{id}`

Revoke an agent key. The token is immediately removed from in-memory state and, if key persistence is configured, removed from the key store file on disk.

**Response `200 OK`**
```json
{ "status": "revoked", "id": "550e8400-e29b-41d4-a716-446655440000" }
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
- The request URL's path, query string or user info — **not** its scheme, host or port
- Any header value
- The request body (inside JSON string values or object keys, or a raw string body)

A single request may use multiple different placeholders. Duplicate placeholders in the same request (e.g., the same credential in two headers) are resolved with one vault call.
