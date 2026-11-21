# API Reference

All requests require an authentication header. The header name depends on the endpoint:

- **Agent endpoints** (`/v1/credentials`, `/v1/forward`): `X-Agent-Key: <token>`
- **Admin endpoints** (`/v1/admin/*`, `/v1/unlock`): `X-Admin-Key: <key>`

`GET /health` needs no authentication.

**API prefix.** If the operator sets `api_prefix` (`FERROWARDEN_API_PREFIX`, e.g. `/k7f3q9`), every path in this document except `/health` moves under it: `/k7f3q9/v1/forward`, `/k7f3q9/v1/admin/keys`, and so on, and the unprefixed `/v1/...` paths return `404`. Give agents the base URL *including* the prefix.

Responses are JSON. Errors follow a consistent shape:

```json
{ "error": "human-readable description" }
```

**Strict JSON input.** Request bodies are parsed strictly. A body is rejected with `400` if it has a duplicate object key at any depth (keys are compared after unescaping, so `"a"` and `"a"` clash), an unknown field, trailing data, invalid UTF-8, nesting deeper than 64 levels, or a content type other than `application/json`. In `headers`, names that differ only by case (`Authorization` and `authorization`) count as duplicates. Error messages name the offending key or field and the line and column, never a value from the body. Query parameters are strict too: see `GET /v1/credentials`.

---

## Agent Endpoints

### `GET /v1/credentials`

List the credentials available in the vault — Login and Secure note items. This is the only way for an agent to discover what credentials exist — values are never included.

**Headers**
- `X-Agent-Key: <token>` — required

**Query parameters**
- `detail=true` — return objects with ready-made placeholders instead of plain names

**Response `200 OK`**
```json
["Proxmox (prod)", "grafana_service_account", "nas_key"]
```

**Response `200 OK` with `?detail=true`**
```json
[
  {
    "name": "Proxmox (prod)",
    "type": "login",
    "placeholder": "{{vault:'Proxmox (prod)'}}",
    "username": "{{vault:'Proxmox (prod)':username}}",
    "totp": "{{vault:'Proxmox (prod)':totp}}",
    "fields": { "api secret": "{{vault:'Proxmox (prod)':field:'api secret'}}" },
    "unavailable_fields": { "dup": "ambiguous: the item has more than one field with this name" },
    "bound_to": ["https://pve.lan:8006"]
  },
  {
    "name": "nas_key",
    "type": "secure_note",
    "notes": "{{vault:nas_key:notes}}",
    "bound_to": ["https://nas.lan"]
  },
  {
    "name": "root_token",
    "type": "login",
    "bound_to": ["https://pve.lan:8006"],
    "unavailable": "master password re-prompt is enabled on this item; agents cannot use it until approvals are supported"
  }
]
```

Each key is present only when that value exists on the item. `bound_to` lists the hosts the credential may be sent to. Copy placeholders verbatim rather than constructing them.

**Errors**
| Status | Condition |
|---|---|
| `400 Bad Request` | Unknown query parameter (only `detail` is accepted), or `detail` given more than once |
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
| `400 Bad Request` | Malformed request JSON; duplicate or unknown JSON fields; header names that differ only by case; unparseable URL; scheme not http/https; invalid HTTP method; placeholder in the URL host/port |
| `401 Unauthorized` | Missing or invalid agent key |
| `403 Forbidden` | Credential not bound to the target host, or target refused by the outbound policy (bw serve, private/internal address not in `allowed_targets`) |
| `403 Forbidden` (re-prompt) | The item has master password re-prompt enabled |
| `409 Conflict` | Placeholder name matches more than one vault item, or a field name appears more than once on the item |
| `422 Unprocessable Entity` | Malformed placeholder, unknown credential, or a value/field the item does not have |
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
| `400 Bad Request` | Malformed JSON, duplicate or unknown fields, or missing `password` |
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

(`POST /v1/admin/keys` also returns `400` for malformed JSON, duplicate or unknown fields, or a `name` outside 1-128 characters.)

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

Placeholders select a value of a Vaultwarden **Login** or **Secure note** item:

| Placeholder | Substitutes |
|---|---|
| `{{vault:NAME}}` | the item's password |
| `{{vault:NAME:password}}` | the password (explicit) |
| `{{vault:NAME:username}}` | the login username |
| `{{vault:NAME:totp}}` | the current TOTP code |
| `{{vault:NAME:notes}}` | the item's notes |
| `{{vault:NAME:field:FIELD}}` | a custom field (text, hidden, boolean, or linked to the username/password) |

`NAME` and `FIELD` are either a plain word of letters, digits, `_`, `-` and `.` — or a **single-quoted string**, which allows any characters (spaces, colons, anything). Inside quotes, write `\'` for a quote and `\\` for a backslash:

```
{{vault:proxmox_api_token}}
{{vault:'Proxmox (prod)':username}}
{{vault:'Proxmox (prod)':field:'api secret'}}
{{vault:'it\'s here'}}
```

Single quotes are used because placeholders usually sit inside JSON strings, where double quotes would need escaping. Names are case-sensitive and must match the vault exactly. **You rarely need to write quoting yourself:** `GET /v1/credentials?detail=true` returns the exact placeholder for every available value.

Anything starting with `{{vault:` that does not parse is rejected with `422` — malformed placeholders are never forwarded.

**Placement**
Placeholders may appear anywhere in:
- The request URL's path, query string or user info — **not** its scheme, host or port
- Any header value
- The request body (inside JSON string values or object keys, or a raw string body)

A single request may use multiple different placeholders. Duplicate placeholders in the same request (e.g., the same credential in two headers) are resolved with one vault call.
