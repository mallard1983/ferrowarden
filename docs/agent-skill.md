# Ferrowarden Agent Skill

You are connected to a **Ferrowarden** credential proxy. Ferrowarden lets you make API calls that require credentials without being handed the credential values. You send requests with `{{vault:name}}` placeholders; Ferrowarden substitutes real values, forwards the request to the target, and returns the response. Credential values stay outside your context by design.

**Base URL:** `https://<ferrowarden-host>:3000` — or the URL the operator gave you, which may include a path prefix (e.g. `https://ferro.example.com/k7f3q9`). All paths below are relative to it.  
**Authentication:** Every request requires the header `X-Agent-Key: <your-token>`

---

## Step 1 — List Available Credentials

Before making any forwarded request, list the credentials available to you. This tells you exactly which placeholder names are valid.

```
GET /v1/credentials
X-Agent-Key: <your-token>
```

**Response** `200 OK`:
```json
["proxmox_api_token", "nas_api_key", "plex_token", "grafana_service_account"]
```

Names are **case-sensitive**. Use them exactly as returned. These are the only names you can use in `{{vault:name}}` placeholders — any other name will be rejected. The list shows only what **your key** is allowed to use; the operator may have scoped it to a subset of the vault, and may also limit which HTTP methods it can send.

---

## Step 2 — Forward a Request

```
POST /v1/forward
X-Agent-Key: <your-token>
Content-Type: application/json
```

**Request body:**
```json
{
  "request": {
    "method": "GET | POST | PUT | PATCH | DELETE | ...",
    "url": "https://target-service/path",
    "headers": {
      "Header-Name": "value or {{vault:name}}"
    },
    "body": "optional body — string or JSON object"
  }
}
```

All fields in `request`:

| Field | Type | Required | Description |
|---|---|---|---|
| `method` | string | yes | HTTP method (GET, POST, PUT, PATCH, DELETE, HEAD) |
| `url` | string | yes | Full target URL — must start with `http://` or `https://` |
| `headers` | object | no | Headers to send to the target — string values only |
| `body` | string or JSON | no | A JSON string is sent as raw text (e.g. form data); an object/array is sent as JSON (with `Content-Type: application/json` added if you did not set one) |

**Response** `200 OK`:
```json
{
  "status": 200,
  "headers": {
    "content-type": "application/json"
  },
  "body": "...",
  "body_encoding": "utf8"
}
```

The `status` and `headers` are from the target service. The `body` is the target's response body — scrubbed to remove the credential values used in the request (shown as `[REDACTED]`) and other credential-shaped content. If the response is binary, `body` is base64 and `body_encoding` is `"base64"`.

**Each credential only works with its own service.** The operator binds every credential to the host(s) it belongs to. Using `{{vault:grafana_token}}` in a request to any other host returns `403` and nothing is sent.

---

## Placeholder Syntax

Use placeholders anywhere inside the `url` (path/query), header values, or `body` field. The simplest way to get them right: call `GET /v1/credentials?detail=true` and **copy the placeholder strings it returns** — they are already correctly quoted.

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

Examples:

```json
{
  "request": {
    "method": "GET",
    "url": "https://proxmox.lan:8006/api2/json/nodes",
    "headers": {
      "Authorization": "PVEAPIToken={{vault:proxmox_api_token}}"
    }
  }
}
```

```json
{
  "request": {
    "method": "POST",
    "url": "https://api.service.com/data",
    "headers": {
      "Authorization": "Bearer {{vault:api_key}}",
      "Content-Type": "application/json"
    },
    "body": {
      "token": "{{vault:service_secret}}",
      "action": "query"
    }
  }
}
```

**Placeholder rules:**
- Must match a name from `/v1/credentials` exactly — prefer copying from `?detail=true`
- Each credential only works for the hosts in its `bound_to` list
- Multiple placeholders in one request are fine
- One placeholder can appear multiple times
- Placeholders work in URL, header values, and body — in any combination
- Do not guess credential names; list them first

---

## Examples

### GET request with Bearer token

```json
{
  "request": {
    "method": "GET",
    "url": "https://grafana.lan/api/dashboards/home",
    "headers": {
      "Authorization": "Bearer {{vault:grafana_service_account}}"
    }
  }
}
```

### POST with JSON body

```json
{
  "request": {
    "method": "POST",
    "url": "https://nas.lan/api/v2/auth/login",
    "headers": {
      "Content-Type": "application/json"
    },
    "body": {
      "username": "admin",
      "password": "{{vault:nas_admin_password}}"
    }
  }
}
```

### Credential in the URL

```json
{
  "request": {
    "method": "GET",
    "url": "https://api.service.com/endpoint?api_key={{vault:service_api_key}}"
  }
}
```

---

## Error Responses

All errors return `{"error": "message"}` with an appropriate HTTP status.

| Status | Meaning | What to do |
|---|---|---|
| `400 Bad Request` | Invalid target URL, a method that is not one of GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS (e.g. TRACE, CONNECT), a placeholder in the URL host/port, or invalid request JSON (extra fields, duplicate keys, header names differing only by case) | Check the URL scheme (must be http/https) and method spelling; put placeholders only in the path, query, headers or body; fix the request JSON and don't send extra fields or repeated keys |
| `401 Unauthorized` | Missing or invalid `X-Agent-Key` | Your token is wrong or has been revoked; contact the operator |
| `403 Forbidden` ("not available to this agent key") | `Credential <name> is not available to this agent key`: your key is not allowed to use that credential. This looks the same whether or not the credential exists | Do not retry with other names or try to discover it. Tell the user which credential you needed so the operator can widen your key's scope |
| `403 Forbidden` ("method not allowed") | `Method <M> is not allowed for this agent key`: your key may not use that HTTP method | Do not retry with a different method to work around it. Tell the user which method you needed |
| `403 Forbidden` | The credential is not allowed for this host, or the target is blocked (internal address, the vault backend) | Do not retry with another host. Tell the user which credential and host were refused; the operator must add the host to the vault item's URIs or to `allowed_targets` |
| `409 Conflict` | The credential name matches more than one vault item, or the field name appears twice on the item | Tell the user; the operator must rename one of them |
| `422 Unprocessable Entity` | Malformed placeholder, unknown credential, or a value/field the item doesn't have | Call `GET /v1/credentials?detail=true` and copy a placeholder from it |
| `429 Too Many Requests` | Rate limit exceeded | Wait the number of seconds in the `Retry-After` header, then retry |
| `502 Bad Gateway` | Could not reach the target service, timeout, or response too large | The target URL is unreachable; check the URL and network |
| `503 Service Unavailable` | Vault is locked | Ferrowarden needs to be unlocked by the operator; wait and retry |

---

## Important Constraints

**You are not given credential values.** The proxy substitutes values only for the outbound request, and scrubs known credential values and common credential patterns from the response. This is by design; scrubbing has limits (see [security.md](security.md)), so do not ask a target to echo or transform a credential, and do not try to read values back.

**Redirects are not followed.** If the target returns 301/302, you receive that redirect response directly. You can then follow it by making another `/v1/forward` call to the redirect destination.

**Timeout is 30 seconds.** Target requests that take longer return a `502 Bad Gateway`.

**Only http and https targets are allowed.** `file://`, `data:`, and other schemes are rejected with `400`.

**Placeholders cannot go in the URL host or port.** `https://{{vault:x}}.example.com/` is rejected with `400`.

**Internal targets are blocked unless the operator allows them.** Private and loopback addresses return `403` unless listed in the operator's `allowed_targets`. The vault backend itself is always blocked.

**Rate limits apply per source IP.** By default you have 120 requests per minute with a burst of 20 (the operator may configure different limits). Respect `Retry-After` headers on `429` responses.

---

## Workflow Pattern

When you need to make an API call that requires credentials:

1. Call `GET /v1/credentials` to see what credential names are available.
2. Identify which credential the target service needs.
3. Call `POST /v1/forward` with the appropriate `{{vault:name}}` placeholder.
4. Use the returned `status`, `headers`, and `body` as you would use any HTTP response.

A machine-readable description of this API is available too: `GET /v1/openapi.json` with your `X-Agent-Key` returns an OpenAPI 3.1 document listing the operations you can call.

If the credential you need is not in the list, do not guess names or attempt to call the target directly. Tell the user which credential name you need added to the vault.
