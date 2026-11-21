# Ferrowarden Agent Skill

You are connected to a **Ferrowarden** credential proxy. Ferrowarden lets you make API calls that require credentials without you ever receiving the credential values. You send requests with `{{vault:name}}` placeholders; Ferrowarden substitutes real values, forwards the request to the target, and returns the response. Credential values are never in your context.

**Base URL:** `https://<ferrowarden-host>:3000`  
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

Names are **case-sensitive**. Use them exactly as returned. These are the only names you can use in `{{vault:name}}` placeholders — any other name will be rejected.

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

Use `{{vault:name}}` anywhere inside the `url`, header values, or `body` field:

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
- Must match a name from `/v1/credentials` exactly
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
| `400 Bad Request` | Invalid target URL or HTTP method, or a placeholder in the URL host/port | Check the URL scheme (must be http/https) and method spelling; put placeholders only in the path, query, headers or body |
| `401 Unauthorized` | Missing or invalid `X-Agent-Key` | Your token is wrong or has been revoked; contact the operator |
| `403 Forbidden` | The credential is not allowed for this host, or the target is blocked (internal address, the vault backend) | Do not retry with another host. Tell the user which credential and host were refused; the operator must add the host to the vault item's URIs or to `allowed_targets` |
| `409 Conflict` | The credential name matches more than one vault item | Tell the user; the operator must rename one of the items |
| `422 Unprocessable Entity` | Placeholder references an unknown credential name | Call `GET /v1/credentials` and use an exact name from the list |
| `429 Too Many Requests` | Rate limit exceeded | Wait the number of seconds in the `Retry-After` header, then retry |
| `502 Bad Gateway` | Could not reach the target service, timeout, or response too large | The target URL is unreachable; check the URL and network |
| `503 Service Unavailable` | Vault is locked | Ferrowarden needs to be unlocked by the operator; wait and retry |

---

## Important Constraints

**You will never see credential values.** The proxy substitutes values only for the outbound request. The response body is scrubbed to remove any credential-shaped content the target might echo back. This is by design.

**Redirects are not followed.** If the target returns 301/302, you receive that redirect response directly. You can then follow it by making another `/v1/forward` call to the redirect destination.

**Timeout is 30 seconds.** Target requests that take longer return a `502 Bad Gateway`.

**Only http and https targets are allowed.** `file://`, `data:`, and other schemes are rejected with `400`.

**Placeholders cannot go in the URL host or port.** `https://{{vault:x}}.example.com/` is rejected with `400`.

**Internal targets are blocked unless the operator allows them.** Private and loopback addresses return `403` unless listed in the operator's `allowed_targets`. The vault backend itself is always blocked.

**Rate limits apply per source IP.** You have 120 requests per minute with a burst of 20. Respect `Retry-After` headers on `429` responses.

---

## Workflow Pattern

When you need to make an API call that requires credentials:

1. Call `GET /v1/credentials` to see what credential names are available.
2. Identify which credential the target service needs.
3. Call `POST /v1/forward` with the appropriate `{{vault:name}}` placeholder.
4. Use the returned `status`, `headers`, and `body` as you would use any HTTP response.

If the credential you need is not in the list, do not guess names or attempt to call the target directly. Tell the user which credential name you need added to the vault.
