# Ferrowarden Reference

## Endpoints

### GET /v1/credentials

Returns the names of all credentials available for use in placeholders. Names only -- values are never returned.

**Headers:** `X-Agent-Key: <token>`

**Response 200:**
```json
["proxmox_api_token", "nas_api_key", "grafana_service_account"]
```

---

### POST /v1/forward

Substitutes placeholders, forwards the request, and returns the scrubbed response.

**Headers:** `X-Agent-Key: <token>`, `Content-Type: application/json`

**Request body:**

| Field | Type | Required | Notes |
|---|---|---|---|
| `request.method` | string | yes | GET, POST, PUT, PATCH, DELETE, HEAD |
| `request.url` | string | yes | Must start with `http://` or `https://` |
| `request.headers` | object | no | String values only. `x-fw-*` headers are stripped. |
| `request.body` | string or JSON | no | Any JSON value or plain string |

**Response 200:**

| Field | Type | Notes |
|---|---|---|
| `status` | number | HTTP status from the target |
| `headers` | object | Response headers from the target (hop-by-hop stripped) |
| `body` | string | Target response body, scrubbed for credential patterns |

---

### GET /health

Returns `200 OK` with no body. No authentication required. Used by health checks.

---

## Error codes

| Status | Error | Cause | Action |
|---|---|---|---|
| 400 | Bad Request | Invalid URL scheme or HTTP method | Use `http://` or `https://`; check method spelling |
| 401 | Unauthorized | Missing or invalid `X-Agent-Key` | Token is wrong or revoked; notify the operator |
| 422 | Unprocessable Entity | Placeholder references unknown name | List credentials; use an exact name from the response |
| 429 | Too Many Requests | Rate limit exceeded | Wait `Retry-After` seconds; retry once |
| 502 | Bad Gateway | Target unreachable or bw serve error | Check URL; notify the operator if vault communication failed |
| 503 | Service Unavailable | Vault is locked | Notify the operator to unlock the vault |

All error responses: `{ "error": "message" }`

---

## Placeholder rules

- Syntax: `{{vault:name}}` -- double braces, `vault:`, then the name. No spaces.
- Names are case-sensitive. `proxmox_api_token` != `Proxmox_API_Token`.
- Placeholders are valid in `request.url`, any header value in `request.headers`, and anywhere in `request.body` (string position inside a JSON value or a plain string body).
- An unknown name causes the entire request to be rejected (422) before any outbound call is made.
- Multiple different placeholders in one request: allowed.
- Same placeholder repeated: allowed.

---

## Rate limits

| Route group | Sustained rate | Burst |
|---|---|---|
| Agent endpoints (`/v1/credentials`, `/v1/forward`, `/v1/unlock`) | 120 req/min | 20 |
| Admin endpoints (`/v1/admin/*`) | 30 req/min | 5 |

Limits are per source IP. `Retry-After` header on 429 gives seconds until the next token is available.

---

## Constraints

- Redirects are not followed. A 301/302 response is returned as-is.
- Request timeout to target: 30 seconds.
- `X-Agent-Key` and `X-Admin-Key` on the outer request are never forwarded to the target.
- Headers beginning with `x-fw-` inside `request.headers` are stripped before forwarding.
- Response body is scrubbed for: Bearer tokens, API key/secret/password JSON fields, PEM private key blocks, Basic auth credentials in URLs, and Proxmox PVEAPIToken values. The scrubber may over-redact; treat the body as the target's intent, not a verbatim copy.
