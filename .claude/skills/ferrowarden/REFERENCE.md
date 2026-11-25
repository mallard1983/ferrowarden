# Ferrowarden Reference

## Endpoints

Paths are relative to the configured base URL, which may include an operator-chosen prefix (e.g. `/k7f3q9/v1/forward`). `/health` is never prefixed.

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
| `request.body` | string or JSON | no | JSON string → sent as raw text. Object/array → sent as JSON (`Content-Type: application/json` added if absent) |

**Response 200:**

| Field | Type | Notes |
|---|---|---|
| `status` | number | HTTP status from the target |
| `headers` | object | Response headers from the target (hop-by-hop stripped) |
| `body` | string | Target response body; substituted values and credential patterns replaced with `[REDACTED]` |
| `body_encoding` | string | `"utf8"`, or `"base64"` when the response was binary |

---

### GET /v1/openapi.json

Returns the OpenAPI 3.1 description of the operations your key can call, as JSON. Use it if your framework can read OpenAPI or you want the exact request and response schemas. `servers[0].url` is the base URL to use.

**Headers:** `X-Agent-Key: <token>`

---

### GET /health

Returns `200 OK` with no body. No authentication required. Used by health checks.

---

## Error codes

| Status | Error | Cause | Action |
|---|---|---|---|
| 400 | Bad Request | Invalid URL scheme, or a method other than GET/HEAD/POST/PUT/PATCH/DELETE/OPTIONS (TRACE, CONNECT are refused); placeholder in URL host/port; invalid request JSON (extra fields, duplicate keys, header names differing only by case) | Use `http://` or `https://`; check method; keep placeholders out of the host; fix the request JSON and don't send extra fields |
| 401 | Unauthorized | Missing or invalid `X-Agent-Key` | Token is wrong or revoked; notify the operator |
| 403 | Forbidden | Credential not bound to this host, or target blocked (internal address / vault backend) | Do not try other hosts. Tell the user which credential/host was refused |
| 403 | Forbidden | "Credential X is not available to this agent key" (your key's scope excludes it; same answer whether or not it exists) | Do not retry with other names. Tell the user which credential you needed |
| 403 | Forbidden | "Method M is not allowed for this agent key" | Do not switch methods to work around it. Tell the user which method you needed |
| 409 | Conflict | Credential name matches several vault items | Tell the user; the operator must rename one |
| 422 | Unprocessable Entity | Malformed placeholder, unknown name, or value/field the item lacks | Copy a placeholder from `GET /v1/credentials?detail=true` |
| 429 | Too Many Requests | Rate limit exceeded | Wait `Retry-After` seconds; retry once |
| 502 | Bad Gateway | Target unreachable, timed out, or response too large | Check URL; notify the operator if it persists |
| 503 | Service Unavailable | Vault is locked or vault backend unreachable | Notify the operator to unlock the vault |

All error responses: `{ "error": "message" }`

---

## Placeholder rules

- Syntax: `{{vault:NAME}}` (password), `{{vault:NAME:username}}`, `{{vault:NAME:totp}}`, `{{vault:NAME:notes}}`, `{{vault:NAME:field:FIELD}}`.
- NAME/FIELD: a plain word (letters, digits, `_ - .`) or a single-quoted string for anything else: `{{vault:'Proxmox (prod)':field:'api secret'}}` (escape `\'` and `\\`).
- Easiest: `GET /v1/credentials?detail=true` returns every placeholder ready to copy, plus `bound_to` hosts.
- Names are case-sensitive. `proxmox_api_token` != `Proxmox_API_Token`.
- Placeholders are valid in the path, query or user info of `request.url` (never the scheme, host or port), any header value in `request.headers`, and anywhere in `request.body` (inside JSON strings/keys or a plain string body).
- Each credential only works for the host(s) the operator bound it to; any other host returns 403.
- `GET /v1/credentials` lists only what your key may use; a name outside that is refused with 403 even if it exists.
- An unknown name causes the entire request to be rejected (422) before any outbound call is made.
- Multiple different placeholders in one request: allowed.
- Same placeholder repeated: allowed.

---

## Rate limits

| Route group | Sustained rate | Burst |
|---|---|---|
| Agent endpoints (`/v1/credentials`, `/v1/forward`) | 120 req/min (operator-configurable) | 20 (operator-configurable) |
| Admin endpoints (`/v1/admin/*`, `/v1/unlock`) | 30 req/min | 5 |

Limits are per source IP. `Retry-After` header on 429 gives seconds until the next token is available.

---

## Constraints

- Redirects are not followed. A 301/302 response is returned as-is.
- Request timeout to target: 30 seconds by default (operator-configurable).
- Responses larger than 10 MiB (default) are rejected with 502.
- `X-Agent-Key` and `X-Admin-Key` on the outer request are never forwarded to the target.
- Headers beginning with `x-fw-` inside `request.headers` are stripped before forwarding.
- Response body and header values are scrubbed for every credential value used in the request (raw, JSON-escaped, URL-encoded, base64), plus: Bearer tokens, API key/secret/password JSON fields, PEM private key blocks, Basic auth credentials in URLs, and Proxmox PVEAPIToken values. The scrubber may over-redact; treat the body as the target's intent, not a verbatim copy.

## MCP tools (`ferrowarden-mcp`)

When the harness runs `ferrowarden-mcp`, the same API is available as two tools. The bridge holds the agent key and the base URL; the agent never handles either.

| Tool | Does | Arguments |
|---|---|---|
| `list_credentials` | `GET /v1/credentials?detail=true` | none |
| `http_request` | `POST /v1/forward` | `method`, `url`, `headers` (optional), `body` (optional) |

Results have structured content (as the API returns it; the credential list is under `credentials`) and a text rendering. A non-success answer from Ferrowarden itself is a tool error carrying the HTTP status, Ferrowarden's message, the request id and one line of guidance (`403`: do not retry with other credentials, hosts or methods, tell the user; `422`: copy a placeholder from `list_credentials`; `429`: wait `Retry-After` seconds; `503`: the vault is locked, tell the user). A `404` or `500` from the target is a normal result with that status.
