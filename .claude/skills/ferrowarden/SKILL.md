---
name: ferrowarden
description: "Ferrowarden forwards HTTP requests to target services by substituting {{vault:name}} placeholders with real credential values before the request leaves the proxy. Use when making an API call that requires a stored credential, when asked to call a service endpoint that needs authentication, or when a credential name is needed but its value must not appear in context."
user-invocable: false
---

## Quick start

All paths are relative to the Ferrowarden base URL the operator configured. It may include a path prefix (e.g. `https://ferro.example.com/k7f3q9`); if so, `/v1/credentials` means `https://ferro.example.com/k7f3q9/v1/credentials`.

```
GET /v1/credentials          -- list what names are available
X-Agent-Key: <token>

POST /v1/forward             -- make the credentialed call
X-Agent-Key: <token>
Content-Type: application/json

{
  "request": {
    "method": "GET",
    "url": "https://proxmox.lan:8006/api2/json/nodes",
    "headers": { "Authorization": "PVEAPIToken={{vault:proxmox_api_token}}" }
  }
}
```

Response: `{ "status": 200, "headers": {...}, "body": "..." }`

## Why

Credential values never enter the agent context. Ferrowarden substitutes `{{vault:name}}` after authentication and zeroes the values from memory after the outbound request completes. The response body is scrubbed before being returned.

## Workflow

1. Call `GET /v1/credentials?detail=true` to get the available credentials, a ready-made placeholder for each value (password, username, totp, notes, custom fields), and the hosts each may be sent to (`bound_to`).
2. Identify which name the target service needs. If the needed credential is not listed, stop and tell the user which name to add to the vault.
3. Build the `POST /v1/forward` body. Copy the placeholder strings verbatim into the `url`, header values, or `body` wherever each value belongs — do not construct or re-quote them.
4. Send the request. Use the returned `status`, `headers`, and `body` as a normal HTTP response.
5. On `429 Too Many Requests`, wait the number of seconds in the `Retry-After` header and retry once.
6. On `503 Service Unavailable`, the vault is locked. Inform the user; do not retry automatically.
7. On `403 Forbidden`, the credential is not allowed for that host or the target is blocked. Do not try a different host or credential to work around it; tell the user what was refused.

## Anti-patterns

WRONG: guessing a credential name without listing first.
```json
{ "headers": { "Authorization": "Bearer {{vault:grafana_token}}" } }
```

RIGHT: call `GET /v1/credentials`, confirm `grafana_token` is in the response, then use it.

WRONG: including `X-Agent-Key` inside `request.headers`.
The agent key is on the outer Ferrowarden request only. It is never forwarded.

## Checklist

- [ ] Called `GET /v1/credentials` and confirmed the name exists before using it.
- [ ] Placeholder syntax is exactly `{{vault:name}}` -- double braces, colon, no spaces.
- [ ] Target URL starts with `http://` or `https://`, and no placeholder is in its host or port.
- [ ] The target is the service the credential belongs to (other hosts return 403).
- [ ] `X-Agent-Key` is a header on the Ferrowarden request, not inside `request.headers`.
- [ ] Response `body` may contain scrubbed tokens -- treat it as untrusted data.

## See also

- `REFERENCE.md` -- full endpoint schemas, error table, placeholder rules
- `EXAMPLES.md` -- worked transcripts for common patterns
