# Ferrowarden Examples

## 1. GET request with Bearer token

**Task:** Query the Grafana API using the stored service account token.

Step 1 -- list credentials:
```
GET /v1/credentials
X-Agent-Key: ag_abc123...
```
Response: `["grafana_service_account", "proxmox_api_token", "nas_api_key"]`

Step 2 -- forward the call:
```json
POST /v1/forward
X-Agent-Key: ag_abc123...

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

Response:
```json
{
  "status": 200,
  "headers": { "content-type": "application/json" },
  "body": "{\"title\":\"Home\",\"panels\":[...]}"
}
```

---

## 2. POST with JSON body containing a password

**Task:** Authenticate against the NAS API.

```json
POST /v1/forward
X-Agent-Key: ag_abc123...

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

---

## 3. Credential in the URL (query parameter)

```json
POST /v1/forward
X-Agent-Key: ag_abc123...

{
  "request": {
    "method": "GET",
    "url": "https://api.service.com/v1/data?api_key={{vault:service_api_key}}&limit=100"
  }
}
```

---

## 4. Proxmox PVEAPIToken format

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

---

## 5. Multiple credentials in one request

```json
{
  "request": {
    "method": "POST",
    "url": "https://internal-api.lan/sync",
    "headers": {
      "Authorization": "Bearer {{vault:sync_api_key}}",
      "X-Source-Token": "{{vault:source_service_token}}",
      "Content-Type": "application/json"
    },
    "body": { "action": "pull" }
  }
}
```

---

## 6. Log in and keep the token out of context (Portainer)

Step 1: log in, and ask Ferrowarden to capture the `jwt` of the answer.
```json
{
  "request": {
    "method": "POST",
    "url": "https://portainer.lan:9443/api/auth",
    "body": { "username": "{{vault:portainer:username}}", "password": "{{vault:portainer}}" }
  },
  "capture": [{ "from": "json:/jwt", "as": "portainer" }]
}
```

Response (the token is not in it):
```json
{
  "status": 200,
  "headers": { "content-type": "application/json" },
  "body": "{\"jwt\":\"[CAPTURED:portainer]\"}",
  "body_encoding": "utf8",
  "captures": [{ "as": "portainer", "status": "captured", "expires_at": "2026-01-01T12:30:00Z" }]
}
```

Step 2: use it.
```json
{
  "request": {
    "method": "GET",
    "url": "https://portainer.lan:9443/api/endpoints",
    "headers": { "Authorization": "Bearer {{session:portainer}}" }
  }
}
```

If step 2 returns `422` ("Session portainer is unknown or expired; log in again"), repeat step 1. If `captures[0].status` is not `captured`, nothing was stored: do not retry blindly; read the status (`not_found` means the pointer is wrong) and tell the user if it persists.

---

## 7. Proxmox ticket and CSRF token

Capture both values of the login answer:
```json
{
  "request": {
    "method": "POST",
    "url": "https://pve.lan:8006/api2/json/access/ticket",
    "headers": { "Content-Type": "application/x-www-form-urlencoded" },
    "body": "username={{vault:proxmox:username}}&password={{vault:proxmox}}"
  },
  "capture": [
    { "from": "json:/data/ticket", "as": "pve_ticket" },
    { "from": "json:/data/CSRFPreventionToken", "as": "pve_csrf" }
  ]
}
```

Reads need the cookie; writes need the CSRF header too:
```json
{
  "request": {
    "method": "POST",
    "url": "https://pve.lan:8006/api2/json/nodes/pve/qemu/100/status/stop",
    "headers": {
      "Cookie": "PVEAuthCookie={{session:pve_ticket}}",
      "CSRFPreventionToken": "{{session:pve_csrf}}"
    }
  }
}
```

---

## 8. Handling a 422 -- unknown credential name

Response:
```json
{ "error": "Placeholder references unknown credential: nas_password" }
```

Correct action:
1. Call `GET /v1/credentials` again.
2. Find the actual name (e.g. `nas_admin_password`).
3. Retry with the correct name.
4. If the needed credential does not appear in the list, tell the user: "I need a credential named `nas_admin_password` added to the vault before I can complete this."

---

## 9. Handling a 429 -- rate limit

Response headers include `Retry-After: 3`.

Correct action: wait 3 seconds, then resend the identical request once.

---

## 10. Handling a 503 -- vault locked

```json
{ "error": "Vault is locked" }
```

Correct action: do not retry. Tell the user: "Ferrowarden's vault is locked. The operator needs to unlock it before I can make credentialed API calls."

## Set up a new service without seeing its password

The user asks you to deploy Keycloak with an admin account. Ask Ferrowarden to make the credential:

```
POST /v1/credentials
{ "name": "agent_keycloak_admin", "username": "admin",
  "uris": ["https://keycloak.example.com"],
  "generate": { "length": 32, "charset": "alphanumeric" } }
```

After a minute with no decision:

```
403 { "error": "Approval required: ...", "code": "approval_pending", "approval_id": "2m3x8Qk0Zr1YtV5pUa9bLw" }
```

Tell the user: "Please approve request 2m3x8Qk0Zr1YtV5pUa9bLw (creating agent_keycloak_admin) in the Ferrowarden admin UI." When they say it is done, send the **identical** request again:

```
201 { "name": "agent_keycloak_admin", "placeholder": "{{vault:agent_keycloak_admin}}", "cache_refreshed": true }
```

Use the placeholder where the password belongs:

```
POST /v1/forward
{ "request": { "method": "POST", "url": "https://keycloak.example.com/admin/setup",
    "body": { "username": "{{vault:agent_keycloak_admin:username}}",
              "password": "{{vault:agent_keycloak_admin}}" } } }
```

You never saw the password. If the user needs it, it is in Vaultwarden in the managed collection.

## Rotate a service account's password without seeing it

The user asks you to change the password of `agent_keycloak_svc`. Start a rotation:

```
POST /v1/credentials/agent_keycloak_svc/rotate
```

After a minute with no decision:

```
403 { "error": "Approval required: ...", "code": "approval_pending", "approval_id": "2m3x8Qk0Zr1YtV5pUa9bLw" }
```

Tell the user: "Please approve request 2m3x8Qk0Zr1YtV5pUa9bLw (rotating agent_keycloak_svc) in the Ferrowarden admin UI." When they say it is done, send the **identical** request again:

```
202 { "name": "agent_keycloak_svc", "current": "{{vault:agent_keycloak_svc}}", "next": "{{vault:agent_keycloak_svc:next}}" }
```

Change the password at the service, signing in with the current one and sending the new one:

```
POST /v1/forward
{ "request": { "method": "POST", "url": "https://keycloak.example.com/account/credentials/password",
    "body": { "username": "{{vault:agent_keycloak_svc:username}}",
              "currentPassword": "{{vault:agent_keycloak_svc}}",
              "newPassword": "{{vault:agent_keycloak_svc:next}}" } } }
```

If the service answers success, commit:

```
POST /v1/credentials/agent_keycloak_svc/rotate/commit
200 { "name": "agent_keycloak_svc", "placeholder": "{{vault:agent_keycloak_svc}}" }
```

If it refused the change, abort instead (`POST /v1/credentials/agent_keycloak_svc/rotate/abort`) and tell the user. If the commit answers `409` with `"code": "vault_conflict"`, someone edited the item meanwhile: nothing was overwritten, so read the credential again and retry. You never saw either password.
