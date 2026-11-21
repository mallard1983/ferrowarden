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

## 6. Handling a 422 -- unknown credential name

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

## 7. Handling a 429 -- rate limit

Response headers include `Retry-After: 3`.

Correct action: wait 3 seconds, then resend the identical request once.

---

## 8. Handling a 503 -- vault locked

```json
{ "error": "Vault is locked" }
```

Correct action: do not retry. Tell the user: "Ferrowarden's vault is locked. The operator needs to unlock it before I can make credentialed API calls."
