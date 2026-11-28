# Operations

## Unlock Modes

Ferrowarden starts locked regardless of mode. The vault must be unlocked before the proxy will serve any requests.

### File Mode (`unlock_mode = "file"`)

Ferrowarden reads the master password from the path specified in `unlock_file`, uses it to unlock the vault (Ferrowarden logs in with the API key, syncs, and derives the vault keys from it), zeroes the value from memory, and then begins serving.

This all happens before the HTTP server starts accepting connections. If the unlock fails (wrong password, Vaultwarden unreachable, the API key rejected), Ferrowarden exits with an error. No requests are possible until the issue is corrected and the process is restarted.

**Use this mode when:**
- Running in Docker with a Docker secret or a bind-mounted password file
- You want zero-touch restarts (the container restarts and unlocks automatically)
- You accept that the master password exists on disk (protected by file permissions and Docker secret management)

**The file is read once and the value is zeroed.** The file remaining on disk after startup is not a security concern — the running process holds no reference to it after unlock.

### Manual Mode (`unlock_mode = "manual"`)

Ferrowarden starts and immediately begins listening. All credential proxy requests return `503 Service Unavailable` until an operator posts the master password to `POST /v1/unlock`.

```sh
curl -X POST https://<ferrowarden-host>:3000/v1/unlock \
  -H "X-Admin-Key: $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"password": "your-master-password"}' \
  --cacert certs/server.crt
```

**Use this mode when:**
- You want explicit human confirmation per boot (audit/compliance requirement)
- You prefer the master password to never exist on disk at the deployment host
- You can tolerate a brief period after restart where the proxy is unavailable

---

## Checking the vault backend

`vault.backend` is `native`, the only value ([native-vault.md](native-vault.md)); the `bw-serve` backend was removed in 0.3.0, and a configuration that still names it fails at startup with a pointer to the [upgrade note](native-vault.md#upgrading-from-bw-serve). Ferrowarden stores nothing between runs.

1. **After an upgrade or a change.** `GET /v1/admin/status` reports `"vault_backend": "native"`, and so do the startup event, the `ferrowarden_build_info` metric and the admin UI's status page. The value is always `native` now; the field stays so that dashboards and SIEM rules keep working. A `vault_sync` event with an `excluded` count means some items were left out: see its `excluded_reasons`. Most reasons mean an item could not be read safely; `hidden_password` means its collection hides passwords from this account (`vault.allow_hidden_passwords` is off, [native-vault.md](native-vault.md#hidden-passwords-collections-that-hide-them)).
2. **From a 0.1.0 deployment.** Follow the [0.2.0 release notes](release-notes/v0.2.0.md#upgrading) first: it gives the ferrowarden service the `bw_client_id` / `bw_client_secret` secrets and sets `FERROWARDEN_VAULT_CLIENT_ID_FILE`, `FERROWARDEN_VAULT_CLIENT_SECRET_FILE`, `FERROWARDEN_VAULT__URL` and `FERROWARDEN_VAULT__CA_FILE` (`ui.vaultwarden_*` still work as deprecated aliases). Outside Compose, set those yourself. Then upgrade.

A leftover `bw_serve_url` is ignored, with a warning at startup. The account's password or key changing locks the vault (`vault_lock`, cause `vault_key_changed` or `security_stamp_changed`): in file mode update the password file, then restart.

---

## Seeding Test Credentials

For development and testing, a standard set of credentials can be seeded into Vaultwarden automatically. The seeder is idempotent — it checks for existing credentials by name before creating them, so it is safe to run on every spin-up without creating duplicates.

### Credential Definitions

Test credentials are defined in [`tests/seed/credentials.json`](../tests/seed/credentials.json). Each entry has a `name` (the placeholder name used in `{{vault:name}}`), a `value` (an obviously fake test value), and an optional `note`.

Edit this file to add, rename, or remove credentials for your test environment.

### Running the Seeder

The seeder is a Docker Compose service under the `seed` profile. It runs once and exits.

```sh
# Seed credentials into a running Vaultwarden instance
docker compose --profile seed up vault-seeder

# Full dev spin-up: seed first, then bring up the stack
docker compose --profile seed up --wait vault-seeder && docker compose up -d
```

The seeder will:
1. Wait for Vaultwarden to become ready (up to 60 seconds)
2. Log in using the same API key as Ferrowarden
3. Unlock the vault with the master password
4. For each credential in `credentials.json`: skip if name already exists, create if not
5. Lock the vault and exit

### Adding New Test Credentials

Add entries to `tests/seed/credentials.json`:

```json
{
  "name": "my_new_service_token",
  "value": "test-my-service-00000000",
  "note": "Token for my-new-service integration tests"
}
```

Re-run the seeder. Existing credentials are unchanged; only the new entry is created.

### Resetting to a Clean State

To wipe all credentials and re-seed from scratch:

```sh
# Stop the stack and delete vault data
docker compose down
docker volume rm ferrowarden_vaultwarden-data

# Bring up Vaultwarden, re-register your account (see docs/setup.md Step 2)
docker compose up -d vaultwarden

# Re-seed
docker compose --profile seed up vault-seeder

# Start the full stack
docker compose up -d
```

---

## Managing Agent Keys

Replace `<ferrowarden-host>` in the examples below with the hostname or IP of the machine running Ferrowarden. If the agent is on the same host, use `localhost`. TLS is on by default; use `--cacert certs/server.crt` with a self-signed cert, or `-k` to skip verification (dev only).

### Approving sensitive credentials

A credential that should not be used without a person is marked in the vault (a `ferrowarden_approval` custom field with the value `required`) or per key (the key's `approval` patterns). An agent that uses it is held, you get a notification, and you decide in the admin UI (Approvals) or with the admin API. See [approvals.md](approvals.md). The day-to-day:

```sh
# What is waiting, and which grants are live
curl -s https://<ferrowarden-host>:3000/v1/admin/approvals -H "X-Admin-Key: $ADMIN_KEY"
# Approve for 15 minutes, or deny
curl -s -X POST https://<ferrowarden-host>:3000/v1/admin/approvals/<id>/approve \
  -H "X-Admin-Key: $ADMIN_KEY" -H "Content-Type: application/json" -d '{"minutes": 15}'
curl -s -X POST https://<ferrowarden-host>:3000/v1/admin/approvals/<id>/deny -H "X-Admin-Key: $ADMIN_KEY"
# End a grant early
curl -s -X DELETE https://<ferrowarden-host>:3000/v1/admin/grants/<grant-id> -H "X-Admin-Key: $ADMIN_KEY"
```

Check that a notifier delivers the prompt (`POST /v1/admin/notify/test`) and that `ui.public_url` is set, or the prompt has no link. A reverse proxy in front of the API needs a read timeout above `approval.wait_secs`. Grants and open approvals are in memory: a restart or a vault lock clears them.

### Creating Keys

```sh
curl -X POST https://<ferrowarden-host>:3000/v1/admin/keys \
  -H "X-Admin-Key: $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name": "descriptive-agent-name", "credentials": ["uptime_kuma_*"], "methods": ["GET"]}' \
  --cacert certs/server.crt
```

`credentials` and `methods` are **required**: a key has no access until you say what it may use. `["*"]` allows everything, `[]` nothing; `null` is rejected. See [Key policy](api-reference.md#key-policy) for the pattern rules. Prefer the narrowest policy the agent needs (see [Staged rollout with scoped keys](#staged-rollout-with-scoped-keys)).

Name keys descriptively. The name appears in audit log entries — if something unexpected happens, the name is how you identify which agent was responsible.

The token is shown once. Store it immediately in the agent's secret management (environment variable, another vault, etc.).

### Listing Keys

```sh
curl https://<ferrowarden-host>:3000/v1/admin/keys \
  -H "X-Admin-Key: $ADMIN_KEY" \
  --cacert certs/server.crt
```

Token values are never returned: only the ID, name, creation time and policy (`credentials`, `methods`, and `policy_set`).

### Using the admin UI instead

The same operations are available in the [admin web UI](admin-ui.md#managing-keys) (when `ui.bind` is set): create a key and copy its token from the page that is shown once, edit a policy with **Check policy** (what it gains and loses, which placeholders it reaches) before saving, check a sample request, and revoke. Creating, revoking and saving need a sign-in within the last 10 minutes. Events carry `via: "ui"`.

### Changing a Key's Policy

```sh
curl -X PATCH "https://<ferrowarden-host>:3000/v1/admin/keys/$KEY_ID" \
  -H "X-Admin-Key: $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"credentials": ["uptime_kuma_*", "lab_*"]}' \
  --cacert certs/server.crt
```

A field you leave out is unchanged; a field you send replaces the old value (`null` and `{}` are rejected). The change takes effect for the very next request with that key's token, and is recorded as a `key_policy_change` event with the policy before and after.

### Keys created with 0.1.0

Keys written by 0.1.0 have no policy. They keep working as keys (the token is valid) but are **deny-all**: they list no credentials and cannot forward any placeholder or method, until you set one. They show `"policy_set": false` in the key listing, the startup event carries `keys_without_policy`, and a warning is logged at startup. To restore the previous behaviour for a key:

```sh
curl -X PATCH "https://<ferrowarden-host>:3000/v1/admin/keys/$KEY_ID" \
  -H "X-Admin-Key: $ADMIN_KEY" -H "Content-Type: application/json" \
  -d '{"credentials": ["*"], "methods": ["*"]}' --cacert certs/server.crt
```

Better: narrow it. Set **both** fields: on a key without a policy, a field you do not send stays deny-all. Once patched the key is saved with an explicit policy and `policy_set` becomes `true`.

### Staged Rollout with Scoped Keys

Give every agent its own key and only the access it needs, then widen on demand. The preview endpoint shows the effect of a policy before you save it, without touching the vault values or the network.

**In the admin UI** (see [Managing keys](admin-ui.md#managing-keys)): create the key on `/ui/keys/new`, then open it and use **Check policy** (what the draft gains and loses, the placeholders it reaches) and **Check request** (would this exact call be allowed) before **Save policy**; a change that widens access asks for confirmation. The curl examples below do the same through the API.

**A read-only monitoring key.**

```sh
curl -X POST https://<ferrowarden-host>:3000/v1/admin/keys \
  -H "X-Admin-Key: $ADMIN_KEY" -H "Content-Type: application/json" \
  -d '{"name": "monitoring-agent", "credentials": ["uptime_kuma_*", "grafana_token"], "methods": ["GET", "HEAD"]}' \
  --cacert certs/server.crt
```

The agent sees only those credentials in `GET /v1/credentials`, and a `POST` or a placeholder for anything else is refused with `403` before the vault or the target is touched.

**A lab-only key.** Name your lab credentials with a common prefix and scope by it:

```sh
-d '{"name": "lab-agent", "credentials": ["lab_*"], "methods": ["*"]}'
```

A credential added to the vault later as `lab_new_switch` is reachable automatically; `prod_db` never is.

**Check with preview before saving.** Say the lab key should also read `grafana_token`:

```sh
curl -X POST "https://<ferrowarden-host>:3000/v1/admin/keys/$KEY_ID/preview" \
  -H "X-Admin-Key: $ADMIN_KEY" -H "Content-Type: application/json" \
  -d '{"credentials": ["lab_*", "grafana_token"],
       "request": {"method": "GET", "url": "https://grafana.lan/api/health",
                   "headers": {"Authorization": "Bearer {{vault:grafana_token}}"}}}' \
  --cacert certs/server.crt
```

The response lists what the key would reach (`credentials`), what the draft adds and removes against the saved policy (`gained`, `lost`) and whether that request would be allowed (`request_check`, with the same status and reason a real forward would give). Nothing is saved: run the `PATCH` when you are happy.

**Watch for probing.** A scoped key that keeps asking for credentials outside its scope, or for methods it may not use, produces `forward` failures with reason `credential_out_of_scope` or `method_not_allowed` (the SIEM examples alert on both). That is either a misconfigured agent or an agent being steered; the response is the same whether or not the credential exists, so nothing is revealed to it.

### Revoking Keys

```sh
KEY_ID="550e8400-e29b-41d4-a716-446655440000"

curl -X DELETE "https://<ferrowarden-host>:3000/v1/admin/keys/$KEY_ID" \
  -H "X-Admin-Key: $ADMIN_KEY" \
  --cacert certs/server.crt
```

Revocation is immediate. The token is removed from in-memory state and, if `FERROWARDEN_KEYS_FILE` is configured, removed from the key store file. Any subsequent request using the revoked token will receive `401 Unauthorized`. Revoking an id that does not exist returns `404 Not Found`. The key will not be re-loaded on the next container restart.

**Rotate keys when:**
- You suspect the token was exposed (logs, error messages, screen sharing)
- An agent instance is decommissioned
- Routine key rotation policy (recommended: every 90 days)
- The agent process or host was compromised

After revoking, create a new key and update the agent's configuration.

---

## ⚠ Rotating the Admin Key

> **This requires a container restart.** The admin key is read once at startup from the Docker secret file. There is no hot-reload. Plan accordingly — there will be a brief (~30 second) outage during the restart.

The admin key controls all key management and audit operations. Rotate it:

- If you suspect it was exposed (logs, screen sharing, error messages)
- After any team member with access departs
- On a routine schedule (recommended: every 90 days)
- Immediately after any security incident

### Rotation Procedure

**1. Generate a new key:**

Linux/Mac:
```sh
openssl rand -base64 48 | tr -dc 'A-Za-z0-9' | head -c 48
```

Windows (PowerShell):
```powershell
$chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'.ToCharArray()
$rng   = [Security.Cryptography.RandomNumberGenerator]::Create()
$buf   = [byte[]]::new(1)
-join (1..48 | ForEach-Object { $rng.GetBytes($buf); $chars[$buf[0] % $chars.Length] })
```

**2. Write the new key to the secret file** (the old key is still active until restart):

Linux/Mac:
```sh
echo -n "NewKeyHere" > secrets/ferrowarden_admin_key
chmod 600 secrets/ferrowarden_admin_key
```

Windows (PowerShell):
```powershell
[IO.File]::WriteAllText("secrets\ferrowarden_admin_key", "NewKeyHere", [Text.UTF8Encoding]::new($false))
```

**3. Restart the ferrowarden container** to pick up the new key:

```sh
docker compose restart ferrowarden
```

The container reads the secret file at startup. The new key takes effect immediately when the process starts. The old key stops working.

**4. Verify the new key works** before closing your terminal:

```sh
NEW_KEY="NewKeyHere"
curl -s https://<ferrowarden-host>:3000/v1/admin/status \
  -H "X-Admin-Key: $NEW_KEY" \
  --cacert certs/server.crt
# Should return: {"locked":false,"vault_backend":"native","credential_count":N,"agent_key_count":N}
```

**5. Update any scripts or automation** that use the old admin key.

### If the Key Is Compromised

Treat a compromised admin key as a full-access breach of key management:

1. Rotate the key immediately (procedure above).
2. List all agent keys — an attacker may have created new ones:
   ```sh
   curl https://<host>:3000/v1/admin/keys -H "X-Admin-Key: $NEW_KEY" --cacert certs/server.crt
   ```
3. Revoke any keys you do not recognize.
4. Review the audit log for the period the key was exposed:
   ```sh
   curl https://<host>:3000/v1/admin/audit -H "X-Admin-Key: $NEW_KEY" --cacert certs/server.crt
   ```
5. Rotate all agent keys as a precaution — an attacker may have read the key list.

---

## Debugging a container with no shell

The `ferrowarden` image is a static binary on `scratch`: there is no `sh`, `ls`, `cat` or `curl` in it, so `docker exec -it ferrowarden sh` fails with "executable file not found". That is deliberate (see [Deployment Profiles](deployment-profiles.md)). The same goes for a custom `entrypoint:` wrapper script around the binary. `bw-serve` and `vaultwarden` are unchanged: they still have a shell.

What to use instead:

```sh
# Logs: startup errors, configuration problems, security events.
docker compose logs --tail 100 ferrowarden

# Is it healthy, as Docker sees it? What did the last checks say?
docker compose ps
docker inspect -f '{{json .State.Health}}' $(docker compose ps -q ferrowarden)

# Run the health check by hand (the binary exists, so exec works for it).
docker compose exec ferrowarden /app/ferrowarden healthcheck; echo "exit $?"
docker compose exec ferrowarden /app/ferrowarden --version

# Copy a file out, e.g. the event file or the key store (hashes only).
docker compose cp ferrowarden:/data/events/events.jsonl ./events.jsonl

# What configuration does the container have? (Variables only; the admin key
# is a file path, never a value.)
docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' $(docker compose ps -q ferrowarden)
```

For anything that needs tools, start a **temporary debug container that joins the Ferrowarden container's namespaces**. It brings its own tools and leaves the hardened container untouched:

```sh
FW=$(docker compose ps -q ferrowarden)

# Network view: same IP, same ports. Test what Ferrowarden can reach, or
# check its listener from inside.
docker run --rm -it --network container:$FW nicolaka/netshoot \
  curl -sk https://vaultwarden/alive

# Process view: see its process (and /proc/<pid>/root, with ptrace).
docker run --rm -it --pid container:$FW --cap-add SYS_PTRACE busybox ps

# Read a volume without touching the container (the key store, read-only).
docker run --rm -v ferrowarden_ferrowarden-keys:/data:ro busybox ls -l /data
```

Volume names are prefixed with the Compose project name (`docker volume ls`). The debug container is `--rm`: exiting removes it. Never mount the Docker socket into it.

## Monitoring

### Structured Log Output

Ferrowarden writes one JSON security event per security-relevant action to stdout (and optionally to a rotating file and syslog; see [events.md](events.md)). A forward:

```json
{
  "@timestamp": "2026-11-21T16:09:25.075Z",
  "message": "forward succeeded",
  "event": {
    "kind": "event",
    "dataset": "ferrowarden.security",
    "action": "forward",
    "category": ["web"],
    "type": ["access"],
    "outcome": "success",
    "duration": 21662683
  },
  "source": { "ip": "172.18.0.1" },
  "http": { "request": { "method": "GET" }, "response": { "status_code": 200 } },
  "url": { "original": "https://proxmox.lan:8006/api2/json/nodes", "domain": "proxmox.lan" },
  "ferrowarden": {
    "schema_version": 1,
    "request_id": "01a1fede-9f3e-76eb-985e-c6beffe1e906",
    "key": { "id": "a35c6bd3-1a1e-48ea-8e90-ebc0718399c4", "name": "homelab-agent" },
    "credentials": ["proxmox_api_token"]
  }
}
```

Ship these logs to Loki, Elasticsearch, Wazuh or any JSON log aggregator for persistent storage. The in-memory buffer behind `GET /v1/admin/audit` is lost on restart. Every response carries an `X-Request-Id` header; the same ID is in the events for that request.

### Grafana / Loki

If you are running Loki and Grafana in your homelab:

```yaml
# In docker-compose.yml, add to ferrowarden service:
logging:
  driver: loki
  options:
    loki-url: "http://loki:3100/loki/api/v1/push"
    loki-external-labels: "service=ferrowarden"
```

Useful LogQL queries:

```logql
# All requests from a specific agent
{service="ferrowarden"} | json | agent_name="homelab-agent"

# All failed requests
{service="ferrowarden"} | json | outcome!="Success"

# Requests using a specific credential
{service="ferrowarden"} | json | line_format "{{.credential_names}}" |= "proxmox_api_token"
```

### Creating and rotating credentials for agents

Agents can ask Ferrowarden to create a credential, or to rotate the password of one in the managed collection, with a password they never see ([managed-credentials.md](managed-credentials.md)). To switch it on:

1. In Vaultwarden, make a dedicated **organisation collection** (for example `Ferrowarden managed`) and give Ferrowarden's account **Can edit** on it, with "Hide passwords" off. An owner or admin of the organisation works.
2. Set `vault.managed.collection` (`FERROWARDEN_VAULT__MANAGED__COLLECTION`) to its name or id, and restart. With file unlock, Ferrowarden refuses to start when the collection is not usable, and says why.
3. Give a key a `create` list: `curl -s -X PATCH .../v1/admin/keys/<id> -H "X-Admin-Key: $ADMIN_KEY" -H "Content-Type: application/json" -d '{"create": ["agent_*"]}'`. It is the key's own permission; it does not follow from `credentials` or `methods`. To let it also **rotate** passwords of items in the collection, give it a `rotate` list the same way (`-d '{"rotate": ["agent_*"]}'`).

Every create (kind `create`), and the start of every rotation (kind `rotate`), is held for approval: approve with `POST /v1/admin/approvals/<id>/approve` and **no body** (neither has a duration), or in the admin UI. A rotation that an agent started and never finished shows under "Rotations in progress" on the Approvals page, where you can abort it (or with `POST /v1/admin/credentials/<name>/rotate/abort`). The managed collection and whether it is usable are in `GET /v1/admin/status` (`managed_collection`) and on the UI's status page.

If it stops working later (someone made the collection "View only", turned on "Hide passwords", renamed it, or deleted it), agents get `503 managed_collection_unavailable` with a `reason`, and the log and a `vault_sync` event say so once. Nothing is written elsewhere in the meantime. Items created by agents have a `ferrowarden_created_by` field naming the key.

### Admin Status

```sh
curl https://<ferrowarden-host>:3000/v1/admin/status \
  -H "X-Admin-Key: $ADMIN_KEY" \
  --cacert certs/server.crt
```

```json
{
  "locked": false,
  "vault_backend": "native",
  "credential_count": 12,
  "agent_key_count": 2,
  "managed_collection": { "configured": false, "usable": false }
}
```

`managed_collection` says whether agents can create credentials ([managed-credentials.md](managed-credentials.md)): with a collection set it has its `name`, `id` and `usable`, or the `reason` it cannot be written to.

A `locked: true` response means all proxy requests are failing. Unlock the vault (manual mode) or check startup logs for why file-mode unlock failed.

### Prometheus metrics

Ferrowarden can expose request counts, outcomes, latency, rate limiting, authentication failures and vault state on a separate, token-protected port for Prometheus, with a ready-made Grafana dashboard. Set `metrics.bind` and a token (`FERROWARDEN_METRICS_TOKEN_FILE`), restart, and scrape `/metrics`:

```sh
curl -H "Authorization: Bearer $(cat secrets/metrics_token)" http://<ferrowarden-host>:9095/metrics
```

Useful alerts: `ferrowarden_vault_unlocked == 0` (every proxy request is failing), `time() - ferrowarden_vault_last_sync_timestamp_seconds > 600` (the vault copy is stale), `ferrowarden_agent_keys{policy_set="false"} > 0` (keys that deny everything), and a rising `ferrowarden_auth_failures_total`. To rotate the metrics token, write the new secret file, restart Ferrowarden and update the file Prometheus reads (`credentials_file`). Setup, every metric, TLS and the privacy rules are in [metrics.md](metrics.md); the dashboard is in [`examples/grafana`](../examples/grafana/README.md).

### Push notifications

Ferrowarden can push blocked requests, repeated authentication failures, vault lock and unlock failures, and (opt-in) admin changes to Gotify, ntfy or a generic webhook. Configure a sender (`[notify]`, `FERROWARDEN_NOTIFY__*`), put its token in a secret file (`FERROWARDEN_NOTIFY_*_TOKEN_FILE`), restart, then check it:

```sh
curl -X POST https://<ferrowarden-host>:3000/v1/admin/notify/test \
  -H "X-Admin-Key: $ADMIN_KEY" --cacert certs/server.crt
```

The admin UI status page shows the same test as a button, with the enabled senders, the categories and the counters (sent, failed, suppressed, dropped). Notifications are best effort and rate limited; they do not replace shipping the [events](events.md) to a persistent sink. Setup, what a notification contains, and limits are in [notifications.md](notifications.md).

---

## Troubleshooting

### Ferrowarden exits at startup with "the native vault backend ... requires the Vaultwarden API key"

The native vault backend (the only one) does not have what it needs: `FERROWARDEN_VAULT_CLIENT_ID[_FILE]` and `FERROWARDEN_VAULT_CLIENT_SECRET[_FILE]` (your Vaultwarden personal API key), and `vault.url` (`FERROWARDEN_VAULT__URL`) if Vaultwarden is not at `https://vaultwarden`. This is what a 0.1.0 configuration meets first. The bundled `docker-compose.yml` sets all of them; if you maintain your own Compose file, copy the `FERROWARDEN_VAULT_*` lines and the `bw_client_id` / `bw_client_secret` secrets from it.

### Ferrowarden exits at startup because Vaultwarden is unreachable

Ferrowarden signs in and unlocks before it serves anything, and exits if it cannot (the restart policy then tries again). In the bundled Compose file it starts as soon as the Vaultwarden container has started, so a few restarts on first boot are normal. If it keeps failing, check `docker compose logs vaultwarden`, that `vault.url` is right, and that `vault.ca_file` (`/ca-public/ca.crt`) exists in the container (run `docker compose up -d` so `internal-certs` populates `internal-ca-public`).

### "FERROWARDEN_ADMIN_KEY must be set"

Neither `FERROWARDEN_ADMIN_KEY` nor `FERROWARDEN_ADMIN_KEY_FILE` is set. In the Compose files the second is set to `/run/secrets/ferrowarden_admin_key`. Ferrowarden reads that file itself (there is no entrypoint script) and never copies the key into its environment. Check that:
1. `secrets/ferrowarden_admin_key` exists and is non-empty, and is listed under the service's `secrets:`
2. On a Linux host, UID 999 can read it. The message then says `cannot read ... as UID 999`; fix it with `sudo chown 999:999 secrets/ferrowarden_admin_key`
3. `FERROWARDEN_ADMIN_KEY_FILE` points at the mounted path (`/run/secrets/...`), not at the host path

If both variables are set, `FERROWARDEN_ADMIN_KEY` wins and the file is not read.

### "FERROWARDEN_ADMIN_KEY must be at least 32 characters"

The key is too short. Generate a new one:

**Linux/Mac:**
```sh
openssl rand -base64 48 | tr -dc 'A-Za-z0-9' | head -c 48 > secrets/ferrowarden_admin_key
```

**Windows (PowerShell):**
```powershell
$chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'.ToCharArray()
$rng   = [Security.Cryptography.RandomNumberGenerator]::Create()
$buf   = [byte[]]::new(1)
$key   = -join (1..48 | ForEach-Object { $rng.GetBytes($buf); $chars[$buf[0] % $chars.Length] })
[IO.File]::WriteAllText("secrets\ferrowarden_admin_key", $key, [Text.UTF8Encoding]::new($false))
```

### `503 Service Unavailable` on all requests

The vault is locked. Check `GET /v1/admin/status`. If `locked: true`:
- **File mode**: Check the startup logs for unlock errors. The password file may be wrong or the file may be missing. If the vault locked (the account's password or keys changed), Ferrowarden notices on the next refresh (`refresh_interval_secs`, default 5 minutes) and re-unlocks it automatically from the password file.
- **Manual mode**: The vault needs to be unlocked via `POST /v1/unlock`.

### `422 Unprocessable Entity` — unknown credential

The placeholder name does not match any login item in the vault. Options:
1. Check the credential name spelling — names are case-sensitive.
2. The credential was added recently: Ferrowarden syncs with Vaultwarden and refreshes its list every `refresh_interval_secs` (default 5 minutes). Wait, or restart / re-unlock to refresh immediately.
3. The item is not a **Login** item (secure notes, cards and identities have no password and are not listed).

### `403 Forbidden` with `approval_pending` or `approval_denied`

A credential needs a person's approval ([approvals.md](approvals.md)). `approval_pending` means nobody decided in `approval.wait_secs`: open the Approvals page (or `GET /v1/admin/approvals`), decide, and have the agent retry the same request. No prompt arrived? Check that `approval` is in `notify.events` and that a notifier is configured (Ferrowarden logs a warning once when it is not). `approval_denied` repeats for `approval.pending_ttl_secs` after a denial. `429 approval_limit_reached`: the key has too many open or recent approval requests; decide or wait for them to expire. A gateway timeout instead of these answers: the reverse proxy's read timeout is shorter than `approval.wait_secs`.

### `503` with `managed_collection_unavailable`, or `403` with `credential_create_disabled`

`POST /v1/credentials` ([managed-credentials.md](managed-credentials.md)). `credential_create_disabled`: `vault.managed.collection` is not set. `managed_collection_unavailable` carries a `reason`: `not_found` (no collection with that id or name in the account's vault: check the setting and that the account is a member of the organisation), `read_only` (the account has "View only": set **Can edit**), `hides_passwords` (turn "Hide passwords" off for the account), `ambiguous_name` (two collections have that name: set the id), `no_organization_key` (the organisation's key could not be read: the member may not be confirmed). Ferrowarden checks again on every sync, so it recovers on its own once it is fixed. `credential_create_out_of_scope`: the agent key has no `create` pattern for that name. `409 credential_exists`: the name is taken in the vault.

### `403 Forbidden` — credential not allowed for this host

The error names the credential and host. The target does not match any URI on the vault item. Add the service's URL (e.g. `https://api.example.com` or `nas.lan`) to the item's URIs in Vaultwarden; the change applies after the next refresh.

### `403 Forbidden` — target not allowed

The target resolved to a private or internal address that is not in `allowed_targets`, or it is the vault endpoint (Vaultwarden; always refused). Add the host name, IP or CIDR to `FERROWARDEN_ALLOWED_TARGETS` and restart Ferrowarden.

### `409 Conflict` — ambiguous credential

Two or more login items share that name. Rename one of them in Vaultwarden.

To list what credentials ferrowarden knows about:

```sh
curl https://<ferrowarden-host>:3000/v1/credentials \
  -H "X-Agent-Key: $AGENT_TOKEN" \
  --cacert certs/server.crt
```

### Native login fails at startup

```sh
docker compose logs ferrowarden
```

- A rejected API key (`401`/`invalid_client`): `secrets/bw_client_id` and `secrets/bw_client_secret` must be the **personal** API key of the account (web vault, Settings, Security, Keys, View API key), with no trailing newline.
- TLS errors: Vaultwarden's certificate was not issued by the CA in `internal-pki`; run `docker compose run --rm internal-certs`, restart `vaultwarden`, then restart `ferrowarden`.
- A wrong master password in `secrets/bw_master_password` is an unlock failure (`vault_unlock`, reason `unlock_failed`), not a login failure.

### Admin web UI

The optional UI is described in [admin-ui.md](admin-ui.md). Common problems:

- **"HTTPS is required" instead of the sign-in form** — the request did not arrive over HTTPS. Serve the UI behind a TLS proxy that sends `X-Forwarded-Proto: https` and list the proxy in `trusted_proxies`, enable Ferrowarden's own TLS, or (local testing only) set `ui.insecure_http`.
- **"Too many attempts"** — the per-IP (5 failures) or global (10 failures) lockout is active for 15 minutes. Behind a proxy, check `trusted_proxies`: without it every client looks like the proxy. Restarting Ferrowarden clears the lockouts.
- **"Ferrowarden could not complete the sign-in with Vaultwarden"** — the account email is unknown (Ferrowarden could not reach Vaultwarden to read it), Vaultwarden is unreachable at `vault.url`, or its certificate is not trusted. Check `docker compose exec ferrowarden ls -l /ca-public` shows `ca.crt` (run `docker compose up -d` so the `internal-certs` one-shot populates `internal-ca-public`), and set `FERROWARDEN_LOG_LEVEL=ferrowarden=debug` to see Vaultwarden's own message in the log.
- **"Request rejected"** — a CSRF or same-origin check failed, for example because the proxy rewrites `Host` without sending `X-Forwarded-Host`, or the page was open for over 15 minutes before submitting.
- **"This account requires a second factor that the admin UI cannot complete"** — the account's only second factors are WebAuthn, Duo or a recovery code. Add an authenticator app, email or YubiKey in the web vault.

### Login with a hand-written tool fails after a client upgrade

Current Bitwarden clients raise an account's PBKDF2 iterations (e.g. 100,000 → 600,000) automatically on login. Anything that derives the master password hash itself must read the count from `POST /identity/accounts/prelogin` instead of assuming it; the bundled setup and seeder scripts do.

### Internal certificate renewal

`internal-certs` (`ferrowarden internal-certs`, from the Ferrowarden image) runs on every `docker compose up` and re-issues Vaultwarden's certificate when it is within 30 days of expiry (it is valid for 825 days), when it is missing, when its names no longer match `VAULTWARDEN_CERT_SANS`, or when it was not signed by the current CA. The CA is kept. To renew without restarting the stack, run `docker compose up internal-certs` (or `docker compose run --rm internal-certs`). Vaultwarden only loads the certificate at start, so restart it after a renewal: `docker compose restart vaultwarden`. The output says what it did (`Internal CA exists`, `Vaultwarden certificate is valid`, or the reason it issued a new one). See [tls.md](tls.md#the-internal-ca-how-it-is-made).

Common causes:
- Vaultwarden is not fully started when the login is attempted — check Vaultwarden is healthy
- `bw_client_id` or `bw_client_secret` are wrong — verify them against Vaultwarden's API Key settings
- Server URL is incorrect — verify `vault.url` matches your Vaultwarden instance

---

## Backup and Recovery

### What to Back Up

1. **Vaultwarden data volume** (`vaultwarden-data`): Contains the encrypted vault. This is the critical data — lose this, lose your credentials.
2. **Secret files** (`secrets/`): The master password, client credentials, and admin key. Store these separately from the vault data (a compromised backup should not yield both the encrypted vault and the master password).
3. **Internal PKI** (`internal-pki` volume) — optional. It only secures the internal Ferrowarden → Vaultwarden hop; if lost, `internal-certs` creates a new CA and certificate on the next `docker compose up`.

### Restoring

```sh
# Stop the stack
docker compose down

# Restore vaultwarden data volume from backup
docker volume create vaultwarden-data
docker run --rm -v vaultwarden-data:/data -v /backup:/backup alpine \
  tar xzf /backup/vaultwarden-data.tar.gz -C /data

# Restore secret files
cp /backup/secrets/* ./secrets/
chmod 600 secrets/*

# Start the stack
docker compose up -d
```

Ferrowarden stores nothing about the vault between runs: it signs in with the API key from the secret files and syncs on every start, so there is nothing else to restore.
