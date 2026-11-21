# Operations

## Unlock Modes

Ferrowarden starts locked regardless of mode. The vault must be unlocked before the proxy will serve any requests.

### File Mode (`unlock_mode = "file"`)

Ferrowarden reads the master password from the path specified in `unlock_file`, sends it to `bw serve`'s `POST /unlock` endpoint, zeroes the value from memory, and then begins serving.

This all happens before the HTTP server starts accepting connections. If the unlock fails (wrong password, bw serve unreachable), Ferrowarden exits with an error. No requests are possible until the issue is corrected and the process is restarted.

**Use this mode when:**
- Running in Docker with a Docker secret or a bind-mounted password file
- You want zero-touch restarts (the container restarts and unlocks automatically)
- You accept that the master password exists on disk (protected by file permissions and Docker secret management)

**The file is read once and the value is zeroed.** The file remaining on disk after startup is not a security concern — the running process holds no reference to it after unlock.

### Manual Mode (`unlock_mode = "manual"`)

Ferrowarden starts and immediately begins listening. All credential proxy requests return `503 Service Unavailable` until an operator posts the master password to `POST /v1/unlock`.

```sh
curl -X POST http://localhost:3000/v1/unlock \
  -H "X-Admin-Key: $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"password": "your-master-password"}'
```

**Use this mode when:**
- You want explicit human confirmation per boot (audit/compliance requirement)
- You prefer the master password to never exist on disk at the deployment host
- You can tolerate a brief period after restart where the proxy is unavailable

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
2. Log in using the same API key as `bw-serve`
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

### Creating Keys

```sh
curl -X POST http://localhost:3000/v1/admin/keys \
  -H "X-Admin-Key: $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name": "descriptive-agent-name"}'
```

Name keys descriptively. The name appears in audit log entries — if something unexpected happens, the name is how you identify which agent was responsible.

The token is shown once. Store it immediately in the agent's secret management (environment variable, another vault, etc.).

### Listing Keys

```sh
curl http://localhost:3000/v1/admin/keys \
  -H "X-Admin-Key: $ADMIN_KEY"
```

Token values are never returned. Only the ID, name, and creation time.

### Revoking Keys

```sh
KEY_ID="550e8400-e29b-41d4-a716-446655440000"

curl -X DELETE "http://localhost:3000/v1/admin/keys/$KEY_ID" \
  -H "X-Admin-Key: $ADMIN_KEY"
```

Revocation is immediate. The token is removed from in-memory state and, if `FERROWARDEN_KEYS_FILE` is configured, removed from the key store file. Any subsequent request using the revoked token will receive `401 Unauthorized`. The key will not be re-loaded on the next container restart.

**Rotate keys when:**
- You suspect the token was exposed (logs, error messages, screen sharing)
- An agent instance is decommissioned
- Routine key rotation policy (recommended: every 90 days)
- The agent process or host was compromised

After revoking, create a new key and update the agent's configuration.

---

## Monitoring

### Structured Log Output

Ferrowarden emits JSON-structured logs to stdout. Every audit event includes:

```json
{
  "timestamp": "2026-11-20T14:32:11.123456789Z",
  "level": "INFO",
  "fields": {
    "message": "audit",
    "agent_id": "550e8400-e29b-41d4-a716-446655440000",
    "agent_name": "homelab-agent",
    "method": "GET",
    "target_url": "https://proxmox.lan:8006/api2/json/nodes",
    "credential_names": ["proxmox_api_token"],
    "outcome": "Success",
    "response_status": 200
  }
}
```

Ship these logs to Loki, Elasticsearch, or any JSON log aggregator for persistent storage. The in-memory audit ring buffer is lost on restart.

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

### Admin Status

```sh
curl http://localhost:3000/v1/admin/status \
  -H "X-Admin-Key: $ADMIN_KEY"
```

```json
{
  "locked": false,
  "credential_count": 12,
  "agent_key_count": 2
}
```

A `locked: true` response means all proxy requests are failing. Unlock the vault (manual mode) or check startup logs for why file-mode unlock failed.

---

## Troubleshooting

### Ferrowarden exits at startup with "bw serve unreachable"

The `bw-serve` container is not ready when Ferrowarden starts. `bw serve` takes a few seconds to initialize after `bw login`. Add a startup delay or health check:

```yaml
# In docker-compose.yml, under ferrowarden:
depends_on:
  bw-serve:
    condition: service_healthy
```

```yaml
# Under bw-serve, add:
healthcheck:
  test: ["CMD", "curl", "-f", "http://localhost:8087/status"]
  interval: 5s
  timeout: 3s
  retries: 10
  start_period: 15s
```

### "FERROWARDEN_ADMIN_KEY must be set"

The admin key environment variable is missing. If using Docker secrets, check that:
1. `secrets/ferrowarden_admin_key` file exists and is non-empty
2. The `ferrowarden-entrypoint.sh` script is reading and exporting the value

### "FERROWARDEN_ADMIN_KEY must be at least 32 characters"

The key is too short. Generate a new one:

```sh
openssl rand -base64 48 | tr -dc 'A-Za-z0-9' | head -c 48 > secrets/ferrowarden_admin_key
```

### `503 Service Unavailable` on all requests

The vault is locked. Check `GET /v1/admin/status`. If `locked: true`:
- **File mode**: Check the startup logs for unlock errors. The password file may be wrong or the file may be missing.
- **Manual mode**: The vault needs to be unlocked via `POST /v1/unlock`.

### `422 Unprocessable Entity` — unknown credential

The placeholder name does not match any credential in the vault (or the vault was unlocked before that credential was added). Options:
1. Check the credential name spelling — names are case-sensitive.
2. The credential was added after the last unlock: restart in file mode, or re-unlock in manual mode to refresh the cache.

To list what credentials ferrowarden knows about:

```sh
curl http://localhost:3000/v1/credentials \
  -H "X-Agent-Key: $AGENT_TOKEN"
```

### bw-serve login fails at startup

```sh
docker compose logs bw-serve
```

Common causes:
- Vaultwarden is not fully started when bw-serve attempts login — check Vaultwarden is healthy
- `bw_client_id` or `bw_client_secret` are wrong — verify them against Vaultwarden's API Key settings
- Server URL is incorrect — verify `BW_SERVER_URL` matches your Vaultwarden instance

---

## Backup and Recovery

### What to Back Up

1. **Vaultwarden data volume** (`vaultwarden-data`): Contains the encrypted vault. This is the critical data — lose this, lose your credentials.
2. **Secret files** (`secrets/`): The master password, client credentials, and admin key. Store these separately from the vault data (a compromised backup should not yield both the encrypted vault and the master password).

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

The bw-serve login (Vaultwarden API key) survives container restarts because the bw CLI stores its local vault cache in the `bw-data` volume. If `bw-data` is lost, bw-serve will log in again on next start (the API key credentials in the secret files are reused).
