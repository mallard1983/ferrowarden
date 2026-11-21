# Logging

## Log Format

Ferrowarden emits structured JSON to stdout on every request:

```json
{
  "timestamp": "2026-11-20T14:32:11.123Z",
  "level": "INFO",
  "fields": {
    "message": "audit",
    "agent_id": "550e8400-e29b-41d4-a716-446655440000",
    "agent_name": "homelab-agent",
    "method": "POST",
    "target_url": "https://proxmox.lan:8006/api2/json/nodes",
    "credential_names": ["proxmox_api_token"],
    "outcome": "Success",
    "response_status": 200
  }
}
```

Credential values are never logged. Only placeholder names (`credential_names`) appear in audit events.

---

## Log Level

Set `FERROWARDEN_LOG_LEVEL` in `docker-compose.yml` or the host environment:

| Level | What you see |
|---|---|
| `error` | Startup failures and fatal errors only |
| `warn` | Errors plus warnings (TLS disabled, vault locked) |
| `info` | **Default** — normal operation: requests, auth events, startup/shutdown |
| `debug` | Internal state transitions, bw serve calls, substitution details |
| `trace` | Everything including HTTP internals — very verbose |

```yaml
# docker-compose.yml
environment:
  FERROWARDEN_LOG_LEVEL: "info"
```

**Module-scoped filtering** is supported — useful when debugging a specific component:

```
FERROWARDEN_LOG_LEVEL: "ferrowarden=debug,tower_http=warn"
```

### Why log level requires a restart

Log level is read once at startup and cannot be changed at runtime. This is intentional.

Changing the log level requires a `docker compose restart ferrowarden`, which produces a container restart event visible in Docker logs and your monitoring system. An attacker who gains access to the running container cannot silently suppress or reduce logging without that restart event appearing. If you see an unexpected log level drop followed by suspicious activity, the restart timestamp bounds the window of reduced visibility.

---

## Log Persistence: Local Files

By default, Docker's `json-file` logging driver writes container stdout to disk. The production `docker-compose.yml` configures rotation limits:

```yaml
logging:
  driver: json-file
  options:
    max-size: "50m"    # rotate after 50 MB
    max-file: "10"     # keep 10 rotated files (500 MB max)
```

Log files are stored at:

```
/var/lib/docker/containers/<container-id>/<container-id>-json.log
```

You can read them directly:

```sh
docker compose logs ferrowarden
docker compose logs --follow ferrowarden         # tail
docker compose logs --since 1h ferrowarden       # last hour
```

---

## Shipping to Loki

[Grafana Loki](https://grafana.com/oss/loki/) stores logs and pairs with Grafana for dashboards and alerts.

### Option A: Loki Docker driver (recommended)

Install the Grafana Loki Docker log driver plugin once per Docker host:

```sh
docker plugin install grafana/loki-docker-driver:latest \
  --alias loki \
  --grant-all-permissions
```

Switch the ferrowarden service to use it in `docker-compose.yml`:

```yaml
# Replace the existing logging: block under ferrowarden:
logging:
  driver: loki
  options:
    loki-url: "http://<loki-host>:3100/loki/api/v1/push"
    loki-external-labels: "service=ferrowarden,env=prod"
    loki-retries: "3"
    loki-batch-size: "400"
    # Keep a local fallback in case Loki is unreachable
    loki-timeout: "10s"
```

Replace `<loki-host>` with the IP or hostname of your Loki instance. If Loki runs in the same Compose stack, use the Docker service name.

**Useful LogQL queries:**

```logql
# All audit events
{service="ferrowarden"} | json | message="audit"

# Failed requests only
{service="ferrowarden"} | json | outcome!="Success"

# Requests from a specific agent
{service="ferrowarden"} | json | agent_name="homelab-agent"

# Requests using a specific credential
{service="ferrowarden"} | json | line_format "{{.credential_names}}" |= "proxmox_api_token"

# Rate-limited requests (429 responses)
{service="ferrowarden"} | json | response_status=429

# Auth failures (unauthorized requests)
{service="ferrowarden"} | json | outcome="Unauthorized"
```

### Option B: Promtail sidecar

If you cannot install the Docker plugin (e.g., restricted host), run a [Promtail](https://grafana.com/docs/loki/latest/send-data/promtail/) container that reads Docker JSON log files and ships them to Loki.

Add to `docker-compose.yml`:

```yaml
promtail:
  image: grafana/promtail:latest
  volumes:
    # Read Docker container logs
    - /var/lib/docker/containers:/var/lib/docker/containers:ro
    - /var/run/docker.sock:/var/run/docker.sock:ro
    - ./promtail-config.yml:/etc/promtail/config.yml:ro
  networks:
    - agent-facing   # or whichever network reaches Loki
```

`promtail-config.yml` (minimal):

```yaml
server:
  http_listen_port: 9080

positions:
  filename: /tmp/positions.yaml

clients:
  - url: http://<loki-host>:3100/loki/api/v1/push

scrape_configs:
  - job_name: docker
    docker_sd_configs:
      - host: unix:///var/run/docker.sock
        refresh_interval: 5s
    relabel_configs:
      - source_labels: [__meta_docker_container_label_com_docker_compose_service]
        target_label: service
```

---

## Shipping to Wazuh

[Wazuh](https://wazuh.com/) is a SIEM that can ingest Docker JSON logs for security monitoring, alerting, and compliance.

### Reading Docker JSON log files

Install the Wazuh agent on the Docker host. Add a localfile block to `/var/ossec/etc/ossec.conf` (or the agent's config) for each container whose logs you want to monitor:

```xml
<ossec_config>
  <localfile>
    <!-- Read all Docker container logs -->
    <log_format>json</log_format>
    <location>/var/lib/docker/containers/*/*.log</location>
  </localfile>
</ossec_config>
```

Wazuh parses the Docker JSON log envelope and indexes the inner `log` field. Add a custom decoder for Ferrowarden's structured JSON:

```xml
<!-- /var/ossec/etc/decoders/ferrowarden.xml -->
<decoder name="ferrowarden">
  <prematch>\"message\":\"audit\"</prematch>
</decoder>

<decoder name="ferrowarden-fields">
  <parent>ferrowarden</parent>
  <json_fields>agent_name,method,target_url,credential_names,outcome,response_status</json_fields>
</decoder>
```

Add custom rules to alert on suspicious patterns:

```xml
<!-- /var/ossec/etc/rules/ferrowarden_rules.xml -->
<group name="ferrowarden">

  <!-- Alert on repeated auth failures (possible brute force) -->
  <rule id="100100" level="10" frequency="5" timeframe="60">
    <decoded_as>ferrowarden-fields</decoded_as>
    <field name="outcome">Unauthorized</field>
    <description>Ferrowarden: repeated authentication failures from same source</description>
    <same_field>agent_name</same_field>
  </rule>

  <!-- Alert on rate limit hits -->
  <rule id="100101" level="7">
    <decoded_as>ferrowarden-fields</decoded_as>
    <field name="response_status">429</field>
    <description>Ferrowarden: rate limit exceeded</description>
  </rule>

  <!-- Alert if vault is locked during a forwarding attempt -->
  <rule id="100102" level="8">
    <decoded_as>ferrowarden-fields</decoded_as>
    <field name="outcome">VaultLocked</field>
    <description>Ferrowarden: forward attempt while vault is locked</description>
  </rule>

</group>
```

Restart the Wazuh agent after adding decoders and rules:

```sh
systemctl restart wazuh-agent
```

### Wazuh Docker listener (alternative)

If you prefer not to read raw log files, the [Wazuh Docker listener](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/wodle-docker.html) can subscribe to Docker events directly. Enable the `docker-listener` wodle in `ossec.conf`.

---

## Log Retention Recommendations

| Destination | Retention | Notes |
|---|---|---|
| Local `json-file` | Last 500 MB (~10 files × 50 MB) | Fast access, bounded disk usage |
| Loki | 30–90 days | Query with LogQL in Grafana |
| Wazuh | 90–365 days | Required for compliance/incident response |

Audit events (every proxy request) are the most important log entries. Treat them as security-relevant data with the same retention requirements as your firewall logs.
