# Logging

Ferrowarden produces two kinds of JSON lines on stdout:

- **Security events**: one structured line for everything security-relevant (every forward, failed authentication, key change, vault lock/unlock, startup and shutdown). They have a stable schema and are what you alert on. See [events.md](events.md).
- **Application logs**: startup messages, warnings and errors, written through `tracing`. Their level is controlled by `FERROWARDEN_LOG_LEVEL` (below).

Event lines are distinguished by `event.dataset == "ferrowarden.security"`.

## Log Format

A security event (a blocked forward):

```json
{
  "@timestamp": "2026-11-21T16:09:27.906Z",
  "message": "forward blocked: credential not bound to target host",
  "event": {
    "kind": "event",
    "dataset": "ferrowarden.security",
    "action": "forward",
    "category": ["web"],
    "type": ["access", "denied"],
    "outcome": "failure",
    "reason": "credential_host_not_allowed",
    "duration": 98918
  },
  "source": { "ip": "172.18.0.1" },
  "http": { "request": { "method": "GET" }, "response": { "status_code": 403 } },
  "url": { "original": "http://mock-api:7777/api/unbound", "domain": "mock-api" },
  "ferrowarden": {
    "schema_version": 1,
    "request_id": "01a1fede-aa62-717e-b0dd-10a8660ac84d",
    "key": { "id": "a35c6bd3-1a1e-48ea-8e90-ebc0718399c4", "name": "monitoring-agent" },
    "credentials": ["test_unbound"]
  }
}
```

An application log line:

```json
{
  "timestamp": "2026-11-21T16:08:26.961371Z",
  "level": "INFO",
  "fields": { "message": "Vault unlocked via file mode" },
  "target": "ferrowarden"
}
```

Events are recorded for failed requests as well as successful ones, including requests with a missing or invalid agent key. Credential values, tokens, the admin key and the API prefix are never logged; only placeholder names appear. The full schema, every action and the reason codes are in [events.md](events.md).

Besides stdout, events can go to a rotating file and to syslog; see [Event sinks](events.md#sinks-and-configuration).

---

## Log Level

Set `FERROWARDEN_LOG_LEVEL` in `docker-compose.yml` or the host environment:

| Level | What you see |
|---|---|
| `error` | Startup failures and fatal errors only |
| `warn` | Errors plus warnings (TLS disabled, a failing event sink, failed credential refresh) |
| `info` | **Default** — normal operation: startup/shutdown messages, vault unlock and refresh notes |
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

Log level is read once at startup and cannot be changed at runtime. This is intentional. The level applies to application logs only: **security events are always written**, whatever `FERROWARDEN_LOG_LEVEL` says, so lowering it cannot suppress the audit trail.

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

**Useful LogQL queries** (events are JSON lines; Loki's `json` parser flattens `event.dataset` to `event_dataset`):

```logql
# All security events
{service="ferrowarden"} | json | event_dataset="ferrowarden.security"

# Everything that failed
{service="ferrowarden"} | json | event_dataset="ferrowarden.security" | event_outcome="failure"

# Failed agent authentication
{service="ferrowarden"} | json | event_action="agent_auth"

# Blocked forwards, by reason
{service="ferrowarden"} | json | event_action="forward" | event_reason="credential_host_not_allowed"

# Requests by one agent key
{service="ferrowarden"} | json | ferrowarden_key_name="homelab-agent"

# Follow one request end to end
{service="ferrowarden"} | json | ferrowarden_request_id="01a1fede-aa62-717e-b0dd-10a8660ac84d"

# Rate limiting
{service="ferrowarden"} | json | event_action="rate_limited"
```

### Option B: Promtail sidecar

> Promtail has reached end of life upstream. For a new setup use Grafana Alloy with [`examples/siem/loki/alloy-config.alloy`](../examples/siem/loki/alloy-config.alloy), which also filters out application log lines. The Promtail example below is kept for existing installations.

If you cannot install the Docker plugin (e.g., restricted host), run a [Promtail](https://grafana.com/docs/loki/latest/send-data/promtail/) container that reads Docker JSON log files and ships them to Loki.

Add to `docker-compose.yml`:

```yaml
promtail:
  image: grafana/promtail:3.5.7
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

[Wazuh](https://wazuh.com/) can ingest Ferrowarden's security events in two ways, both described in [events.md](events.md#sinks-and-configuration):

- **File sink**: enable `events.file`, mount the directory on a volume, and point a Wazuh agent `localfile` entry (with `<log_format>json</log_format>`) at it. The file is rotated by Ferrowarden itself.
- **Syslog sink**: set `events.syslog` to `udp://<wazuh-manager>:514` or `tcp://<wazuh-manager>:514` to send RFC 5424 messages to a manager whose `ossec.conf` has a `<remote>` block with `<connection>syslog</connection>`. Wazuh's syslog listener has no TLS, so for `tls://` send to an rsyslog or syslog-ng relay that forwards to the manager or a local agent.

Ready-made decoders, rules and an agent `localfile` snippet are in [`examples/siem/wazuh/`](../examples/siem/wazuh/), tested with `wazuh-logtest` and a live manager (4.14.1):

- `ferrowarden_rules.xml` (ids 100200-100299, group `ferrowarden`): failed agent authentication (level 4) and five of them from one `source.ip` within two minutes (10); failed admin authentication (10) and three within five minutes (13); forwards blocked as `credential_host_not_allowed` or `target_blocked` (8, a possible prompt-injection or exfiltration attempt); rate limiting, vault lock and failed unlock, key creation and revocation, `events_dropped`, startup and shutdown.
- `ferrowarden_decoders.xml`: the syslog route (RFC 5424 with APP-NAME `ferrowarden`, JSON as the message). The file route needs no decoder: Wazuh's built-in `json` decoder parses the lines.
- `ossec-localfile.xml`: the agent `localfile` entry for the file sink.

## Loki and Wazuh examples

[`examples/siem/`](../examples/siem/README.md) holds both integrations, each verified against a running instance:

- [`loki/`](../examples/siem/loki/): a Compose file (Loki and Grafana Alloy), the Alloy pipeline that keeps only `event.dataset = ferrowarden.security` lines and labels them `job`, `service`, `action` and `outcome`, LogQL queries ([`queries.md`](../examples/siem/loki/queries.md)) and Loki ruler alert rules.
- [`wazuh/`](../examples/siem/wazuh/): the decoders, rules and `localfile` snippet above.

Alloy keeps IPs, request ids and key names out of the labels; query them with `| json`. Promtail is end-of-life upstream: the Alloy configuration replaces the Promtail one in Option B for new setups.

---

## Push notifications

Events are for your log pipeline; to be told about the important ones right away (a blocked request, repeated authentication failures, the vault locking), Ferrowarden can also push a short message to Gotify, ntfy or a generic webhook. It is fed by the same event stream, never contains more than an allow-listed handful of fields (credential names, target host, key name, source IP, request id, reason; never values, paths, queries or headers), is rate limited, and never delays a request or an event sink. See [notifications.md](notifications.md).

---

## Log Retention Recommendations

| Destination | Retention | Notes |
|---|---|---|
| Local `json-file` | Last 500 MB (~10 files × 50 MB) | Fast access, bounded disk usage |
| Loki | 30–90 days | Query with LogQL in Grafana |
| Wazuh | 90–365 days | Required for compliance/incident response |

Security events are the most important log entries. Treat them as security-relevant data with the same retention requirements as your firewall logs. The in-memory buffer behind `GET /v1/admin/audit` is lost on restart: rely on a sink for retention.
