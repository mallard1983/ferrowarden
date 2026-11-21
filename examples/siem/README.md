# SIEM examples for Ferrowarden security events

Working examples for the [security event stream](../../docs/events.md): Loki (with Grafana Alloy) and Wazuh. Both were tested against running instances (Loki 3.5.7 with Alloy v1.11.3, Wazuh manager 4.14.1) using real events from a Ferrowarden test stack.

```
examples/siem/
  loki/
    docker-compose.yml      Loki + Alloy (pinned images), Alloy reads the Docker socket
    alloy-config.alloy      keep only security events, add labels job/service/action/outcome
    loki-config.yaml        single-binary Loki with the ruler enabled
    rules/fake/ferrowarden.yaml   Loki ruler alert rules
    queries.md              LogQL for the common questions
  wazuh/
    ferrowarden_decoders.xml   decoder for the syslog route
    ferrowarden_rules.xml      rules 100200-100299, group "ferrowarden,"
    ossec-localfile.xml        agent localfile snippet for the file sink
```

Security events are JSON lines with `event.dataset == "ferrowarden.security"`. Ordinary application log lines (tracing JSON, no `event` object) share stdout with them; both examples keep only the events.

## Loki and Alloy

```sh
cd examples/siem/loki
docker compose up -d
```

Alloy finds the container whose Compose service name is `ferrowarden` through the Docker socket (`//var/run/docker.sock` is mounted so this also works on Docker Desktop for Windows), tails its logs, and drops every line that does not carry `event.dataset = ferrowarden.security`. Change the `regex` in `discovery.relabel` if your service has another name.

Labels, deliberately few: `job="ferrowarden"`, `service="ferrowarden"`, `container`, `action` and `outcome`. Source IPs, request ids, key names and reasons are **not** labels (each value would create a stream); they stay in the line and are read with `| json`, for example:

```logql
sum by (source_ip) (count_over_time({job="ferrowarden", action="agent_auth", outcome="failure"} | json source_ip="source.ip" [15m]))
```

The event `@timestamp` becomes the Loki timestamp. See [`loki/queries.md`](loki/queries.md) for the full set (auth failures by IP, blocked forwards by reason, rate limiting, vault lock and unlock, key changes, `events_dropped`, tracing one request).

Wiring into your stack: Ferrowarden needs no change, the default stdout sink is what Alloy reads. If Loki and Alloy run in your own Compose project, copy the `alloy` service and `alloy-config.alloy`, and point `loki.write` at your Loki. For a remote host use the file or syslog sink with an agent of your choice. Loki itself is a minimal demo (filesystem storage, no retention, no auth); harden it before production.

### Loki alerts

`loki/rules/fake/ferrowarden.yaml` (tenant `fake`, because the demo runs with `auth_enabled: false`; use your tenant id otherwise):

| Alert | Fires when | Severity |
|---|---|---|
| `FerrowardenAgentAuthBruteForce` | 5 or more failed agent authentications from one `source.ip` in 5 minutes | high |
| `FerrowardenAdminAuthFailure` | any failed admin authentication in 5 minutes | high |
| `FerrowardenForwardBlocked` | a forward blocked as `credential_host_not_allowed` or `target_blocked` (possible prompt injection or exfiltration) | medium |
| `FerrowardenVaultLocked` | the vault was locked | medium |
| `FerrowardenEventsDropped` | Ferrowarden dropped events, so the stream has a gap | high |

Set `ruler.alertmanager_url` in `loki-config.yaml` to deliver them; without an Alertmanager they are visible at `http://localhost:3100/prometheus/api/v1/rules` and `/prometheus/api/v1/alerts`.

## Wazuh

Two ways in, matching the sinks in [events.md](../../docs/events.md#sinks-and-configuration). Install the rules (and, for syslog, the decoder) on the **manager**:

```sh
cp wazuh/ferrowarden_decoders.xml /var/ossec/etc/decoders/
cp wazuh/ferrowarden_rules.xml    /var/ossec/etc/rules/
chown wazuh:wazuh /var/ossec/etc/decoders/ferrowarden_decoders.xml /var/ossec/etc/rules/ferrowarden_rules.xml
systemctl restart wazuh-manager
```

### File sink with an agent (recommended)

Set `FERROWARDEN_EVENTS__FILE=/var/log/ferrowarden/events.jsonl` (put it on a volume the agent can read) and add [`wazuh/ossec-localfile.xml`](wazuh/ossec-localfile.xml) to the agent's `ossec.conf`. Wazuh's built-in `json` decoder parses the lines, so no custom decoder is needed on this route. Do not add a child decoder of `json` for Ferrowarden: in Wazuh 4.14 it discards the fields the JSON decoder extracted. The rules identify events by the field `event.dataset`.

### Syslog sink

Add to the manager's `ossec.conf`:

```xml
<remote>
  <connection>syslog</connection>
  <port>514</port>
  <protocol>udp</protocol>   <!-- or tcp -->
  <allowed-ips>192.0.2.0/24</allowed-ips>  <!-- the Ferrowarden host -->
</remote>
```

and set `FERROWARDEN_EVENTS__SYSLOG=udp://<manager>:514` (or `tcp://`). Wazuh's syslog listener has no TLS: for `tls://` use an rsyslog or syslog-ng relay in front of the manager. Ferrowarden's lines look like `<36>1 2026-11-21T16:09:23.492Z host ferrowarden 1 agent_auth - {json}`; the `ferrowarden-syslog` decoder matches that header (with or without the `<PRI>` that remoted strips) and passes the JSON to the JSON decoder. Syslog is sent without a Wazuh agent identity, so the events are attributed to the manager host unless you route them differently.

### Rules

All rules carry group `ferrowarden` and use ids 100200 to 100299. Fields appear in alerts under `data.` (for example `data.source.ip`, `data.event.reason`, `data.ferrowarden.key.name`).

| Rule | Level | Condition |
|---|---|---|
| 100200 / 100201 | 0 | base: Ferrowarden event via file (JSON) / via syslog. No alert on their own |
| 100210 | 4 | `agent_auth` failure (`missing_key`, `invalid_key`) |
| 100211 | 10 | 5 `agent_auth` failures from the same `source.ip` within 120 s |
| 100220 | 10 | `admin_auth` failure |
| 100221 | 13 | 3 `admin_auth` failures from the same `source.ip` within 300 s |
| 100230 | 8 | `forward` failed with `credential_host_not_allowed` or `target_blocked` |
| 100231 | 8 | `forward` failed with `credential_out_of_scope` or `method_not_allowed` (the key left its policy: possible probing or prompt injection) |
| 100240 | 6 | `rate_limited` |
| 100250 | 8 | `vault_lock` |
| 100251 | 9 | `vault_unlock` failure |
| 100260 | 5 | `key_create` |
| 100261 | 5 | `key_revoke` (success) |
| 100262 | 5 | `key_policy_change` (success) |
| 100270 | 10 | `events_dropped` |
| 100280 / 100281 | 3 | `startup` / `shutdown` |

Other events (successful forwards, credential listings, other forward failure reasons, ...) match only the level-0 base rule. Add rules on `event.reason` for them if you want alerts. Note that Wazuh's `frequency` fires on the Nth event (the fifth failure, the third admin failure).

### Try the rules without an agent

```sh
docker exec -i wazuh-manager /var/ossec/bin/wazuh-logtest < events.jsonl
```

`wazuh-logtest` reads decoders and rules from `/var/ossec/etc` for each session, so no restart is needed while editing.

## Rough edges

- Wazuh `same_field` matches on `source.ip` as a dynamic field, so the alert does not carry a top-level `srcip`.
- The Loki example reads logs through the Docker API. It starts from the beginning of the container's log on first run (useful for a demo, a one-time backfill otherwise).
- `rate_limited`, `vault_lock`, failed `vault_unlock` and `events_dropped` are rare and were tested with hand-built events following the schema, not with live ones.
