# LogQL queries for Ferrowarden security events

These assume the labels set by `alloy-config.alloy`: `job="ferrowarden"`, `service`, `action` and `outcome`. Everything else (source IP, reason, key name, request id, ...) stays inside the JSON line and is read with `| json`. Do not turn those into labels: each distinct IP or request id would create a new stream.

In Grafana, use these in Explore with the Loki data source. Over the HTTP API:

```sh
curl -G http://localhost:3100/loki/api/v1/query_range \
  --data-urlencode 'query={job="ferrowarden", action="agent_auth"}' \
  --data-urlencode 'since=1h'
```

`| json source_ip="source.ip"` extracts one field with a nested path. `| json` alone flattens every field (`event_reason`, `source_ip`, `ferrowarden_key_name`, ...) and is convenient but slower.

## Everything

All security events, newest first (application log lines are already filtered out by Alloy):

```logql
{job="ferrowarden"}
```

Event volume by action:

```logql
sum by (action) (count_over_time({job="ferrowarden"}[1h]))
```

## Authentication failures

Failed agent authentications by source IP (brute force or a leaked or revoked key):

```logql
sum by (source_ip) (
  count_over_time({job="ferrowarden", action="agent_auth", outcome="failure"} | json source_ip="source.ip" [15m])
)
```

Missing versus invalid key (an invalid key is the more interesting one):

```logql
sum by (reason) (
  count_over_time({job="ferrowarden", action="agent_auth"} | json reason="event.reason" [1h])
)
```

Failed admin authentications (should be near zero; any is worth a look):

```logql
{job="ferrowarden", action="admin_auth", outcome="failure"} | json source_ip="source.ip", reason="event.reason", endpoint="ferrowarden.details.endpoint"
```

## Blocked forwards

Forwards that failed, by reason:

```logql
sum by (reason) (
  count_over_time({job="ferrowarden", action="forward", outcome="failure"} | json reason="event.reason" [1h])
)
```

Possible prompt injection or exfiltration: an agent asked to send a credential to a host it is not bound to, or to a blocked target. Shows which key, which URL and which credentials:

```logql
{job="ferrowarden", action="forward", outcome="failure"}
  | json reason="event.reason", key="ferrowarden.key.name", url="url.original", ip="source.ip"
  | reason=~"credential_host_not_allowed|target_blocked"
  | line_format "{{.key}} from {{.ip}} -> {{.url}} ({{.reason}})"
```

Which agent keys trigger the most blocks:

```logql
topk(5, sum by (key) (
  count_over_time({job="ferrowarden", action="forward", outcome="failure"}
    | json reason="event.reason", key="ferrowarden.key.name"
    | reason=~"credential_host_not_allowed|target_blocked" [24h])
))
```

Rejected requests (malformed bodies from an authenticated agent):

```logql
{job="ferrowarden", action="request_rejected"} | json reason="event.reason", error="ferrowarden.details.error"
```

## Rate limiting

Rate limiting is aggregated: at most one `rate_limited` event per IP and limiter per minute, with `details.suppressed` counting the swallowed 429s.

```logql
{job="ferrowarden", action="rate_limited"} | json ip="source.ip", limiter="ferrowarden.details.limiter", suppressed="ferrowarden.details.suppressed"
```

Rate-limited events per limiter:

```logql
sum by (limiter) (
  count_over_time({job="ferrowarden", action="rate_limited"} | json limiter="ferrowarden.details.limiter" [1h])
)
```

## Vault

Locks, unlocks (including failed unlocks) and sync problems:

```logql
{job="ferrowarden", action=~"vault_lock|vault_unlock|vault_sync"} | json reason="event.reason", cause="ferrowarden.details.cause", mode="ferrowarden.details.mode"
```

Failed unlocks only:

```logql
{job="ferrowarden", action="vault_unlock", outcome="failure"}
```

## Key changes

Agent key creation and revocation (audit trail of who changed access):

```logql
{job="ferrowarden", action=~"key_create|key_revoke"}
  | json key_name="ferrowarden.details.key_name", ip="source.ip"
  | line_format "{{.action}} {{.key_name}} from {{.ip}} ({{.outcome}})"
```

## Pipeline health

`events_dropped` means Ferrowarden's sink queue overflowed: events are missing from the SIEM.

```logql
{job="ferrowarden", action="events_dropped"} | json dropped="ferrowarden.details.dropped"
```

Startups and shutdowns (restarts, and a changed security posture in the startup details):

```logql
{job="ferrowarden", action=~"startup|shutdown"}
```

## Trace one request

Take the `X-Request-Id` from a response header or an alert and find every event it produced:

```logql
{job="ferrowarden"} |= "01a1fede-aa62-717e-b0dd-10a8660ac84d"
```

## Alerts

`rules/fake/ferrowarden.yaml` contains Loki ruler rules for brute-force agent authentication, any admin authentication failure, blocked forwards, vault lock, and dropped events. The ruler is enabled in `loki-config.yaml`; set `alertmanager_url` there to deliver them.
