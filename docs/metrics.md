<img src="../branding/assets/png/banners/ferrowarden-docs-header.png" width="100%" alt="">

# Prometheus metrics

Ferrowarden can expose request volume, outcomes, latency, rate limiting, authentication failures and vault state to Prometheus, and ships a Grafana dashboard for them.

Metrics are **optional and off by default**. They run on **their own listener**, protected by a **bearer token** unless you say otherwise. No metric carries a credential value, a URL, a host, an IP address, a header name or a placeholder.

## Contents

- [Turn it on](#turn-it-on)
- [Authentication and TLS](#authentication-and-tls)
- [Scrape it with Prometheus](#scrape-it-with-prometheus)
- [How the numbers are made](#how-the-numbers-are-made)
- [The metrics](#the-metrics)
- [What is never a label](#what-is-never-a-label)
- [Credential names as labels (opt-in)](#credential-names-as-labels-opt-in)
- [The Grafana dashboard](#the-grafana-dashboard)
- [Useful queries](#useful-queries)

## Turn it on

Set a bind address and give the listener a token:

```toml
# ferrowarden.toml
[metrics]
bind = "0.0.0.0:9095"
```

```yaml
# docker-compose.yml, under ferrowarden
environment:
  FERROWARDEN_METRICS__BIND: "0.0.0.0:9095"
  FERROWARDEN_METRICS_TOKEN_FILE: "/run/secrets/metrics_token"
secrets:
  - metrics_token
```

```sh
# At least 16 characters, printable ASCII without spaces.
openssl rand -base64 48 | tr -dc 'A-Za-z0-9' | head -c 40 > secrets/metrics_token
```

| Setting | Environment | Default | Meaning |
|---|---|---|---|
| `metrics.bind` | `FERROWARDEN_METRICS__BIND` | empty (off) | Address and port of the metrics listener, for example `0.0.0.0:9095`. It must not be the port of `bind_addr` or `ui.bind` |
| (none) | `FERROWARDEN_METRICS_TOKEN` or `FERROWARDEN_METRICS_TOKEN_FILE` | none | The bearer token. Setting both is an error. The file form is the one for Docker secrets; the value is read by Ferrowarden, held in wiped memory and never put in the process environment, a log or an event. There is no config-file setting for it |
| `metrics.allow_unauthenticated` | `FERROWARDEN_METRICS__ALLOW_UNAUTHENTICATED` | `false` | Serve `/metrics` with no token on a non-loopback address. See [below](#authentication-and-tls) |
| `metrics.credential_labels` | `FERROWARDEN_METRICS__CREDENTIAL_LABELS` | `false` | Add one counter labelled with vault item names. See [the warning](#credential-names-as-labels-opt-in) |

The metrics listener serves `GET /metrics` and nothing else: every other path is `404`, every other method on `/metrics` is `405`. It is never merged into the agent API or the admin UI, and `/metrics` does not exist on their ports.

## Authentication and TLS

**A bearer token is the default.** A scrape sends `Authorization: Bearer <token>`:

- No header, another scheme, or a wrong token gets `401` with `WWW-Authenticate: Bearer`.
- The token is compared in constant time (the SHA-256 digests of both sides, so even its length is not learned) and is only kept as a digest after start.
- Each failure is counted in `ferrowarden_auth_failures_total{kind="metrics"}`, and reported as a `metrics_auth` [security event](events.md) at most **once per source address per minute**, with the number of failures suppressed since the last one (`details.suppressed`), the way `rate_limited` is. The event never holds a token, the right one or the one presented.

**Running without a token** is allowed in two cases:

- The bind address is a loopback address (`127.0.0.1:9095`, `[::1]:9095`): only that machine can reach it. Ferrowarden logs that no token is set.
- You set `metrics.allow_unauthenticated = true`. Anyone who can reach the port can then read the metrics, and Ferrowarden says so in a warning at start. Use it only on a network you control end to end.

A bind address that is **not** loopback, with no token and without `allow_unauthenticated`, is **refused at start**. Setting a token and `allow_unauthenticated` together is also refused: pick one. The `startup` event reports `metrics_enabled`, `metrics_auth` (`token` or `none`), `metrics_tls` and `metrics_credential_labels`.

**TLS.** If `tls_enabled = true` the metrics listener serves TLS with the same certificate and key as the API (`tls_cert_file`, `tls_key_file`). Point Prometheus at it with `scheme: https` and `tls_config.ca_file`. If TLS is off, the listener speaks plain HTTP and **the token crosses the network in clear text**: keep that port on an internal-only network (a Docker network that is not published, a management VLAN), and do not publish it to the internet. Ferrowarden logs a warning when a token is used without TLS.

## Scrape it with Prometheus

A scrape configuration is in [`examples/prometheus/prometheus.yml`](../examples/prometheus/prometheus.yml):

```yaml
scrape_configs:
  - job_name: ferrowarden
    scheme: http                       # https when tls_enabled = true
    # tls_config:
    #   ca_file: /etc/prometheus/ferrowarden-ca.crt
    authorization:
      type: Bearer
      credentials_file: /etc/prometheus/secrets/ferrowarden_metrics_token
    static_configs:
      - targets: ["ferrowarden:9095"]
```

`credentials_file` keeps the token out of the configuration file; Prometheus re-reads it, so rotating the token is "write the new file, restart Ferrowarden".

The scrape is OpenMetrics text (`Content-Type: application/openmetrics-text; version=1.0.0; charset=utf-8`), which Prometheus 2.x and later accept. Counters appear as `<name>_total`.

## How the numbers are made

- **Counters and histograms** are fed by the [security event stream](events.md): the metrics consumer is one more reader of it, like the [push notifier](notifications.md). `EventLog::emit` hands each event to a bounded queue (4096) with `try_send`, and one task turns events into counter and histogram updates. Emitting an event therefore never waits for metrics: a full queue drops the event from the *metrics only* and counts it in `ferrowarden_metrics_events_dropped_total`. Nothing the consumer does can delay a request, a sink or a notification.
- **Gauges** are read from the live state when you scrape: vault lock state, credential count, last sync, keys, UI sessions, captured sessions, the counters other parts of Ferrowarden keep (dropped events, notifications).
- Scrapes are served one at a time. A scrape reads in-memory state only; it makes no call to Vaultwarden or any other service.
- Series are never removed. A revoked agent key **keeps its series** (a counter that vanishes and returns looks like a reset), so the number of `key` values only grows with the number of keys you have ever used. A restart resets all counters, as Prometheus expects.

## The metrics

Every name starts with `ferrowarden_`. Types are as exposed (the counter `events` is `ferrowarden_events_total`).

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `ferrowarden_build_info` | gauge, always 1 | `version`, `vault_backend` | Version and vault backend (always `native`; the label stays so dashboards keep working) |
| `ferrowarden_events_total` | counter | `action`, `outcome`, `reason` | Every [security event](events.md) by its action, outcome (`success`, `failure`, `unknown`) and reason code (empty when none) |
| `ferrowarden_forward_requests_total` | counter | `outcome`, `reason`, `key` | Forward requests. `outcome` is `success` or `failure`; `reason` is the [reason code](events.md#reason-codes) of a failure (`target_blocked`, `credential_host_not_allowed`, `unknown_credential`, `vault_locked`, `upstream_error`, ...); `key` is the agent key's **name** (empty if the request had none) |
| `ferrowarden_forward_duration_seconds` | histogram | `outcome` | Time to serve a forward, in seconds. Buckets 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30 |
| `ferrowarden_forward_response_bytes` | histogram | none | Size of the **upstream** response body of successful forwards, before scrubbing. Buckets 256 B doubling to 32 MiB. The same size is in the `forward` event as `http.response.body.bytes` |
| `ferrowarden_rate_limited_total` | counter | `limiter` | Requests answered `429`: `agent`, `admin` or `notify_test`. Counts the 429s that were folded into an event too (`suppressed`), so it lags by at most the ones not yet reported (an event per client address per minute) |
| `ferrowarden_auth_failures_total` | counter | `kind` | Failed authentications: `agent` (agent key), `admin` (admin key), `ui` (admin UI sign-in, including a lockout; a sign-in refused for not being HTTPS is not counted), `metrics` (this endpoint; every failure is counted) |
| `ferrowarden_vault_unlocked` | gauge | none | 1 when the vault is unlocked, 0 when locked |
| `ferrowarden_vault_credentials` | gauge | none | Credentials in the cache (names only, never values) |
| `ferrowarden_vault_excluded_items` | gauge | none | Items the [vault backend](native-vault.md) left out at its last rebuild, because they could not be read safely or because their collection hides passwords from the account (`vault.allow_hidden_passwords` off) |
| `ferrowarden_vault_last_sync_timestamp_seconds` | gauge | none | Unix time of the last successful sync (the sync and the listing both worked); 0 before the first. Seconds since: `time() - ferrowarden_vault_last_sync_timestamp_seconds` |
| `ferrowarden_agent_keys` | gauge | `policy_set` | Agent keys. `policy_set="false"` are keys from 0.1.0 that run **deny-all** until you set a policy |
| `ferrowarden_events_dropped_total` | counter | none | Security events dropped because the sink queue was full |
| `ferrowarden_metrics_events_dropped_total` | counter | none | Events not counted in these metrics because the metrics queue was full (see [How the numbers are made](#how-the-numbers-are-made)) |
| `ferrowarden_notifications_total` | counter | `sender`, `result` | Push notifications: `sender` is `gotify`, `ntfy` or `webhook` with `result` `sent` or `failed`; `sender="all"` carries `suppressed` and `dropped`, which the notifier keeps for all senders together |
| `ferrowarden_ui_sessions` | gauge | none | Admin UI sessions signed in now (0 when the UI is off) |
| `ferrowarden_session_captures_total` | counter | `outcome` | `capture` entries of forward requests, by the capture status: `captured`, `not_found`, `not_a_string`, `ambiguous`, `too_short`, `too_long`, `expired`, `limit_reached` ([captured sessions](sessions.md)). All eight series exist from the start |
| `ferrowarden_session_uses_total` | counter | `outcome` | Forward requests that used a `{{session:NAME}}`: `success`, `unknown_session` or `session_host_not_allowed` |
| `ferrowarden_sessions_active` | gauge | none | Captured sessions that are live now, all agent keys together. Read from memory when you scrape. A session's name, key and host are never exported |
| `ferrowarden_approval_requests_total` | counter | `outcome` | [Approvals](approvals.md) by how they ended: `granted`, `denied`, `expired` (open approvals that ran out or were cleared) and `limit_reached` (a request refused because the key was over its approval limits). All four series exist from the start |
| `ferrowarden_approvals_pending` | gauge | none | Approvals waiting for a decision now, all agent keys together. Read from memory when you scrape; ids, keys and names are never exported |
| `ferrowarden_approval_grants_active` | gauge | none | Grants that are live now, all agent keys together |
| `ferrowarden_forward_approval_total` | counter | `result` | Forward requests that needed approval, by how they ended at the gate: `granted_by_grant`, `approved_while_waiting`, `pending` (answered `approval_pending`) or `denied` |
| `ferrowarden_forward_credential_uses_total` | counter | `credential` | Only with [`metrics.credential_labels`](#credential-names-as-labels-opt-in) |

Not exported: process metrics (CPU, memory, file descriptors). `prometheus-client` does not provide them for Linux without extra dependencies, and the container runtime or node exporter already does.

## What is never a label

Label values come from two places only:

1. **Fixed sets in the code:** `action`, `outcome`, `reason` (and the capture and session-use outcomes), `limiter`, `kind`, `policy_set`, notification `sender` and `result`, the version and the vault backend. A value from a request that is not in the set (for example an unknown limiter name) becomes `other`.
2. **Names an administrator chose:** the agent key name in `key` (set when the key was created) and, if you opt in, vault item names.

Never a label, and never anywhere in the output: URLs, paths, query strings, hosts, IP addresses, header names or values, placeholders (`{{vault:...}}`), request or response bodies, credential values, tokens, the `api_prefix`. The code has no field to hold them: the label types are built from `&'static str` enums plus the two names above, and the consumer ignores the free-form parts of an event. Tests feed it hostile events with every one of those and check that none reaches a scrape; the integration suite makes real requests with recognisable paths, queries, headers and secrets and checks a scrape of both instances, and the [secret gate](cicd.md) scans a scrape after every CI run.

The `key` label is capped for safety at 1000 distinct names; any more count under `key="_other"`. Key names are escaped by the OpenMetrics encoder (quotes, backslashes and newlines cannot break a line).

## Credential names as labels (opt-in)

By default **no credential name appears in the metrics**. A name such as `proxmox_api_token` tells whoever can read the metrics what the vault holds, and one label per credential adds a series per credential.

If you need per-credential usage, set `metrics.credential_labels = true`. It adds:

```
ferrowarden_forward_credential_uses_total{credential="grafana_service_account"} 12
```

- It counts **successful** forwards only, once per request per item name, using the item name (the selector, for example `:username`, is dropped). Names in refused requests are text the agent typed, and are not counted.
- At most **500** distinct names. Beyond that, further names count under `credential="_other"` (a vault item really named `_other` merges into it).
- **Warning:** enabling this means anyone who can scrape Ferrowarden, or read your Prometheus and Grafana, can list the names of the credentials agents use. Treat the metrics endpoint, Prometheus and every dashboard viewer as part of the audience for your vault's item names. The startup event records `metrics_credential_labels`, and Ferrowarden logs a warning.

## The Grafana dashboard

[`examples/grafana/ferrowarden-dashboard.json`](../examples/grafana/ferrowarden-dashboard.json) has panels for:

- request rate by outcome, and blocked requests by reason
- forward latency (p50 and p95) and response size
- authentication failures and rate limiting
- vault state, credential count and time since the last sync, and agent keys without a policy
- notifications and dropped events

It uses a Prometheus **datasource variable** (no fixed UID), so it imports into any Grafana. See [`examples/grafana/README.md`](../examples/grafana/README.md) to import it, including provisioning. The dashboard and its queries are tested against real instances (every panel query returns data) in the way described there.

## Useful queries

```promql
# Requests per second by outcome
sum by (outcome) (rate(ferrowarden_forward_requests_total[5m]))

# Blocked requests by reason (anything that failed on policy)
sum by (reason) (rate(ferrowarden_forward_requests_total{outcome="failure"}[5m]))

# p95 forward latency
histogram_quantile(0.95, sum by (le) (rate(ferrowarden_forward_duration_seconds_bucket[5m])))

# The vault has not synced for ten minutes (alert)
time() - ferrowarden_vault_last_sync_timestamp_seconds > 600

# The vault is locked (alert)
ferrowarden_vault_unlocked == 0

# Keys that deny everything because no policy was ever set (alert)
ferrowarden_agent_keys{policy_set="false"} > 0
```

Metrics complement the [event sinks](events.md#sinks-and-configuration) and [push notifications](notifications.md); they are counts and trends, not an audit trail. An event that did not fit in a queue is counted as dropped in the sinks and in the metrics, not recovered.
