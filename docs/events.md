# Security Events

Ferrowarden writes one structured **security event** for every security-relevant thing it does: each forwarded request, each failed authentication, each key change, each vault lock and unlock, and its own startup and shutdown. The events have a fixed, documented schema, so a SIEM (Loki, Wazuh, Elastic, ...) can alert on them without a custom parser.

Events go to:

- **stdout** (default on), where Docker logging picks them up;
- a **rotating JSON-lines file** (off by default);
- **syslog**, RFC 5424 over UDP, TCP or TLS (off by default);
- an **in-memory ring buffer** that backs `GET /v1/admin/audit`.

Application logs (startup messages, warnings) are separate and still go through `tracing`; see [logging.md](logging.md). Event lines are told apart from application log lines by `event.dataset == "ferrowarden.security"`.

---

## Schema (`schema_version` 1)

One JSON object per line. Field names follow the [Elastic Common Schema](https://www.elastic.co/guide/en/ecs/current/index.html) (nested objects, not dotted keys). Fields that do not apply to an event are **omitted**, never `null`.

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
  "url": { "original": "http://mock-api:7777/mock-api/api/unbound", "domain": "mock-api" },
  "service": { "name": "ferrowarden", "version": "0.1.0" },
  "ferrowarden": {
    "schema_version": 1,
    "request_id": "01a1fede-aa62-717e-b0dd-10a8660ac84d",
    "key": { "id": "a35c6bd3-1a1e-48ea-8e90-ebc0718399c4", "name": "monitoring-agent" },
    "credentials": ["test_unbound"]
  }
}
```

| Field | Meaning |
|---|---|
| `@timestamp` | UTC, RFC 3339 with milliseconds and `Z` |
| `message` | Short human summary built from fixed text only |
| `event.kind` | Always `event` |
| `event.dataset` | Always `ferrowarden.security` |
| `event.action` | What happened; see [Actions](#actions) |
| `event.category`, `event.type` | ECS classification, derived from the action (and, for `forward`, whether it was denied) |
| `event.outcome` | `success`, `failure` or `unknown` |
| `event.reason` | A fixed code explaining a failure; see [Reason codes](#reason-codes). Never free text from a request |
| `event.duration` | Nanoseconds. Only on `forward` |
| `source.ip` | Client IP: the TCP peer, or the rightmost untrusted `X-Forwarded-For` entry when the peer is in `trusted_proxies` |
| `http.request.method` | Method the agent asked for (`forward`) |
| `http.response.status_code` | The HTTP status Ferrowarden returned to the caller (for a successful `forward`, the target's status). A **number** |
| `url.original` | The URL **as the agent sent it, before substitution** (placeholders, never values), truncated to 2048 characters |
| `url.domain` | Host parsed from that URL |
| `service.name`, `service.version` | `ferrowarden` and its version |
| `ferrowarden.schema_version` | Integer, see [Stability](#stability) |
| `ferrowarden.request_id` | UUID v7, also returned in the `X-Request-Id` response header |
| `ferrowarden.key` | `{ "id", "name" }` of the agent key that made the request. Never the token |
| `ferrowarden.credentials` | Placeholder labels the request used, e.g. `grafana_token` or `'Proxmox (prod)':username`. Never values |
| `ferrowarden.details` | Small, action-specific object; see below |

Every string that comes from a request (URL, method, key and field names) is truncated (URL 2048 characters, everything else 128) and only ever written through JSON serialization, so a hostile value cannot add or alter log lines.

### Request IDs

Every response, including `/health`, 404s and 429s, carries an `X-Request-Id` header. Ferrowarden always generates it itself (UUID v7, time-ordered); an `X-Request-Id` sent by the client is ignored. The same value is in `ferrowarden.request_id` of every event the request produced, which ties a SIEM alert back to one request and to a log line in your reverse proxy if it forwards the header.

---

## Actions

| `event.action` | category / type | Emitted when |
|---|---|---|
| `forward` | web / access (+ `denied` when blocked) | Every `POST /v1/forward` after the agent key was accepted: success (with the target's status) or failure with a reason |
| `credentials_list` | web / access | `GET /v1/credentials` after agent authentication. Details: `detail` (bool), `count` |
| `agent_auth` | authentication / start | **Failures only.** Reason `missing_key` or `invalid_key`. Details: `endpoint`. Success is implied by `forward` and `credentials_list` carrying `ferrowarden.key` |
| `admin_auth` | authentication / start | **Failures only**, on any admin route including `/v1/unlock`. Reason `missing_admin_key` or `invalid_admin_key`. Details: `endpoint` |
| `rate_limited` | network / denied | A request was answered `429`. **Aggregated**, see below. Details: `limiter` (`agent` or `admin`), `suppressed` |
| `request_rejected` | web / denied | An authenticated request had an invalid body or query. Reason `invalid_json` or `invalid_request`. Details: `endpoint`, `error` (the sanitized message the client received). Also: a POST to the [admin UI](admin-ui.md) refused for a missing or wrong CSRF token or a failed same-origin check (`invalid_request`, status `403`, `error` = `csrf_check_failed` or `origin_check_failed`) |
| `key_create` | iam / creation | Admin created an agent key. Details: `key_id`, `key_name`, `credentials` and `methods` (the key's policy; `["*"]` = everything) |
| `key_policy_change` | iam / change | Admin changed a key's policy with `PATCH`. Details: `key_id`, `key_name`, `before` and `after` (each `{ "credentials": [...], "methods": [...] }`). Failures (unknown id `key_not_found`, invalid body) carry the reason and `key_id` |
| `policy_preview` | iam / access | Admin previewed a draft policy (`POST /v1/admin/keys/{id}/preview`); nothing is changed. Details: `key_id`, `key_name`, `request_checked` (bool) |
| `key_revoke` | iam / deletion | Admin revoked a key. Details: `key_id`, `key_name`; an unknown id is a `404` failure with reason `key_not_found` |
| `key_list` | iam / access | Admin listed keys. Details: `count` |
| `audit_read` | web / access | Admin read `/v1/admin/audit`. Details: `limit`, `count` |
| `status_read` | web / access | Admin read `/v1/admin/status` |
| `vault_unlock` | authentication / start | Details: `mode` = `manual` (`POST /v1/unlock`), `file` (startup) or `reunlock` (automatic, after bw serve restarted). Failure reason `unlock_failed` |
| `vault_lock` | configuration / change | The vault went from unlocked to locked. Details: `cause` (`bw_serve_locked`, `forward_vault_locked`). Emitted on the transition only |
| `vault_sync` | configuration / info | Credential refresh. Always on failure (reason `sync_failed`, details `stage`); on success **only when the credential count changed** (details `credential_count`, `previous`) |
| `startup` | configuration / start | Once at start. Details: `version`, `tls_enabled`, `unlock_mode`, `enforce_credential_hosts`, `allow_private_targets`, `allowed_targets` (count), `trusted_proxies` (count), `api_prefix_set` (bool; **the prefix itself is never logged**), `agent_key_count`, `keys_without_policy` (keys from 0.1.0 that are deny-all until patched), `sinks`, `ui_enabled`, `ui_tls` (the UI listener serves TLS), `ui_insecure_http` (the sign-in form is served over plain HTTP: a security downgrade) |
| `shutdown` | configuration / end | On SIGTERM or Ctrl-C. Details: `signal`. Sinks are flushed before the process exits |
| `events_dropped` | configuration / info | The sink queue overflowed and events were not delivered to the sinks. Details: `dropped`. `event.outcome` is `unknown` |
| `ui_login` | authentication / start (+ `denied` when refused) | A sign-in to the [admin UI](admin-ui.md) with the vault master password. `event.outcome` is `success`, `failure`, or `unknown` for **step one of a two-step login** (the password was right, a second factor is pending; reason `two_factor_required`). Reasons: `invalid_credentials`, `two_factor_required`, `two_factor_failed`, `login_locked_out` (details `scope`: `ip` or `global`), `upstream_rate_limited`, `upstream_error`, `insecure_transport` (the form was refused because the connection is not HTTPS; at most one event per 30 s, `details.suppressed` counts the rest). Details: `provider` (`authenticator`, `email` or `yubikey`) on second-factor steps. Never the password, a code, a hash or anything Vaultwarden said |
| `ui_logout` | authentication / end | The operator signed out of the admin UI |
| `ui_session_expired` | authentication / end | An admin UI session that ran out (idle or absolute limit) was detected on its next request |
| `ui_two_factor_email_sent` | authentication / info | The UI asked Vaultwarden to email a second-factor code (failure: reason `upstream_rate_limited` or `upstream_error`). Never the code |

Authentication happens **before** the request body is looked at. A caller without a valid key therefore gets `401` and an `agent_auth` / `admin_auth` event, never a parse error or a `request_rejected` event.

### Rate limiting is aggregated

A flood of `429`s must not flood the event stream. For each client IP and limiter, Ferrowarden emits at most one `rate_limited` event per 60 seconds. `details.suppressed` is the number of `429`s since the previous event for that IP (0 for the first). The `429` responses themselves are not affected.

### Examples

A successful forward:

```json
{"@timestamp":"2026-11-21T16:09:25.075Z","message":"forward succeeded","event":{"kind":"event","dataset":"ferrowarden.security","action":"forward","category":["web"],"type":["access"],"outcome":"success","duration":21662683},"source":{"ip":"172.18.0.1"},"http":{"request":{"method":"GET"},"response":{"status_code":200}},"url":{"original":"http://mock-api:7777/mock-api/api/audited","domain":"mock-api"},"service":{"name":"ferrowarden","version":"0.1.0"},"ferrowarden":{"schema_version":1,"request_id":"01a1fede-9f3e-76eb-985e-c6beffe1e906","key":{"id":"a35c6bd3-1a1e-48ea-8e90-ebc0718399c4","name":"integration-test"},"credentials":["grafana_service_account"]}}
```

A failed agent authentication (the presented key is never logged, not even a prefix):

```json
{"@timestamp":"2026-11-21T16:09:24.110Z","message":"agent authentication blocked: no agent key presented","event":{"kind":"event","dataset":"ferrowarden.security","action":"agent_auth","category":["authentication"],"type":["start"],"outcome":"failure","reason":"missing_key"},"source":{"ip":"172.18.0.1"},"http":{"response":{"status_code":401}},"service":{"name":"ferrowarden","version":"0.1.0"},"ferrowarden":{"schema_version":1,"request_id":"01a1fede-9b8e-7625-aec4-0a429b12598a","details":{"endpoint":"/v1/credentials"}}}
```

`details.endpoint` is the route template (`/v1/forward`, `/v1/admin/keys/{id}`), not the raw path: it never contains the `api_prefix` or an id from the URL.

An authenticated request with a bad body:

```json
{"@timestamp":"2026-11-21T16:09:33.259Z","message":"request blocked: invalid JSON body","event":{"kind":"event","dataset":"ferrowarden.security","action":"request_rejected","category":["web"],"type":["denied"],"outcome":"failure","reason":"invalid_json"},"source":{"ip":"172.18.0.1"},"http":{"response":{"status_code":400}},"service":{"name":"ferrowarden","version":"0.1.0"},"ferrowarden":{"schema_version":1,"request_id":"01a1fede-bf4b-77a0-ae8d-a73ed5b694e9","key":{"id":"a35c6bd3-1a1e-48ea-8e90-ebc0718399c4","name":"integration-test"},"details":{"endpoint":"/v1/forward","error":"Invalid JSON: duplicate key \"k\" (line 1, column 105)"}}}
```

A key creation (id and name only; never the token or its hash):

```json
{"@timestamp":"2026-11-21T16:09:23.487Z","message":"agent key created","event":{"kind":"event","dataset":"ferrowarden.security","action":"key_create","category":["iam"],"type":["creation"],"outcome":"success"},"source":{"ip":"172.18.0.1"},"http":{"response":{"status_code":201}},"service":{"name":"ferrowarden","version":"0.1.0"},"ferrowarden":{"schema_version":1,"request_id":"01a1fede-991d-7505-b535-ee18d0f043d7","details":{"key_id":"0dcc9fd5-eba6-4290-9887-8fe440e0e17b","key_name":"lifecycle-test-key"}}}
```

The startup event (shown formatted):

```json
{
  "@timestamp": "2026-11-21T16:08:26.697Z",
  "message": "ferrowarden started",
  "event": { "kind": "event", "dataset": "ferrowarden.security", "action": "startup",
             "category": ["configuration"], "type": ["start"], "outcome": "success" },
  "service": { "name": "ferrowarden", "version": "0.1.0" },
  "ferrowarden": {
    "schema_version": 1,
    "details": {
      "version": "0.1.0", "tls_enabled": false, "unlock_mode": "file",
      "enforce_credential_hosts": true, "allow_private_targets": false,
      "allowed_targets": 1, "trusted_proxies": 0, "api_prefix_set": false,
      "agent_key_count": 3, "keys_without_policy": 0, "sinks": ["stdout", "file"]
    }
  }
}
```

---

## Reason codes

`event.reason` is always one of these. New codes are added to the list over time; existing ones are not renamed or repurposed within a schema version.

| Reason | Typical HTTP status | Meaning |
|---|---|---|
| `missing_key` | 401 | No `X-Agent-Key` header |
| `invalid_key` | 401 | Unknown agent key |
| `missing_admin_key` | 401 | No admin key presented |
| `invalid_admin_key` | 401 | Wrong admin key |
| `rate_limited` | 429 | Client exceeded the rate limit |
| `invalid_json` | 400 | Body is not valid, strict JSON |
| `invalid_request` | 400 | Valid JSON or query that is not acceptable (unknown field or parameter, bad value) |
| `target_blocked` | 403 | The outbound target policy refused the destination |
| `invalid_target_url` | 400 | URL cannot be parsed, or a placeholder tried to change scheme, host or port |
| `credential_host_not_allowed` | 403 | A credential is not bound to the target host |
| `credential_out_of_scope` | 403 | A placeholder names a credential the agent key's policy does not allow. Identical whether or not the credential exists. `ferrowarden.credentials` lists the placeholders the agent sent |
| `method_not_allowed` | 403 | The request method is not in the agent key's `methods` |
| `reprompt_required` | 403 | The vault item has master password re-prompt enabled |
| `unknown_credential` | 422 / 404 | A placeholder names a credential or field that does not exist |
| `ambiguous_credential` | 409 | More than one vault item has that name |
| `ambiguous_field` | 409 | More than one field on the item has that name |
| `malformed_placeholder` | 422 | A `{{vault:...}}` placeholder does not parse |
| `vault_locked` | 503 | The vault is locked |
| `upstream_error` | 502 | The target (or bw serve) could not be reached or failed |
| `response_too_large` | 502 | The target's response exceeded `max_response_bytes` |
| `key_not_found` | 404 | Revoke, policy change or preview of an unknown key id |
| `unlock_failed` | varies | Vault unlock failed |
| `sync_failed` | n/a | Credential refresh failed |
| `internal_error` | 500 | Unexpected internal error |
| `invalid_credentials` | 401 | Admin UI: wrong master password |
| `two_factor_required` | 303 / 422 | Admin UI: the password was right and a second factor is needed (outcome `unknown`), or the account has only second factors the UI cannot complete (outcome `failure`, `422`) |
| `two_factor_failed` | 401 | Admin UI: a second-factor code was rejected |
| `login_locked_out` | 429 | Admin UI: refused before any work because too many sign-ins failed (per IP or global) |
| `upstream_rate_limited` | 429 | Admin UI: Vaultwarden answered `429` |
| `insecure_transport` | 400 | Admin UI: the request was not over HTTPS, so the sign-in form was not served |

---

## Sinks and configuration

All settings live in the `[events]` section of `ferrowarden.toml` or in `FERROWARDEN_EVENTS__*` environment variables (two underscores after `EVENTS`). The defaults:

```toml
[events]
stdout = true               # JSON lines on stdout
buffer_size = 1000          # events kept in memory for GET /v1/admin/audit
queue_size = 10000          # events that may wait for the sink writer
file = ""                   # path of a JSON-lines file; empty = off
file_max_bytes = 52428800   # rotate at 50 MiB
file_keep = 10              # events.jsonl.1 ... events.jsonl.10
syslog = ""                 # udp://, tcp:// or tls://host:port; empty = off
syslog_facility = "auth"
syslog_ca_file = ""         # extra CA bundle for tls://
```

| TOML key | Environment variable |
|---|---|
| `stdout` | `FERROWARDEN_EVENTS__STDOUT` |
| `buffer_size` | `FERROWARDEN_EVENTS__BUFFER_SIZE` |
| `queue_size` | `FERROWARDEN_EVENTS__QUEUE_SIZE` |
| `file` | `FERROWARDEN_EVENTS__FILE` |
| `file_max_bytes` | `FERROWARDEN_EVENTS__FILE_MAX_BYTES` |
| `file_keep` | `FERROWARDEN_EVENTS__FILE_KEEP` |
| `syslog` | `FERROWARDEN_EVENTS__SYSLOG` |
| `syslog_facility` | `FERROWARDEN_EVENTS__SYSLOG_FACILITY` |
| `syslog_ca_file` | `FERROWARDEN_EVENTS__SYSLOG_CA_FILE` |

Invalid settings (an unknown URL scheme, `file_keep = 0`, an unknown facility) stop Ferrowarden at startup with an error.

### stdout

On by default. Each event is one line, written with a single `write` call, so it cannot interleave with an application log line. Docker's logging driver (and Loki/Alloy/Promtail on top of it) sees both; filter on `event.dataset == "ferrowarden.security"` to select events.

### File

Appends JSON lines to `file`, creating the directory and the file (mode `0640` on Unix) if needed. When a write would take the file past `file_max_bytes`, the file is rotated: `events.jsonl` becomes `events.jsonl.1`, `.1` becomes `.2`, and so on; the file beyond `file_keep` is deleted. Output is flushed after every batch of events.

In Docker, put the file on a volume so it survives the container. The Ferrowarden user (UID 999) must be able to write to the directory. A Wazuh agent reads it with a `localfile` entry using `<log_format>json</log_format>`.

### Syslog

RFC 5424 messages: `APP-NAME` is `ferrowarden`, `MSGID` is the event action, and the message body is the event JSON. Facility is configurable (`auth`, `authpriv`, `daemon`, `local0` to `local7`, or a number 0-23). Severity follows the event: failures are `warning` (4), successes `info` (6), `events_dropped` and `internal_error` are `err` (3).

| URL scheme | Transport |
|---|---|
| `udp://host:port` | One datagram per event |
| `tcp://host:port` | Octet-counting framing (RFC 6587): `<length> <message>` |
| `tls://host:port` | Same framing inside TLS (rustls). The server certificate is verified against the public web roots plus `syslog_ca_file`, and the host name must match |

TCP and TLS reconnect automatically with exponential backoff (1 s up to 60 s). Events produced while the collector is unreachable are not buffered for it; they still reach the other sinks and the ring buffer.

### In-memory ring buffer

The last `buffer_size` events are kept in memory and returned by `GET /v1/admin/audit` (newest first, `?limit=` up to the buffer size, default 100). It is lost on restart: use a sink for durable storage.

---

## Delivery guarantees

- **Logging never changes a response.** Emitting an event does not block and cannot fail a request.
- Events are queued to a single writer task (up to `queue_size`). If the queue is full, the event is **dropped for the sinks** (it is still in the ring buffer), a line is written to stderr immediately, and the writer later emits an `events_dropped` event with the number of events lost.
- A sink that fails (disk full, collector down) is reported with an application log warning, at most once a minute per sink, and delivery continues to the other sinks.
- On SIGTERM or Ctrl-C, Ferrowarden stops accepting connections, emits `shutdown` and flushes the sinks before it exits.

---

## What is never logged

Credential values, agent tokens and their hashes, the admin key, the vault master password (and the login hash derived from it), second-factor codes, admin UI session ids and CSRF tokens, anything Vaultwarden said in an error response, and the `api_prefix` value never appear in an event. A failed-authentication event does not contain the presented key, not even a prefix. The `scripts/check-no-secrets.sh` gate, run in CI, greps the container logs and the event file for every seeded secret and fails the build if one shows up.

Agent-supplied data that **is** logged (URLs before substitution, key names, credential labels) comes from the agent and is treated as data: truncated and JSON-escaped. An agent that puts a real secret literally into a URL has disclosed it itself.

---

## Stability

`ferrowarden.schema_version` is `1`. Within a schema version, fields are not removed or renamed and their meaning does not change; new fields, new actions and new reason codes may be added, so parse tolerantly. A breaking change bumps `schema_version`, is announced in the [changelog](../CHANGELOG.md) under **Upgrading**, and is called out in this document.

## SIEM examples

Ready-made Loki/Alloy and Wazuh configuration (Alloy pipeline, LogQL queries, ruler alerts, Wazuh decoders and rules) is in [`examples/siem/`](../examples/siem/README.md).
