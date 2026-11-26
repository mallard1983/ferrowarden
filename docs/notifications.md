<img src="../branding/assets/png/banners/ferrowarden-docs-header.png" width="100%" alt="">

# Push notifications

Blocked requests are the most interesting thing Ferrowarden produces. An agent that tries to send a credential to a host it is not bound to, to reach the vault, or to use a revoked key is either buggy or being steered. Ferrowarden can tell you about these events as they happen, on your phone or in your chat, through Gotify, ntfy or a generic webhook.

Notifications are **best effort** and **optional**: nothing is sent unless you configure a sender, and a slow or broken notifier never delays or fails a request. They are an alert, not an audit trail. For history, use the [event sinks](events.md#sinks-and-configuration).

## How it works

The notifier is one more consumer of the [security event stream](events.md). No request handler knows it exists.

```
handler -> EventLog::emit -> ring buffer, event writer -> stdout / file / syslog
                          \-> notifier queue (1000) -> classify -> rate limit -> render -> sender queues -> Gotify / ntfy / webhook
```

- `emit` never waits. An event the notifier cares about is handed to a bounded queue with `try_send`. If the queue is full the event is dropped and counted, and the next notification says so ("N notifications were dropped").
- One task classifies events, applies the [rate limits](#rate-limiting) and renders the message. Each sender then has its own queue and worker, its own 10 second timeout and its own retries, so a slow Gotify cannot hold up the webhook, and neither can hold up an event sink.
- Delivery failures are counted and logged (at most once a minute per sender). A notification is tried at most three times and then given up on.

## What is notified

`events` selects the categories. The default is `["blocked", "auth_failure", "vault", "system", "approval"]`; `admin` is opt-in.

| Category | Notifies about | Priority |
|---|---|---|
| `blocked` | A forward refused with reason `credential_host_not_allowed`, `target_blocked`, `credential_out_of_scope`, `method_not_allowed` or `reprompt_required` | high |
| `auth_failure` | **Repeated** failed `agent_auth`, `admin_auth` or admin UI sign-ins from one source IP: at least `auth_failure_threshold` (default 5) within `auth_failure_window_secs` (default 300). Also immediately when the admin UI locks sign-ins out (`login_locked_out`) | high |
| `vault` | The vault locked; an unlock or a sync failed; and a recovery notice when the vault unlocks again after a lock was notified | high, recovery normal |
| `admin` | A key was created, revoked or had its policy changed; a successful admin UI sign-in; an agent **created a credential** ([managed-credentials.md](managed-credentials.md): the name and the key, never the password) | normal |
| `system` | Security events were dropped (`events_dropped`); notifications were dropped; notifications paused by the hourly cap | high |
| `approval` | A request is waiting for a person to approve or deny it: **one** prompt per new approval ([approvals.md](approvals.md)). Decisions and expiry are events, not prompts | high |

A single failed key or password is not an alert; five from one address in five minutes is. Failures from the agent API, the admin API and the admin UI count together. Events that are not in this table (reads, rate limiting, startup, UI sign-outs, and a forward that failed for another reason such as an unreachable target) are never notified.

## Rate limiting

- At most **one notification per category and subject** every `min_interval_secs` (default 60). The subject is the key id for `blocked` and `admin`, the source IP for `auth_failure` (a lockout is its own subject), `vault` for the vault and `system` for system notices. Occurrences held back are counted and summarised in the next notification for that subject: *"and 14 more since 12:03 UTC"*.
- At most **`max_per_hour`** notifications in total (default 60). Beyond that Ferrowarden sends one *"notifications paused, N suppressed"* message and then stays silent until the hour rolls over.
- The recovery notice after a vault lock is not held back by the per-subject limit, so you always hear that the problem is over. It counts towards the hourly cap.
- The tables behind these limits are bounded (1024 subjects, 4096 source addresses) and expired entries are pruned, so a flood of distinct keys or addresses cannot grow memory without limit.

The counters (sent, failed, suppressed, dropped) are on the [status page of the admin UI](admin-ui.md#what-you-get).

## What a notification contains

A notification is built **only** from an allow-list of event fields:

| Field | Notes |
|---|---|
| category, action, outcome, reason code | Fixed vocabularies |
| key name and the first 8 characters of its id | Names are reduced to letters, digits and a few punctuation marks, and cut short |
| credential **names** | Placeholder labels such as `grafana_service_account`, never values; at most three are spelled out in the message |
| target **host** | `url.domain` only: never the path, the query, the port or a user name |
| source IP, request id, timestamp | |
| counts | Failures in the window, events dropped, occurrences suppressed |

Never in a notification: credential values, tokens, URLs with their path or query, header names or values, request or response bodies, the master password, the `api_prefix`, anything Vaultwarden said, or any free-text `details` of an event. This is enforced in code, not by convention: `EventFields::from_event` is the one function that reads an event for a notification, it reads exactly the fields above, and every title, message and webhook `event` object is built from its output. Tests build hostile events (URLs with userinfo, path, query, fragment and placeholders; details carrying header text, bodies and a secret-looking value) for every category and check what Gotify, ntfy and the webhook would put on the wire.

Example, as shown on the phone:

> **Ferrowarden: request blocked**
> Key "monitoring-agent" (id 11111111) tried to send grafana_service_account to api.example.com. Blocked: credential not bound to that host. Source 172.20.0.5, request 01a21046….

## Configuration

Settings live in `[notify]` of `ferrowarden.toml` or in `FERROWARDEN_NOTIFY__*` environment variables (two underscores after `NOTIFY`). Everything is off until a sender URL is set.

```toml
[notify]
gotify_url = "https://gotify.example.com"                # base URL; needs a token
ntfy_url = "https://ntfy.example.com/ferrowarden"        # full topic URL; token optional
webhook_url = "https://hooks.example.com/ferrowarden"    # generic JSON POST; token optional

events = ["blocked", "auth_failure", "vault", "system", "approval"]  # add "admin" to be told about key changes
min_interval_secs = 60          # per category and subject
max_per_hour = 60               # all notifications together
auth_failure_threshold = 5      # failures from one IP ...
auth_failure_window_secs = 300  # ... within this many seconds
allow_http = false              # permit http:// URLs for hosts other than this machine
ca_file = ""                    # extra CA certificate (PEM) for the notifier URLs
```

| TOML key | Environment variable | Default |
|---|---|---|
| `gotify_url` | `FERROWARDEN_NOTIFY__GOTIFY_URL` | off |
| `ntfy_url` | `FERROWARDEN_NOTIFY__NTFY_URL` | off |
| `webhook_url` | `FERROWARDEN_NOTIFY__WEBHOOK_URL` | off |
| `events` | `FERROWARDEN_NOTIFY__EVENTS` (comma-separated) | `blocked,auth_failure,vault,system,approval` |
| `min_interval_secs` | `FERROWARDEN_NOTIFY__MIN_INTERVAL_SECS` | 60 |
| `max_per_hour` | `FERROWARDEN_NOTIFY__MAX_PER_HOUR` | 60 |
| `auth_failure_threshold` | `FERROWARDEN_NOTIFY__AUTH_FAILURE_THRESHOLD` | 5 |
| `auth_failure_window_secs` | `FERROWARDEN_NOTIFY__AUTH_FAILURE_WINDOW_SECS` | 300 |
| `allow_http` | `FERROWARDEN_NOTIFY__ALLOW_HTTP` | false |
| `ca_file` | `FERROWARDEN_NOTIFY__CA_FILE` | none |

Everything is validated at startup, and a mistake stops Ferrowarden with a message: an unparseable URL, a URL with a user name, query or fragment (put secrets in the token variables), `http://` without `allow_http`, a Gotify URL without a token, an unknown category, a zero cap, threshold or window, an unreadable `ca_file`.

All senders share these rules:

- **`https://` is required**, except for `localhost` and loopback addresses. `allow_http = true` lifts that for other hosts (for example a notifier on a private Docker network). It is logged as a warning at startup and recorded in the `startup` event (`notify_allow_http`).
- Redirects are never followed. Requests time out after 10 seconds. A network error or a `5xx` answer is retried up to twice with backoff; a `4xx` is not retried.
- `ca_file` adds a root certificate for a notifier with a private CA, on top of the public roots. It never turns certificate verification off.
- The notifier connection ignores proxy environment variables.

### Tokens

Tokens are **never read from the config file**. They come from the environment, like the admin key, or from a file (the usual way to use a Docker secret):

| Variable | Or from a file | For |
|---|---|---|
| `FERROWARDEN_NOTIFY_GOTIFY_TOKEN` | `FERROWARDEN_NOTIFY_GOTIFY_TOKEN_FILE` | Gotify application token (required with `gotify_url`) |
| `FERROWARDEN_NOTIFY_NTFY_TOKEN` | `FERROWARDEN_NOTIFY_NTFY_TOKEN_FILE` | ntfy access token (optional) |
| `FERROWARDEN_NOTIFY_WEBHOOK_TOKEN` | `FERROWARDEN_NOTIFY_WEBHOOK_TOKEN_FILE` | Bearer token for the webhook (optional) |

Setting both a variable and its `_FILE` is a startup error, as is an empty file or a token that is not printable ASCII. Surrounding whitespace is trimmed. A token is held in memory that is wiped when it is dropped, sent only as a header marked sensitive, and never written to a log, an event, an error message or the status page. Error messages name the variable and the kind of problem, not the value.

### Gotify

Create an application in Gotify and put its token in a secret file:

```sh
echo -n "AbCdEf123456" > secrets/gotify_token
```

```yaml
# docker-compose.yml, under ferrowarden:
    secrets:
      - gotify_token
    environment:
      FERROWARDEN_NOTIFY__GOTIFY_URL: "https://gotify.example.com"
      FERROWARDEN_NOTIFY_GOTIFY_TOKEN_FILE: "/run/secrets/gotify_token"
```

Ferrowarden sends `POST {gotify_url}/message` with the header `X-Gotify-Key: <token>` and the JSON body `{"title": "...", "message": "...", "priority": 8}`: priority 8 for high, 4 for normal.

### ntfy

```yaml
    environment:
      FERROWARDEN_NOTIFY__NTFY_URL: "https://ntfy.example.com/ferrowarden"
      # Only if the topic needs authentication:
      FERROWARDEN_NOTIFY_NTFY_TOKEN_FILE: "/run/secrets/ntfy_token"
```

Ferrowarden sends `POST` to the topic URL with the message as the body and the headers `Title`, `Priority` (`high` or `default`) and `Tags` (`warning`, `lock`, `key`, `white_check_mark`), plus `Authorization: Bearer <token>` when a token is set. On the public `ntfy.sh` a topic name is the only protection: use a long random one and treat the URL as a secret, which is one more reason to run your own server.

### Generic webhook

`POST {webhook_url}` with `Content-Type: application/json` and, when a token is set, `Authorization: Bearer <token>`:

```json
{
  "source": "ferrowarden",
  "schema_version": 1,
  "category": "blocked",
  "severity": "high",
  "title": "Ferrowarden: request blocked",
  "message": "Key \"monitoring-agent\" (id 11111111) tried to send grafana_service_account to api.example.com. Blocked: credential not bound to that host. Source 172.20.0.5, request 01a21046….",
  "event": {
    "category": "blocked",
    "action": "forward",
    "outcome": "failure",
    "reason": "credential_host_not_allowed",
    "key_name": "monitoring-agent",
    "key_id": "11111111",
    "credentials": ["grafana_service_account"],
    "target_host": "api.example.com",
    "source_ip": "172.20.0.5",
    "request_id": "01a21046-9f3e-76eb-985e-c6beffe1e906",
    "timestamp": "2026-11-24T12:03:41.512Z",
    "count": 1
  },
  "suppressed": 0
}
```

| Field | Meaning |
|---|---|
| `schema_version` | `1`. Fields are not removed or renamed within a version; new ones may be added |
| `category` | `blocked`, `auth_failure`, `vault`, `admin` or `system` |
| `severity` | `high` or `normal` |
| `event` | The [allow-listed fields](#what-a-notification-contains). Fields that do not apply are omitted. `count` is how many occurrences the notification stands for (failures in the window, events dropped) |
| `suppressed` | Occurrences for the same subject held back by the rate limit since the previous notification (also written into `message`) |

Matrix, Slack, Discord and similar services can be reached through their webhook bridges or an automation tool (n8n, a small relay): point `webhook_url` at the bridge and map `title` and `message` in its template. Ferrowarden does not speak those protocols natively.

## The approval prompt

The `approval` category is on by default, because an approval nobody hears about is useless: the agent's request waits, then fails with `approval_pending`. It goes out once per new approval. Requests that wait on an approval that is already open send nothing more, and the per-subject limit and the hourly cap do not hold a prompt back (approvals are limited per agent key instead: `approval.max_requests_per_key_per_hour`, see [approvals.md](approvals.md#limits)).

**This prompt deliberately carries more than the others**, because you cannot decide without it:

| Field | Notes |
|---|---|
| key name and short id, credential **names** | As for the other categories |
| method | `GET`, `DELETE`, ... |
| target host **and port** | Shown with `:port` when the port is not the default |
| **path** | As the agent sent it, **without the query string or fragment**, cut to 200 characters, printable ASCII only. It may contain placeholders such as `{{vault:name:username}}`, which are names, never values |
| approval id, when it closes | |
| link | `<ui.public_url>/approvals/<id>` when `ui.public_url` is set; otherwise the text says to open the Approvals page of the admin UI |

Still never in it: credential values (none has been read yet), the query string, headers, the body, tokens or anything Vaultwarden said. The path is chosen by the agent: treat it as text from the agent. If a notifier crossing a network you do not control is a concern, use an `https://` notifier, or leave `approval` out of `events` and watch the Approvals page of the admin UI instead.

> **Ferrowarden: approval needed**
> Key "homelab-agent" (id 3f2b8c1e) wants to use proxmox_root for GET pve.example.com:8006/api2/json/nodes. Approve or deny: https://ferrowarden-admin.example.com/approvals/2m3x8Qk0Zr1YtV5pUa9bLw Approval 2m3x8Qk0Zr1YtV5pUa9bLw, open until 12:10 UTC.

In the webhook body the event object has an `approval` member with `id`, `kind`, `method`, `target`, `path`, `expires_at` and `link` (when set).

A request to **create a credential** ([managed-credentials.md](managed-credentials.md)) sends the same prompt, in the same category, with what the agent asked for instead of a request: the key, the credential name, the username, the URLs, the length and character set of the password, whether the new item will need approval too, and the collection it goes to. There is no method, target or path (`kind` is `create` and the `approval` member has a `create` object), and no value: none has been generated yet. The names and URLs are chosen by the agent, so they are cleaned like every other field.

> **Ferrowarden: approval needed**
> Key "homelab-claude" (id 3f2b8c1e) wants to create the credential agent_keycloak_admin with username admin for https://keycloak.example.com in the collection Ferrowarden managed: a 32-character alphanumeric password that Ferrowarden generates and the agent never sees. Approve or deny: https://ferrowarden-admin.example.com/approvals/2m3x8Qk0Zr1YtV5pUa9bLw Approval 2m3x8Qk0Zr1YtV5pUa9bLw, open until 12:10 UTC. If an approval is opened and no notifier is configured, Ferrowarden logs a warning once; the admin UI and the admin API still work.

## Notifier hosts are off-limits to agents

The notifier URLs are operator configuration and are not subject to the agent target policy, but they are **excluded from agent use**: an agent must not be able to post fake notifications or flood your phone. Every configured notifier URL's host is on an internal deny list that the outbound target policy checks:

- A request to a notifier's **host name** is refused with `403` and reason `target_blocked`, on any port, even if the name is also in `allowed_targets`.
- An **IP address** that a notifier name resolves to (or an IP-literal notifier URL) is refused on the notifier's port, in the pre-flight check and again when the connection is made. If the operator lists a different host name in `allowed_targets` that shares the notifier's address and port (as the test stack's `mock-api` and `notify-sink` aliases do), that explicit entry decides for that name.

The deny list is checked in the same two places as the vault-endpoint block: the pre-flight check of the target URL and the DNS resolver the outbound connection uses. Forwarded requests never follow redirects.

## Testing the setup

- **API:** `POST /v1/admin/notify/test` with the admin key sends one test notification to every enabled sender now, each with the 10 second timeout and no retries, and returns the result per sender:

  ```json
  { "results": [
      { "sender": "gotify", "ok": true, "status": 200 },
      { "sender": "webhook", "ok": false, "error": "could not connect" }
  ] }
  ```

  `error` is one of `timed out`, `could not connect`, `the request failed` or `the notifier answered HTTP <status>`: it never contains a URL, a path or a token. The call counts against the admin rate limit, and at most one test is accepted every 10 seconds (`429` with `Retry-After`). It emits a `notify_test` event. See [`sendTestNotification`](openapi.yaml).
- **Admin UI:** the status page has a **Notifications** section with the enabled senders (type and host only), the categories, the counters and a **Send test notification** button that shows the same per-sender result. It is a normal POST with CSRF and same-origin checks and needs no recent sign-in.

```sh
curl -X POST https://ferrowarden.example.com:3000/v1/admin/notify/test \
  -H "X-Admin-Key: $(cat secrets/ferrowarden_admin_key)"
```

## Limits

- **Best effort.** Notifications can be dropped under load (a full queue), lost when a notifier is down for longer than the three tries, or suppressed by the rate limits. They are held in memory and lost on restart. Do not rely on them as the only way to find out about an incident.
- A notification describes what Ferrowarden saw; it does not prove who was behind it.
- A compromised Ferrowarden host can silence or forge notifications. Notifications carry no signature; use the bearer token and a private network to let your receiver tell Ferrowarden from others.
- The status page counters restart from zero with the process.

## Troubleshooting

| Symptom | Check |
|---|---|
| Ferrowarden will not start: `notify.gotify_url needs a token` | Set `FERROWARDEN_NOTIFY_GOTIFY_TOKEN` or `..._FILE` |
| `must be https:// (http:// only for localhost, or with notify.allow_http = true)` | Use an `https://` URL, or `allow_http = true` for a notifier on a private network |
| `set only one of ... and ..._FILE` | Remove one of the two |
| The test button reports `could not connect` | The hostname must resolve from inside the Ferrowarden container; mind the Docker network |
| `the notifier answered HTTP 401` or `403` | Wrong or missing token |
| Nothing arrives for blocked requests | `events` must include `blocked`; the same key notifies at most once per `min_interval_secs` (the rest are summarised) and the hourly cap pauses everything for the rest of the hour |
| `a notifier is not keeping up` in the logs | That notifier is slower than the notifications arrive; its queue (100) overflowed |
