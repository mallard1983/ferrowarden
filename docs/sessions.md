# Captured sessions

Many APIs log in in two steps. You send a username and password, the service answers with a session token (a JWT, a cookie, a ticket), and every later call carries that token. Portainer (`/api/auth` returns a `jwt`), Proxmox (`/access/ticket` returns a `ticket` and a CSRF token) and Keycloak (`/token` returns an `access_token`) work like this.

Without help, the login works through Ferrowarden, because the password is substituted. But the token the service sends back reaches the agent. It is a live credential: it can end up in chat history, in a log, or in a prompt-injected request.

A **captured session** keeps the token inside Ferrowarden. The agent asks for a value of the login response to be captured under a name. Ferrowarden stores it in memory and shows the agent `[CAPTURED:name]` in its place. Later requests write `{{session:name}}` where the token belongs, and Ferrowarden substitutes it, the same way it substitutes `{{vault:name}}`.

This page describes what it does and where it stops. For the API itself see [api-reference.md](api-reference.md#post-v1forward) and the `CaptureSpec` schema in [openapi.yaml](openapi.yaml).

## Contents

- [Log in and capture](#log-in-and-capture)
- [Use a session](#use-a-session)
- [Sources](#sources)
- [How long a session lives](#how-long-a-session-lives)
- [What a session is bound to](#what-a-session-is-bound-to)
- [What is removed from the response](#what-is-removed-from-the-response)
- [Statuses and limits](#statuses-and-limits)
- [Listing and deleting](#listing-and-deleting)
- [What ends a session](#what-ends-a-session)
- [Policy](#policy)
- [Configuration](#configuration)
- [Events and metrics](#events-and-metrics)
- [Example: Portainer](#example-portainer)
- [Example: Proxmox](#example-proxmox)
- [What this does not protect against](#what-this-does-not-protect-against)

## Log in and capture

Add a `capture` member next to `request` in `POST /v1/forward`:

```json
{
  "request": {
    "method": "POST",
    "url": "https://portainer.lan:9443/api/auth",
    "body": {
      "username": "{{vault:portainer:username}}",
      "password": "{{vault:portainer}}"
    }
  },
  "capture": [
    { "from": "json:/jwt", "as": "portainer" }
  ]
}
```

| Field | Required | Description |
|---|---|---|
| `from` | yes | Where the value is in the response. See [Sources](#sources). |
| `as` | yes | The session name: 1 to 64 letters, digits, `_`, `-` or `.`. Used once per request. |
| `ttl_secs` | no | How long to keep it, from 1 to `sessions.max_ttl_secs`. Default `sessions.default_ttl_secs`. |

`capture` holds 1 to 8 entries. The member may be left out, but `null` and `[]` are errors, and so are unknown fields and duplicate keys, like everywhere else in the API. Neither `as` nor `from` may contain `{{`.

Everything in `capture` is checked before the request is sent. A malformed entry is a `400` and nothing goes to the target.

The response is the target's response, with the token replaced, plus a `captures` list that says what happened to each entry:

```json
{
  "status": 200,
  "headers": { "content-type": "application/json" },
  "body": "{\"jwt\":\"[CAPTURED:portainer]\"}",
  "body_encoding": "utf8",
  "captures": [
    { "as": "portainer", "status": "captured", "expires_at": "2026-01-01T12:30:00Z" }
  ]
}
```

A capture that fails never fails the request. The login already happened at the target, so the agent still gets the (scrubbed) response, and `captures` says why nothing was stored.

Capturing under a name the key already has **replaces** that session: new value, new origin, new expiry.

## Use a session

Write `{{session:NAME}}` anywhere a vault placeholder may go: the URL's path, query or user info, a header value, a JSON body string or key, or a raw string body.

```json
{
  "request": {
    "method": "GET",
    "url": "https://portainer.lan:9443/api/endpoints",
    "headers": { "Authorization": "Bearer {{session:portainer}}" }
  }
}
```

A session name is a plain word. Quoting is not accepted, because the agent chose the name itself. Anything that starts with `{{session:` and does not parse is a `422`, like a malformed `{{vault:`.

`{{session:...}}` and `{{vault:...}}` can be mixed in one request. A request that only uses sessions still needs the vault unlocked: the vault check comes first for every forward, and locking the vault clears every session anyway.

The checks run in this order, and none of them opens a connection:

1. The body is strict JSON, every `capture` entry is valid, every placeholder parses.
2. The key's method policy and credential scope, for the `{{vault:...}}` placeholders. Session names are **not** credential names and are not matched against the key's credential patterns.
3. The vault is unlocked, the target passes the outbound policy, every vault placeholder is valid and bound to the target.
4. Every `{{session:NAME}}` is a live session of this key, captured from the target's origin.

A session that is absent, expired or belongs to another key gets the same `422` (`unknown_session`: `Session NAME is unknown or expired; log in again`). It cannot be used to find out what other keys hold. A session captured from another origin is a `403` (`session_host_not_allowed`).

## Sources

| `from` | The value |
|---|---|
| `json:/pointer` | The string at an [RFC 6901](https://www.rfc-editor.org/rfc/rfc6901) JSON pointer in the response body. `/jwt`, `/data/ticket`, `/tokens/0`. Use `~1` for `/` and `~0` for `~` inside a key. The value must be a JSON string; a number, object or array is `not_a_string`, and so is a body that is not JSON. |
| `header:Name` | A response header. The name is case-insensitive. It must occur exactly once. |
| `cookie:name` | A cookie from the response's `Set-Cookie` headers, by name (case-sensitive, as cookie names are). All `Set-Cookie` headers are looked at. The name must occur exactly once, and only the value is taken, not the attributes. |

A value is read from the **raw** response, before scrubbing, on any status code.

## How long a session lives

The session expires at the earliest of:

- `now + ttl`, where `ttl` is the request's `ttl_secs` or `sessions.default_ttl_secs` (30 minutes);
- the `exp` of the token, when the value looks like a JWT: three base64url segments, the middle one a JSON object with a numeric `exp`. The signature is not checked, because the value is only ever used to make a lifetime shorter;
- the cookie's `Max-Age` (or `Expires`, when there is no `Max-Age`), for a `cookie:` source.

None of these can lengthen a session. A token that is valid for a day is still kept for 30 minutes unless you ask for more, and a token that expires in 10 minutes is dropped after 10. If the result is already in the past, the status is `expired` and nothing is stored.

Expired sessions are treated as absent the moment they expire. A sweep every 60 seconds removes them from memory and records a `session_expire` event.

## What a session is bound to

A session is kept under **(agent key, name)**. Another key cannot use it, list it or delete it. Each session is also bound to the **origin** of the login request: its scheme, host (lower-cased) and port, taken from the URL the agent sent, before substitution. A request to another scheme, host or port is refused with `403` (`session_host_not_allowed`) before anything is sent. A different name for the same machine, such as an IP address instead of its DNS name, is another origin.

This is the same idea as the host binding on vault credentials ([security.md](security.md#13-credential-host-binding)), with one difference: the binding is not stored in the vault but follows from where the login happened.

## What is removed from the response

Every session value of the calling key is removed from every response of that key, whether or not the request used it. The exact value, in its raw, JSON-escaped, URL-encoded and four base64 forms, is replaced with `[CAPTURED:name]`. This covers the body, the header values (including `Set-Cookie`) and error bodies. A target that echoes the token back, or an error page that quotes it, does not leak it.

A value that was **found** at a capture source but could not be stored is removed too, as `[REDACTED]`: it was `too_long`, `expired`, or the key was at its `limit_reached`.

Two cases cannot be hidden:

- `too_short`: a value shorter than 4 characters is not stored, and the scrubber does not match values that short, because it would shred ordinary text. Such a value is not a useful secret anyway.
- Nothing was found (`not_found`, `ambiguous`, `not_a_string` for a body that is not JSON): there is no value to remove, and if the response carries a token elsewhere, it is visible. Look at `captures` and fix the capture.

Scrubbing is exact-value matching, plus a structural pass for JSON bodies that escape the value in another way (`\/`, `\u0026`, `\uXXXX`). If a target returns the token in a form Ferrowarden does not know (cut in half, hex-encoded, run through a hash), it is not covered. See [what this does not protect against](#what-this-does-not-protect-against).

## Statuses and limits

| `status` | Meaning | Stored | Value in the response |
|---|---|---|---|
| `captured` | Stored. `expires_at` says until when. | yes | `[CAPTURED:name]` |
| `not_found` | Nothing at the source. | no | n/a |
| `not_a_string` | The JSON pointer points at a number, object, array or `null`, or the body is not JSON, or a header is not text. | no | n/a |
| `ambiguous` | More than one header or cookie of that name, or a JSON body that repeats a key. | no | not hidden (nothing was chosen) |
| `too_short` | Shorter than 4 characters. | no | **not hidden** |
| `too_long` | Longer than 16384 bytes. | no | `[REDACTED]` |
| `expired` | Already past its own expiry (an expired JWT, `Max-Age=0`). | no | `[REDACTED]` |
| `limit_reached` | The key holds `sessions.max_per_key` live sessions already. Replacing a name it already has does not count as new. | no | `[REDACTED]` |

## Listing and deleting

`GET /v1/sessions` lists the calling key's live sessions: name, host and expiry. Never a value.

```json
[
  { "name": "portainer", "host": "portainer.lan:9443", "expires_at": "2026-01-01T12:30:00Z" }
]
```

`DELETE /v1/sessions/{name}` forgets one: `204`, or `422` (`unknown_session`) for a name that is absent, expired or another key's. Both use the agent key and the agent rate limit, like `GET /v1/credentials`.

## What ends a session

| Cause | `session_delete` `cause` |
|---|---|
| The agent called `DELETE /v1/sessions/{name}` | `agent` |
| The key was revoked | `key_revoke` |
| The key's policy was changed with `PATCH /v1/admin/keys/{id}` (or in the admin UI) | `key_policy_change` |
| The vault locked, for any reason | `vault_lock` |
| The lifetime ran out | `session_expire` event, from the sweep |
| Ferrowarden restarted | nothing: sessions are kept in memory only and never written to disk |

A bulk removal records **one `session_delete` event per session**.

## Policy

There is no key-policy field for captured sessions in this release. The reasoning:

- Capturing only ever **removes** values from what the agent sees. A key that may call a login endpoint can already send the password and read the answer; capture hides the answer.
- A session can only be sent back to the origin the same key logged in to, under the key's method policy and the outbound target policy.
- Every policy change clears the key's sessions, so what was captured under one policy is not carried into another.

The operator can switch the feature off with `sessions.enabled = false`. Then any `capture` member or `{{session:` placeholder is a `400` (`sessions_disabled`).

The policy preview (`POST /v1/admin/keys/{id}/preview`) checks the syntax of `{{session:...}}` placeholders in the request it is given, and that sessions are switched on. It does **not** look at the session store: sessions are runtime state of an agent key, not something a policy decides, so the preview answers the same for a name nobody has captured. The preview body takes a `request` only, so it does not validate `capture` entries.

## Configuration

`[sessions]` in `ferrowarden.toml`, or `FERROWARDEN_SESSIONS__*` in the environment. The values are validated at startup.

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `true` | Accept `capture` and `{{session:...}}`. |
| `default_ttl_secs` | `1800` | Lifetime when the request gives no `ttl_secs`. At least 1. |
| `max_ttl_secs` | `86400` | The most a request may ask for. At least `default_ttl_secs`, at most 7 days (`604800`). |
| `max_per_key` | `32` | Live sessions one agent key may hold. 1 to 256. |

## Events and metrics

Events carry the session **name** and outcomes, never a value. See [events.md](events.md#captured-sessions) for the fields.

| Action | When |
|---|---|
| `session_capture` | One per `capture` entry: key, name, target host, `success` or `failure`, and on failure the status (`details.status`, reason `capture_failed`). |
| `session_use` | One per forward that used a session: key, names, host, outcome. Also on `unknown_session` and `session_host_not_allowed`. |
| `session_expire` | A session removed by the sweep. |
| `session_delete` | A session removed by the agent, a key revoke, a policy change or the vault locking, with the `cause`. |

The `forward` event also lists the session names in `ferrowarden.sessions`, apart from the vault credentials in `ferrowarden.credentials`.

None of these notifies by default. A forward refused for `session_host_not_allowed` is a `blocked` notification, like `credential_host_not_allowed`.

Metrics ([metrics.md](metrics.md)): `ferrowarden_session_captures_total{outcome}`, `ferrowarden_session_uses_total{outcome}` and the gauge `ferrowarden_sessions_active`. Session names are never labels.

## Example: Portainer

Portainer's `POST /api/auth` takes `{"username", "password"}` and answers `{"jwt": "..."}`. Store the login in Vaultwarden as an item named `portainer` with its URL, then:

```json
{
  "request": {
    "method": "POST",
    "url": "https://portainer.lan:9443/api/auth",
    "body": {
      "username": "{{vault:portainer:username}}",
      "password": "{{vault:portainer}}"
    }
  },
  "capture": [{ "from": "json:/jwt", "as": "portainer" }]
}
```

The agent gets `{"jwt":"[CAPTURED:portainer]"}` and `captures[0].status` of `captured`. Every later call uses the token without seeing it:

```json
{
  "request": {
    "method": "GET",
    "url": "https://portainer.lan:9443/api/endpoints",
    "headers": { "Authorization": "Bearer {{session:portainer}}" }
  }
}
```

Portainer's JWT has an `exp`, so the session ends when the token does, if that comes before the 30 minutes.

## Example: Proxmox

Proxmox's `POST /api2/json/access/ticket` takes form fields and answers a ticket and a CSRF token. The ticket is also set as the `PVEAuthCookie` cookie, URL-encoded. Reads need the cookie. Writes (`POST`, `PUT`, `DELETE`) need the `CSRFPreventionToken` header as well.

```json
{
  "request": {
    "method": "POST",
    "url": "https://pve.lan:8006/api2/json/access/ticket",
    "headers": { "Content-Type": "application/x-www-form-urlencoded" },
    "body": "username={{vault:proxmox:username}}&password={{vault:proxmox}}"
  },
  "capture": [
    { "from": "json:/data/ticket", "as": "pve_ticket" },
    { "from": "json:/data/CSRFPreventionToken", "as": "pve_csrf" }
  ]
}
```

Then:

```json
{
  "request": {
    "method": "POST",
    "url": "https://pve.lan:8006/api2/json/nodes/pve/qemu/100/status/stop",
    "headers": {
      "Cookie": "PVEAuthCookie={{session:pve_ticket}}",
      "CSRFPreventionToken": "{{session:pve_csrf}}"
    }
  }
}
```

Two notes:

- Capture the ticket from the JSON body rather than the cookie. The cookie is the ticket, URL-encoded, and Ferrowarden hides the URL-encoded form of every captured value, so the `Set-Cookie` header is covered. Captured the other way round (`cookie:PVEAuthCookie`), the raw ticket in the JSON body would be a different string from the one you stored, and would stay visible. You can capture both, as separate names, if you want to send the cookie value exactly as the server set it.
- Where Proxmox offers **API tokens**, `{{vault:...}}` with an API token is the simpler option: there is no login step and no expiry to manage. Use a session when a service has no token and only offers a login.

## What this does not protect against

Captured sessions narrow what the agent can see. They are not a boundary around what the agent can **do**:

- **The agent still drives the session.** While a session lives, the agent can send any request the key's policy allows to the origin it is bound to, with the token. A prompt-injected agent can call that API as the logged-in user. Keep the method policy tight, keep TTLs short, and delete a session when the work is done.
- **A target can still hand the token back in a form Ferrowarden does not know.** Exact-value scrubbing covers the raw, JSON-escaped, URL-encoded and base64 forms. A service that echoes a token cut up, hex-encoded, hashed or in an encoding of its own is not covered. Do not capture from, or send tokens to, a service that does that.
- **Other tokens in the same response stay visible.** Only the values you capture are hidden. A login response that carries a refresh token, a CSRF token or a second cookie shows them unless you capture them too.
- **`too_short` values and values that were never found** cannot be hidden (see [What is removed from the response](#what-is-removed-from-the-response)).
- **Memory only.** Sessions are kept in the memory of the Ferrowarden process. Someone who can read that memory (a debugger, a core dump) can read them. With the native vault backend the process already holds the vault's keys, which is the larger exposure ([native-vault.md](native-vault.md)). Core dumps are disabled where the platform allows.
- **No signature check.** The JWT's `exp` is read, not verified, and is only used to shorten a lifetime.
