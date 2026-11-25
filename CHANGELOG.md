# Changelog

All notable changes to this project are documented here. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows [Semantic Versioning](https://semver.org/). While the version is 0.x, minor releases may contain breaking changes; they are called out under **Upgrading**.

## [Unreleased]

> This release widens credential coverage with field placeholders, makes agent keys default-deny and scoped, adds an optional admin web UI, and records security events in a stable format for your SIEM. Review the upgrade notes and security changes before deployment: keys created with 0.1.0 become deny-all until you set a policy.

### Added

- **MCP server** (#11): `ferrowarden-mcp`, a second binary in the crate that exposes Ferrowarden to MCP-capable agent harnesses over stdio. Two tools, `list_credentials` and `http_request`, with strict input schemas (checked in a test against `docs/openapi.yaml`) and tool descriptions that carry the key rules. It is a thin client of a running Ferrowarden holding only an agent key: configured with `FERROWARDEN_URL` (including any `api_prefix`), `FERROWARDEN_AGENT_KEY` or `FERROWARDEN_AGENT_KEY_FILE`, and optionally `FERROWARDEN_CA_FILE`, `FERROWARDEN_MCP_TIMEOUT_SECS`, `FERROWARDEN_MCP_ALLOW_HTTP` and `FERROWARDEN_MCP_LOG`. HTTPS is required except for loopback hosts. The key and the URL path are never logged or shown in tool output; stdout carries only protocol messages. Errors from Ferrowarden itself become tool errors with guidance per status, distinct from a target's own 4xx and 5xx. Uses the official `rmcp` SDK. See `docs/mcp.md`, with configuration for Claude Code, Claude Desktop and generic stdio clients.
- **Release workflow** (`.github/workflows/release.yml`): for a `v*` tag, builds `ferrowarden` and `ferrowarden-mcp` for Linux (x86_64, aarch64), macOS (Apple silicon) and Windows (x86_64), writes `SHA256SUMS`, attests build provenance and attaches the files to a draft release, which is never published automatically. A manual run is a dry run that cannot upload.
- **OpenAPI specification** (#10): `docs/openapi.yaml`, a hand-written OpenAPI 3.1 description of every route (operations, parameters, request bodies, each response status with its schema, the placeholder grammar, scrubbing and its limits, examples, and the security event schema). Each operation has a stable `operationId` (`listCredentials`, `forwardRequest`, `createKey`, ...). It is checked in CI: Redocly lint, a test that the routes the server serves and the spec describe are the same set, and integration tests that validate real responses against the response schemas.
- **`GET /v1/openapi.json`** serves the specification to holders of a key: an agent key gets the agent and meta operations, the admin key gets the full document, and `servers[0].url` is set to the configured `api_prefix`. No key gets `401`. It counts against the agent rate limit. Event `openapi_read` (details `variant`: `agent` or `admin`). The Docker image now copies `docs/openapi.yaml` into the build, because the file is embedded in the binary.
- `docs/integrations/n8n.md`: using Ferrowarden from the n8n HTTP Request node.
- **Ferrowarden brand identity**: logo and brand kit in `branding/` (assets, tokens, voice and messaging guide), README and docs headers, release-notes header, and a redesigned admin web UI using the same palette. README, docs, CLI text and release notes now follow the kit's claims rules: credential protections are described as design properties with their limits, and Ferrowarden is described as a sidecar to Vaultwarden, not affiliated with Vaultwarden or Bitwarden.
- **Admin web UI design**: the brand palette, the self-hosted Inter font (OFL, served from the UI's own origin), the brand mark and lockup, favicons, and light and dark themes that follow the system setting. The layout is responsive: the keys and audit tables become cards on narrow screens, and the filters, key editor and navigation fit phone widths. The UI's Content-Security-Policy adds `font-src 'self'` and is otherwise unchanged (no scripts, no inline styles).
- **Command-line help**: `ferrowarden --help` / `-h` prints usage and where configuration comes from, `--version` / `-V` prints the version, and any other argument exits with status 2 and the usage on stderr. Running with no arguments starts the proxy as before.
- **Admin web UI, phase 2** (#24): `/ui/keys` (list, with a deny-all badge for keys without a policy), `/ui/keys/new` (create; the token is rendered once in the POST response, never in a URL, redirect, event or log), `/ui/keys/{id}` (policy editor with **Check policy** showing gained and lost credentials, placeholders and `bound_to` hosts, a request check, and a confirmation step for changes that widen access), `/ui/keys/{id}/revoke` and `/ui/audit` (filters, strict query, per-event JSON). A 10-minute "sudo" window requires a recent sign-in for create, revoke and save, enforced on both GET and POST, with a strictly validated `next` redirect carried server-side through two-step login. Key operations now live in one shared service (`api::key_service`) used by both the JSON API and the UI. Events from either path carry `details.via` (`api` or `ui`). The create form is single-use, so reloading or re-sending it cannot create a second key. A save or create made after the sign-in window keeps your changes: they are held server-side (15 minutes, tied to your IP) and restored, unsaved, after you sign in again. No JavaScript. See `docs/admin-ui.md`.
- **Admin web UI, phase 1** (#24): an optional operator UI on its own listener (`ui.bind`, off by default; never merged into the API router). Sign in with the Vaultwarden master password, verified by Vaultwarden itself (login hash derived with PBKDF2 or Argon2id, server KDF parameters bounded), including two-step login (authenticator app, email code, YubiKey OTP). Server-side sessions (idle 15 min, 8 h absolute, 8 at most, SHA-256 of the id stored), `__Host-` `HttpOnly` `Secure` `SameSite=Strict` cookies, CSRF token plus same-origin check on every POST, per-IP and global sign-in lockouts checked before any key derivation, strict form parsing, no scripts, strict security headers, and a read-only status page. The sign-in form is only served over HTTPS (own TLS, or a `trusted_proxies` proxy sending `X-Forwarded-Proto: https`); `ui.insecure_http` opts out for local testing. No Vaultwarden token or key is ever read or kept. See `docs/admin-ui.md` and `docs/security.md` §16.
- Events `ui_login`, `ui_logout`, `ui_session_expired`, `ui_two_factor_email_sent`; reasons `invalid_credentials`, `two_factor_required`, `two_factor_failed`, `login_locked_out`, `upstream_rate_limited`, `insecure_transport`; the `startup` event reports `ui_enabled`, `ui_tls`, `ui_insecure_http`. Wazuh rules 100290 to 100293 and a LogQL query in the SIEM examples.
- **`internal-ca-public` volume**: the `internal-certs` one-shot now also copies `ca.crt` (never the key) into it, and `ferrowarden` mounts it read-only at `/ca-public` to verify Vaultwarden's certificate for the UI sign-in. `docker compose up` re-runs the one-shot, so existing deployments get it automatically.

- **Per-agent credential scoping and method policy** (#9): every agent key carries a policy, `credentials` (name patterns, `*` wildcard, whole-name, case-sensitive) and `methods` (`GET HEAD POST PUT PATCH DELETE OPTIONS`). `GET /v1/credentials` lists only matching credentials. `/v1/forward` refuses a disallowed method or an out-of-scope placeholder with `403` before any vault access, target check or connection. An out-of-scope name gives the same response and event whether or not the credential exists, so scoping cannot be used to probe the vault.
- **`PATCH /v1/admin/keys/{id}`** changes a key's policy (absent field = unchanged, `null` and `{}` rejected, takes effect immediately).
- **`POST /v1/admin/keys/{id}/preview`**: shows what a draft policy would allow (credentials reached, access gained and lost against the saved policy, and optionally whether a given request would be allowed), without saving, reading values or sending anything.
- Events `key_policy_change` and `policy_preview`; reasons `credential_out_of_scope` and `method_not_allowed`; `key_create` records the policy; the `startup` event reports `keys_without_policy`. SIEM examples updated.
- **Field placeholders** (#8): `{{vault:NAME:username}}`, `:totp`, `:notes` and `:field:FIELD` for custom fields (text, hidden, boolean, and linked to the username or password). **Secure notes** are now supported.
- **Any item or field name**: names with spaces, colons or other characters are referenced with single quotes, e.g. `{{vault:'Proxmox (prod)':field:'api secret'}}`.
- `GET /v1/credentials?detail=true` returns ready-made placeholders for every available value, unavailable values with the reason, and each credential's `bound_to` hosts.
- Reserved custom field `ferrowarden_uris` sets an item's host bindings (needed for secure notes; overrides a login's URIs).

- **Security event stream** (#22): one structured event, with a stable documented schema (`ferrowarden.schema_version` 1, ECS-style field names), for every security-relevant action: forwards (success and each block reason), failed agent and admin authentication, credential listings, key create/revoke/list, audit and status reads, vault unlock/lock/sync, rate limiting (aggregated), rejected requests, startup, shutdown and dropped events. See `docs/events.md`.
- **Event sinks**, configurable under `[events]` / `FERROWARDEN_EVENTS__*` and combinable: stdout JSON lines (default), a rotating JSON-lines file, and RFC 5424 syslog over UDP, TCP or TLS. Delivery is queued and never blocks or fails a request; overflow is counted and reported as an `events_dropped` event.
- **Request IDs**: every response carries an `X-Request-Id` header (UUID v7, always generated by Ferrowarden), also present in every event for that request. The client IP is now computed once for all consumers.
- `GET /v1/admin/audit` accepts `?limit=` (1 to the buffer size; strict query parsing); the buffer size is configurable (`events.buffer_size`).
- `scripts/check-no-secrets.sh`, run in CI after the integration tests: fails if any seeded secret value, agent key, admin key or master password appears in the container logs or the event file.

### Changed

- **Licence: Ferrowarden is now source-available under the Functional Source License 1.1, ALv2 Future License (FSL-1.1-ALv2).** Use, modification and redistribution are allowed for any purpose except offering it, or something substantially similar, as a commercial product or service (a "Competing Use"); self-hosting for internal use is explicitly permitted. Each release becomes Apache-2.0 two years after publication. v0.1.0 and earlier remain MIT-licensed. Contributions now require the [Contributor License Agreement](CLA.md).

- **The startup log line now reads `Ferrowarden <version> starting — the credential boundary for AI agents`** (with a `version` field) instead of `Ferrowarden starting`. Update any log alert that matched the old text exactly; the `startup` security event is unchanged.
- Revoking (or patching, or previewing) an unknown agent key id returns `404 Not Found` instead of `401`, as documented.
- Malformed placeholders (anything starting with `{{vault:` that does not parse) are rejected with `422` instead of being forwarded as literal text.
- `GET /v1/credentials` also lists secure notes, and names that previously could not be referenced.
- **Strict JSON input** (#23): request bodies and the key file are rejected if they contain duplicate object keys (at any depth), unknown fields, trailing data or nesting deeper than 64 levels; header names that differ only by case are treated as duplicates; `GET /v1/credentials` rejects unknown and repeated query parameters. Error messages name the problem but never echo values from the body.

### Upgrading

- **Admin UI (optional):** nothing changes unless you set `FERROWARDEN_UI__BIND`. The Docker image now needs the `templates/` directory when built from source (the `Dockerfile` copies it). Run `docker compose up -d --build` so `internal-certs` fills the new `internal-ca-public` volume. Keep the UI port off agent-reachable networks and serve it over HTTPS (see `docs/admin-ui.md`).
- **Agent keys now require an explicit policy, and keys created with 0.1.0 become deny-all.** `POST /v1/admin/keys` now requires `credentials` and `methods` (`["*"]` for everything, `[]` for nothing; omitting them or sending `null` is a `400`). Keys already in your key file have no policy: after the upgrade they authenticate but can list no credentials and forward nothing until you set one. They are shown with `"policy_set": false` in `GET /v1/admin/keys`, counted in the `startup` event (`keys_without_policy`), and a warning is logged at startup. To restore the previous behaviour for a key, run:

  ```sh
  curl -X PATCH https://<host>:3000/v1/admin/keys/<key-id> \
    -H "X-Admin-Key: $ADMIN_KEY" -H "Content-Type: application/json" \
    -d '{"credentials":["*"],"methods":["*"]}'
  ```

  (set both fields; a field you leave out stays deny-all on such a key). Better, scope each key to what its agent needs. Scripts that create keys must send a policy. A key file with `null` policy values fails to load at startup.
- **`/v1/forward` now rejects methods outside `GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS`** (for example `TRACE` or `CONNECT`) with `400`, for every key. The method is matched case-insensitively.
- **Key list output now includes policy fields** (`credentials`, `methods`, `policy_set`), and so do the create and patch responses. Unrestricted is shown as `["*"]`, never `null`.
- **`GET /v1/admin/audit` returns security events instead of the old audit entries.** The fields changed: `timestamp` is now `@timestamp`, `agent_id`/`agent_name` are `ferrowarden.key.id`/`.name`, `method` and `target_url` are `http.request.method` and `url.original`, `credential_names` is `ferrowarden.credentials`, `response_status` is `http.response.status_code` (now a number; it was the string `"Some(200)"`), and `outcome` is `event.outcome` (`success`/`failure`) with the cause in `event.reason`. The ring buffer now also contains non-forward events (authentication failures, key changes, vault events), so filter on `event.action == "forward"` for the old view.
- **The `audit` log line is gone.** The `tracing` line with `message: "audit"` (fields `agent_id`, `credential_names`, `outcome`, ...) is replaced by security events on stdout with a different shape (`event.dataset == "ferrowarden.security"`). Update Loki queries and Wazuh decoders that matched `message="audit"`; see `docs/events.md` and `docs/logging.md`.
- **Authentication is now checked before request bodies are parsed.** An unauthenticated request with a malformed body gets `401` (it used to get a `400` with parse details). Authenticated requests are unaffected.
- **The `api_prefix` value is no longer written to the startup log.** The startup log says only that a prefix is configured.
- **Ferrowarden now shuts down gracefully** on SIGTERM and Ctrl-C (in-flight requests get up to 10 seconds) and flushes the event sinks before exiting.
- **Items with master password re-prompt are now refused (`403`).** Previously they were usable. Turn re-prompt off on items agents should use.
- **URIs with match type *regex* or *never* no longer act as host bindings.** Add a normal URI (or a `ferrowarden_uris` field) if a credential relied on one.
- **Stricter request parsing.** Requests with unknown fields, duplicate JSON keys, case-insensitively duplicated header names, or unknown/repeated query parameters on `/v1/credentials` now get `400`. A key file with duplicate keys or unknown fields fails to load at startup.

## [0.1.0] — 2026-11-21 (preview)

First public release. Ferrowarden is a credential proxy for AI agents: credentials live in a self-hosted Vaultwarden password manager, agents call APIs through Ferrowarden with `{{vault:name}}` placeholders, and credential values are kept out of the agent's context by design.

### Added

- **Credential proxy** — `POST /v1/forward` substitutes `{{vault:name}}` placeholders in the URL path/query, headers and JSON or raw-string bodies, forwards the request, and returns the scrubbed response. `GET /v1/credentials` lists credential names, never values.
- **Credential host binding** — each credential is only sent to the hosts listed in its Vaultwarden item's URIs (`enforce_credential_hosts`, on by default). Placeholders cannot change the target scheme, host or port.
- **Outbound target policy** — enforced at DNS resolution: bw serve is always refused; private, loopback, link-local (cloud metadata) and other internal addresses need `allowed_targets` or `allow_private_targets`.
- **Response scrubbing** — every substituted value is removed from response bodies, headers and errors in raw, JSON-escaped, URL-encoded and base64 forms, plus common credential patterns. Binary responses are returned base64-encoded.
- **Agent and admin keys** — agent keys stored only as SHA-256 hashes (optionally persisted); environment-only admin key (≥ 32 characters); key rotation via the admin API.
- **Audit log** — credential names (never values), target, outcome and status for every request, in memory and as structured JSON log lines.
- **Rate limiting** — per client IP (configurable: `agent_rate_limit_*` and `admin_rate_limit_*`), with `trusted_proxies` for deployments behind a reverse proxy.
- **Vault lifecycle** — file or manual unlock; periodic `bw serve` sync and credential refresh (`refresh_interval_secs`); automatic re-unlock in file mode after bw serve restarts — immediately when a request finds the vault locked (the request is retried once), otherwise on the next refresh.
- **Configurable API prefix** — `api_prefix` moves every route except `/health` under a hard-to-guess path.
- **Docker Compose stack** — Vaultwarden (pinned 1.37.5) with its web vault published for managing credentials; Bitwarden CLI 2026.11.0 `bw serve` on an internal-only network; internal CA and HTTPS between bw serve and Vaultwarden; settings via `.env` (see `.env.example`).
- **Native TLS** for the agent API (rustls), or run behind a TLS reverse proxy such as Pangolin.
- **Test stack and tooling** — one-command dev setup (`scripts/dev-setup.sh` / `.ps1`), mock API, integration tests covering the leak-prevention guarantees, and a Claude Code skill (`.claude/skills/ferrowarden`).

### Upgrading from pre-release snapshots

- **Vault items need URIs.** A credential whose Vaultwarden item has no URIs, or whose URIs don't match the target host, is now refused with `403`. Add the service's URL to each item.
- **Internal targets need `allowed_targets`.** Services on private networks (e.g. `192.168.1.0/24`, `proxmox.lan`) are blocked until listed.
- **Vaultwarden now uses HTTPS on the internal network** (`https://vaultwarden`), required by current Bitwarden CLI releases. The `internal-certs` service creates the certificates; existing `bw-data` volumes are logged out and reconfigured automatically.
- **Linux hosts:** the Ferrowarden container runs as UID 999 and bw serve as UID 1000; secret files and `certs/server.key` must be readable by them (see `docs/setup.md`).
- **`/v1/unlock`** now accepts `X-Admin-Key` (as documented) and shares the admin rate limit; `Authorization: Bearer` still works.
- **Forward responses** include a new `body_encoding` field (`"utf8"` or `"base64"`).

[Unreleased]: https://github.com/mallard1983/ferrowarden/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/mallard1983/ferrowarden/releases/tag/v0.1.0
