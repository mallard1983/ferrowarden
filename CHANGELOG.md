# Changelog

All notable changes to this project are documented here. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows [Semantic Versioning](https://semver.org/). While the version is 0.x, minor releases may contain breaking changes; they are called out under **Upgrading**.

## [Unreleased]

### Added

- **Field placeholders** (#8): `{{vault:NAME:username}}`, `:totp`, `:notes` and `:field:FIELD` for custom fields (text, hidden, boolean, and linked to the username or password). **Secure notes** are now supported.
- **Any item or field name**: names with spaces, colons or other characters are referenced with single quotes, e.g. `{{vault:'Proxmox (prod)':field:'api secret'}}`.
- `GET /v1/credentials?detail=true` returns ready-made placeholders for every available value, unavailable values with the reason, and each credential's `bound_to` hosts.
- Reserved custom field `ferrowarden_uris` sets an item's host bindings (needed for secure notes; overrides a login's URIs).

### Changed

- Malformed placeholders (anything starting with `{{vault:` that does not parse) are rejected with `422` instead of being forwarded as literal text.
- `GET /v1/credentials` also lists secure notes, and names that previously could not be referenced.

### Upgrading

- **Items with master password re-prompt are now refused (`403`).** Previously they were usable. Turn re-prompt off on items agents should use.
- **URIs with match type *regex* or *never* no longer act as host bindings.** Add a normal URI (or a `ferrowarden_uris` field) if a credential relied on one.

## [0.1.0] — 2026-11-21 (preview)

First public release. Ferrowarden is a credential proxy for AI agents: credentials live in a self-hosted Vaultwarden password manager, agents call APIs through Ferrowarden with `{{vault:name}}` placeholders, and credential values never reach the agent.

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
