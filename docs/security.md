<img src="../branding/assets/png/banners/ferrowarden-docs-header.png" width="100%" alt="">

# Security Model

This document describes what Ferrowarden is designed to protect against, the security properties it aims to provide, the design decisions behind them, and the limits of its protection. Ferrowarden is a sidecar to [Vaultwarden](https://github.com/dani-garcia/vaultwarden), not a fork or replacement, and is not affiliated with or endorsed by the Vaultwarden or Bitwarden projects. No independent security audit has been published. To report a vulnerability, follow the [Security Policy](../SECURITY.md).

**Transparency is intentional.** Every design decision here has a rationale, and the limits are stated next to the properties. If something seems like it should be here and is not, that is a gap worth reporting.

---

## Threat Model

### Who We Trust

| Actor | Trust Level | Rationale |
|---|---|---|
| The operator | Full trust | Holds the admin key, master password, and vault |
| The host OS | Full trust | Ferrowarden cannot protect against OS-level compromise |
| Vaultwarden | Full trust | Chosen by the operator; runs on the same host |
| bw serve | Full trust | The Bitwarden CLI's vault API server; runs on the same host |
| Docker daemon | Full trust | Same host; controls container isolation |

### Who We Do Not Trust

| Actor | Threat | Mitigation |
|---|---|---|
| The AI agent | Exfiltrates credentials through conversation or logs, or by steering the proxy (sending a credential to a host that echoes it back, or calling bw serve directly) | Agent API tokens are scoped to the proxy only; credentials are bound to the hosts in their vault item URIs; internal targets (always including bw serve and the notifier hosts) are blocked; every encoding of each substituted value is scrubbed from responses and errors |
| The model provider | Logs prompt content including credentials | Credential values are not placed in the agent conversation by design: the agent only handles placeholders and scrubbed responses |
| Target services | Return credential values or credential-shaped content in responses | Exact substituted values (raw, JSON-escaped, URL-encoded, base64) are scrubbed from body and headers, then common credential patterns |
| An attacker who compromises the agent process | Reads credential values from agent memory or conversation | Same as AI agent above |
| A network observer between agent and Ferrowarden | Reads credentials in transit | Native TLS (rustls) is enabled by default; TLS can be disabled only when both agent and Ferrowarden run on the same host |

### Out of Scope

The following threats are explicitly out of scope. Mitigation requires infrastructure choices beyond Ferrowarden's responsibility:

- **Host-level compromise**: If an attacker gains code execution on the Ferrowarden host, they can read bw serve's memory, Ferrowarden's memory, or the secret files. This is a physical/OS security problem.
- **Vaultwarden vulnerabilities**: Ferrowarden depends on Vaultwarden's security. Keep Vaultwarden updated.
- **Credential theft at the target service**: Once Ferrowarden forwards a request, the credential is in the target's logs and memory. This is the same risk as any HTTP client.
- **Agent key theft**: If the agent key is compromised, an attacker can use Ferrowarden to make API calls to any service whose credentials are in the vault. Rotate keys immediately if compromised (see [Operations](operations.md)).

---

## Security Properties

### 1. Credential Values Stay Out of the Agent's Context

The agent sends `{{vault:name}}` placeholders. The substituted values are built in Ferrowarden's memory, used for one outbound HTTP request, and zeroed. Four controls stop the agent from getting a value back:

1. **Credential host binding** (property 13) — a credential is only sent to the hosts listed in its vault item's URIs, so the agent cannot send it to a service that reflects it.
2. **Outbound target policy** (property 14) — bw serve, cloud metadata and other internal addresses cannot be used as targets.
3. **Exact-value scrubbing** (property 8) — every substituted value is removed from the response body, response headers, and error messages, in its raw, JSON-escaped, URL-encoded and base64 forms.
4. **URL-free errors** — forward errors never include the target URL, which contains substituted values.

**What this means:** Credential values are not part of the agent's request or response, so a model provider logging the conversation does not see them, and an agent that echoes back its context does not echo a value. This holds while the controls above are in place and the credential is bound only to services that do not transform and return it (see below).

**What this does not mean:** It does not prevent the agent from learning that a credential exists (it can list credential names). A target that is *bound* to a credential could still transform it into an unrecognisable form (e.g. reversed, or base64 inside a larger string) and return it — only bind credentials to the services they belong to. It does not prevent the agent from making API calls that would indirectly expose data.

### 2. Memory Zeroing on Drop

Credential values fetched from bw serve are held as `Zeroizing<String>` (from the `zeroize` crate). When the value is dropped — at the end of the substitution step — the crate overwrites the memory location with zeros.

**Why this matters:** In a garbage-collected language, there is no guarantee of when memory is freed or whether it is overwritten. With `Zeroizing`, the zeroing is explicit, deterministic, and happens as part of normal ownership semantics.

**Limitation:** The value passes through the `bw serve` HTTP response before reaching Ferrowarden. At that point it is a string in reqwest's response buffer. We zero our copy; we cannot zero reqwest's internal allocations. This is acceptable: the value is short-lived and within our process boundary.

### 3. Admin Key Is Environment-Only

The `admin_key` field in the `Config` struct is marked `#[serde(skip)]`. It cannot be set from `ferrowarden.toml`. It must come from the environment variable `FERROWARDEN_ADMIN_KEY`.

**Why this matters:** A config file is easier to accidentally commit to version control, share, or leave world-readable. An environment variable (or Docker secret read into an env var by the entrypoint) is handled by the deployment system and is not part of the application artifact.

**The 32-character minimum is enforced at startup.** A short key expands the brute-force search space to an attackable range. 32 random alphanumeric characters provides ~190 bits of entropy — well beyond any feasible attack.

### 4. Constant-Time Token Comparison

Both agent token authentication and admin key authentication use a constant-time comparison function (XOR-fold over all bytes, running in O(length) regardless of where a mismatch occurs).

**Why this matters:** A naive string comparison (`==` or `strcmp`) returns early on the first mismatched byte. An attacker who can measure response time can determine how many bytes of their guess were correct, iterating toward the full key. Constant-time comparison eliminates this timing channel.

### 5. Credential Name Validation Before Vault Calls

Before fetching any credential value, Ferrowarden validates all placeholder names against the in-memory cache. If any name is unknown, the entire request is rejected immediately.

**Why this matters:** This is a fail-fast design. An agent cannot probe the vault by guessing names, observe which guesses cause slow responses (due to vault lookups), and use timing to enumerate credentials. All unknown names are rejected without a vault call.

The cache is populated at unlock time and refreshed every `refresh_interval_secs` (default 300 seconds): Ferrowarden asks bw serve to `POST /sync` with Vaultwarden, then reloads item names, ids and URIs. A credential added in Vaultwarden becomes usable within one refresh interval, without a restart.

Values are fetched by **item id**, not by name, so bw's search can never return a different item than the one validated. If two login items share a name, the name is rejected as ambiguous (`409`) rather than guessing.

### 6. bw serve Is Not Exposed Externally

The Docker Compose configuration places `bw-serve` on an `internal: true` network. This means no routing exists between the bw serve container and anything outside Docker. Only Ferrowarden, which is also on that network, can reach `bw serve`.

**Why this matters:** `bw serve` has no authentication. Anyone who can reach its port can list credentials and retrieve values. Network isolation is the primary protection layer for `bw serve`.

Two further layers apply: Ferrowarden's outbound policy refuses `bw serve` as a forward target (property 14), and current `bw serve` releases reject requests whose `Host` header is not `localhost`/`127.0.0.1`/`[::1]` or the `--hostname` it was started with (DNS-rebinding protection). In Docker Compose it is started with `--hostname bw-serve`, the name Ferrowarden uses.

### 6b. The Vaultwarden Web Vault Is User-Facing

Vaultwarden is the user's password manager, so its web vault is published (`127.0.0.1:8443` by default, configurable via `.env`). This is the same exposure as any self-hosted Vaultwarden: vault data is end-to-end encrypted with the master password, and the server never sees plaintext. Signups are off except while creating the first account, and the `/admin` panel is disabled because no `ADMIN_TOKEN` is set.

What is *not* exposed: `bw serve`, which holds the unlocked vault, stays on the `internal: true` network only. The web vault is on a separate `vault-web` network that bw serve and ferrowarden do not join.

Ferrowarden's target policy treats the web vault like any other internal service: an agent cannot reach `https://vaultwarden` (internal address) unless `allowed_targets` permits it, and even if it could, it would only see end-to-end-encrypted data without the master password. Do not bind a credential to the vault's own URL.

### 6a. Internal TLS Between bw serve and Vaultwarden

Current Bitwarden CLI releases refuse plain-HTTP servers, so Vaultwarden serves HTTPS on the `vault-internal` network. A one-shot `internal-certs` service creates a private CA (10 years) and a certificate for `vaultwarden` (825 days, re-issued automatically within 30 days of expiry) in the `internal-pki` volume. Vaultwarden mounts it read-only; bw serve, the setup and the seeder trust only that CA for the internal hop via `NODE_EXTRA_CA_CERTS`. The CA private key never leaves the volume.

This hop only carries Vaultwarden's end-to-end-encrypted vault data and API-key authentication, but it now has transport encryption and server authentication too.

### 7. No Redirect Following

Ferrowarden's HTTP client is configured with `redirect::Policy::none()`, so it does not follow HTTP redirects.

**Why this matters:** A target service could respond with a redirect to an attacker-controlled URL. If Ferrowarden followed the redirect, the credential value in the original request's Authorization header could be forwarded to that URL. With redirect following disabled, this attack does not apply — the agent receives the redirect response and decides whether to follow it.

### 8. Response Scrubbing

First, every credential value substituted into the request is removed from the response body, every response header value, and any error message — in its raw form and its JSON-escaped, URL-encoded, and base64 (standard and URL-safe, padded and unpadded) encodings. Values shorter than 4 characters are not exact-matched (they would shred ordinary text). Non-UTF-8 bodies are scrubbed byte-wise and returned base64-encoded.

Then the body is run through a set of regex patterns that redact:

- Bearer tokens (`Bearer <value>`)
- API key/secret/password JSON fields
- Proxmox PVEAPIToken values
- Basic auth credentials in URLs (`https://user:pass@host/`)
- PEM private key blocks

**Why this matters:** A target service might echo back a credential value in its response (e.g., a 401 that includes the rejected token). Without scrubbing, the agent would receive the value and it would enter its context.

**Limitations:** Exact-value scrubbing catches direct echoes, but a target can transform a value in ways no scrubber recognises. This is why host binding (property 13) is the primary control and scrubbing is defense in depth. The regex patterns cannot catch all formats of credentials the request did *not* use. The scrubber errs on the side of false positives (over-redacting) rather than false negatives.

### 9. Auth Headers Never Forwarded; `x-fw-*` Namespace Reserved

There are two separate protections:

**Agent and admin keys are on the outer request, not the inner one.** The agent authenticates by putting `X-Agent-Key` in the HTTP request headers sent to Ferrowarden. The inner `request.headers` field inside the JSON body is what Ferrowarden forwards to the target — a completely different structure. `X-Agent-Key` is read and consumed by Ferrowarden's auth layer and is never inserted into the outbound request.

**`x-fw-*` headers in the inner request are stripped.** If an agent includes any header whose name starts with `x-fw-` inside its `request.headers` body field, that header is dropped before the request is forwarded. This namespace is reserved for future Ferrowarden-internal use.

**Why this matters:** Together these two properties mean no Ferrowarden authentication credential can reach a target service, whether by accident or by a malicious agent trying to exfiltrate its own key by including it in a forwarded header.

### 10. Native TLS (Transport Security)

Ferrowarden serves HTTPS by default using rustls (a pure-Rust TLS implementation). The certificate and key are configured by the operator.

**Why native TLS instead of a reverse proxy?**  Anyone who wants this level of infrastructure security is already managing their own certificate chain. A built-in TLS layer avoids the operational dependency on a correctly-configured reverse proxy and removes one failure mode (proxy misconfigured without TLS, Ferrowarden exposed unencrypted).

**TLS can be disabled** by setting `tls_enabled = false`. This is only acceptable when both conditions hold:

1. The agent process and Ferrowarden run on the same physical or virtual host.
2. No network hop exists between them (same Docker network, loopback, or Unix socket equivalent).

When TLS is disabled, Ferrowarden logs a prominent multi-line warning at startup. This is intentional — the operator must be aware they are accepting plaintext HTTP.

**Certificate management is the operator's responsibility.** Ferrowarden does not auto-rotate or provision certificates. Restart ferrowarden after replacing a cert to pick up the new one.

**Crypto backend:** We use `axum-server` with the `tls-rustls-ring` feature (ring crypto provider). This is preferred over the `aws-lc-rs` backend for easier cross-platform builds, particularly on Windows development environments with MinGW toolchains.

### 11. Agent Key Persistence: SHA-256 Hashing, No Plaintext on Disk

When `FERROWARDEN_KEYS_FILE` is configured, agent keys survive container restarts. Only the SHA-256 hash of each token is written to disk — the plaintext token is never stored.

**Why SHA-256 for tokens and not bcrypt/argon2?**  Bcrypt and argon2 exist to protect low-entropy secrets (passwords) against offline brute-force. Agent tokens are 48 random alphanumeric characters (~286 bits of entropy). SHA-256 preimage attacks against 286-bit secrets are computationally infeasible. The deliberate slowness of bcrypt/argon2 would add latency to every authentication request with no security benefit against an attacker who would need to try 2^286 values regardless of hash speed.

**What is stored:** A JSON array of `{ id, name, token_hash, created_at }` entries. The `token_hash` is the hex-encoded SHA-256 of the plaintext token. The plaintext is gone after the create response — it is not stored anywhere, including memory.

**Atomic writes:** The key file is written via a rename (write to `.tmp`, then `rename`). A crash or power loss during a write should not leave a corrupt key file — the rename is atomic on the OS filesystems Ferrowarden targets. The old file remains until the rename succeeds.

**Key revocation** removes the entry from the file. Revoked keys are not reloaded on restart.

### 12. Hop-by-Hop Header Stripping

The following headers are removed from forwarded responses: `transfer-encoding`, `connection`, `keep-alive`, `proxy-authenticate`, `proxy-authorization`, `te`, `trailer`, `upgrade`.

**Why this matters:** These headers are specific to a single hop and have no meaning when proxied. Including them could confuse the agent's HTTP client or expose internal connection details.

### 13. Credential Host Binding

With `enforce_credential_hosts = true` (the default), each credential may only be substituted into a request whose target matches one of the URIs on its Vaultwarden login item:

| URI on the vault item | Matches |
|---|---|
| `https://api.example.com` | `https://api.example.com/...` on port 443 only |
| `http://mock-api:7777` | `http://mock-api:7777/...` only |
| `nas.lan` (no scheme) | `nas.lan` over http or https, any port |

Host matching is exact and case-insensitive (`api.example.com.evil.net` does not match). An item with no URIs cannot be used until a URI is added. The check runs before any value is fetched, and a refused request is never sent (`403`).

Binding applies to every value of an item — username, TOTP, notes and custom fields as well as the password. Where the bindings come from:

- A reserved custom field **`ferrowarden_uris`** (comma- or newline-separated URIs), if present. It gives **secure notes** a binding and overrides a login's URIs, so autofill URIs and agent bindings can differ.
- Otherwise the login's URIs, **excluding** those whose Bitwarden match type is *regex* or *never*.

Items with **master password re-prompt** enabled are refused (`403`) — Vaultwarden's API does not enforce re-prompt itself, so Ferrowarden treats it as "never hand this to an agent" until human approval (#14) is available.

**What is scrubbed:** passwords, notes and text/hidden custom fields. Usernames, TOTP codes and boolean fields are **not** treated as secret and are not scrubbed from responses — redacting values such as `admin`, `true` or six-digit numbers would corrupt ordinary output.

Placeholders may not appear in the URL's scheme, host, or port: the host is fixed before substitution, and the request is refused if substitution would change it. This prevents a credential leaking through a DNS lookup of `{{vault:x}}.attacker.example`.

**Why this matters:** Without binding, any agent can send any credential to any host it can reach — including one that simply echoes the request back (`httpbin.org/anything`), defeating every other control.

### 14. Outbound Target Policy (SSRF Protection)

Every address a target resolves to is checked inside Ferrowarden's DNS resolver, so the address checked is the address connected to (no DNS-rebinding gap):

- **Always refused:** the bw serve endpoint (by host name, and by resolved IP + port), the hosts of the configured [notifier URLs](notifications.md#notifier-hosts-are-off-limits-to-agents) (an agent must not be able to post fake notifications or flood your phone), unspecified, multicast and broadcast addresses.
- **Refused unless allowed:** loopback, RFC 1918 private, CGNAT, link-local (including `169.254.169.254` cloud metadata), IPv6 ULA/link-local, and other non-public ranges. Allow specific ones with `allowed_targets` (CIDRs, IPs, or host names) or all of them with `allow_private_targets = true`.
- **Allowed:** public addresses.

`HTTP_PROXY`/`HTTPS_PROXY` environment variables are ignored for forwarded requests, since a proxy would resolve the target itself and bypass this check.

**Why this matters:** bw serve has no authentication. Before this policy, any agent could forward `GET http://bw-serve:8087/object/password/<name>` and read every password in plaintext.

### 15. Response Size Limit

Forwarded responses are read in chunks and rejected with `502` once they exceed `max_response_bytes` (default 10 MiB), so a hostile or broken target cannot exhaust Ferrowarden's memory.

### 16. The Admin Web UI

The optional [admin web UI](admin-ui.md) (`ui.bind`) accepts the **vault master password**, which decrypts the whole vault, so it is held to a stricter standard than the rest of Ferrowarden. It is off by default.

**Threat model.** The assets are the master password and the operator's UI session. The attackers are: a network attacker (sniffing or injecting), a malicious web page the operator visits (CSRF), a script that guesses passwords or codes, a compromised or hostile Vaultwarden, a compromised **agent** (which can reach the API port), and an attacker who reads Ferrowarden's memory or logs after the fact.

| Risk | Control |
|---|---|
| The password crossing the network in clear text | The sign-in form is **only served over HTTPS** (its own TLS, or a trusted proxy's `X-Forwarded-Proto`). Otherwise the page explains why and no form is rendered. `insecure_http` is an explicit, warned-about opt-out |
| An agent reaching the sign-in page | The UI is a **separate listener**; the API router is not mounted on it and the UI is not mounted on the API port. An agent on `:3000` cannot reach `:3001`, and the UI port should not be exposed to agent networks |
| The password being stored or replayed | Ferrowarden never stores it. It derives the Bitwarden login hash in a blocking thread (all intermediates `Zeroizing`), wipes the password, and lets **Vaultwarden itself verify** the hash. On success Vaultwarden's response (tokens, encrypted vault keys) is **dropped unread**: no Vaultwarden credential is ever kept. A session only proves that a login succeeded |
| A hostile Vaultwarden burning CPU/RAM | KDF parameters from the server are **bounded** before use (PBKDF2 5 000 to 2 000 000; Argon2id 16 to 1024 MiB, 2 to 10 iterations, 1 to 16 lanes) |
| A fake Vaultwarden capturing the password | Verified HTTPS to `ui.vaultwarden_url`, trusting the stack's CA via a **public-only** copy (`internal-ca-public`). The **CA private key is never mounted into the Ferrowarden container**: with it an attacker could mint a certificate for `vaultwarden`. Certificate verification is never disabled |
| Password guessing, and exhausting Vaultwarden's login budget (every attempt comes from one IP) | Per-IP (5 per 15 min) and global (10 per 15 min) lockouts, checked **before** any key derivation or upstream call. The error text is generic |
| CSRF | Every POST needs a CSRF token (constant-time compare) **and** a same-origin proof (`Sec-Fetch-Site`, else `Origin`; neither is refused). Cookies are `__Host-` `HttpOnly` `Secure` `SameSite=Strict` |
| Session theft | 32-byte random ids; only the SHA-256 is stored; idle (15 min) and absolute (8 h) limits; at most 8 sessions; rotation on every sign-in; server-side logout |
| XSS, clickjacking, leakage | No scripts at all (`default-src 'none'`), auto-escaping templates, `frame-ancestors 'none'`, `no-store`, `no-referrer`, HSTS |
| Secrets in logs and events | The password, hash, codes, tokens, cookies and Vaultwarden's error text are never logged or put in an event (Vaultwarden's message goes to the **debug** log only: a TOTP failure message contains the server time and IP). Tests check responses, events and log output against fake tokens |
| Two-step bypass | WebAuthn, Duo and recovery codes are not accepted: a recovery login deletes the account's two-step providers. A pending sign-in lives 3 minutes, is bound to the client IP and allows 3 wrong codes |

**Residual risk.** (1) Anyone who can read Ferrowarden's process memory can read a password in flight, or the login hash of a pending two-step sign-in; the buffers Ferrowarden owns are wiped, but the HTTP stack's internal buffers and swap are outside its control. (2) The UI trusts `trusted_proxies` for the client IP and `X-Forwarded-Proto`: list only proxies you control. (3) Ten failed guesses lock the password form for everyone for 15 minutes: an attacker who can reach the UI can keep the operator out (never in). (4) The master password is still the single factor unless the account has two-step login: enable it in the web vault. Keep the UI behind your reverse proxy's authentication where you can.

---

## Security Event Log

Every security-relevant action produces one structured event with a stable schema (see [events.md](events.md)):

- every forwarded request (agent key id and name, method, target URL as the agent sent it, credential names, outcome, a reason code when it failed, the HTTP status, duration);
- failed agent and admin authentication (missing or invalid key), with source IP and request ID;
- credential listings, key creation and revocation, vault unlock/lock/sync, startup (security-relevant settings) and shutdown;
- admin UI sign-ins (success, failure with a fixed reason, lockouts, the first step of a two-step login), sign-outs and session expiry;
- rate limiting (aggregated: at most one event per client IP per minute), and requests rejected for an invalid body or query.

Events carry the client IP and a request ID that is also returned in the `X-Request-Id` response header. Authentication is checked **before** a request body is parsed, so an unauthenticated caller learns nothing from parse errors.

Credential values, agent tokens and their hashes, the admin key, the master password and the API prefix are never recorded, and a failed-authentication event does not contain the presented key. Agent-supplied strings are truncated and JSON-escaped, so they cannot forge log lines. `scripts/check-no-secrets.sh` (run in CI) fails the build if any seeded secret shows up in the container logs or the event file.

Events are written to stdout (default), optionally a rotating file and syslog (UDP, TCP or TLS), and to an in-memory ring buffer (default 1000 events) behind `GET /v1/admin/audit`. Logging never blocks or fails a request; if the sink queue overflows, events are dropped for the sinks and an `events_dropped` event reports the count.

**Recommendation:** ship the events to a persistent sink (Loki, Wazuh, a file, syslog) so the trail survives a restart, and alert on repeated `agent_auth` failures, any `credential_host_not_allowed` or `target_blocked` forward, and `admin_auth` failures.

**Push notifications.** Ferrowarden can also send the important events to Gotify, ntfy or a generic webhook ([notifications.md](notifications.md)). A notification is built from an allow-listed set of event fields only (credential *names*, target *host*, key name, source IP, request id, reason code), never a value, token, URL path or query, header or body; the notifier tokens come only from the environment or a secret file and are never logged; and a slow or failing notifier cannot delay a request or an event sink, at the cost that notifications are best effort.

---

## Deployment Security Checklist

Before going to production:

- [ ] Vaultwarden's `SIGNUPS_ALLOWED` is set to `false`
- [ ] The Vaultwarden web vault is published only where you need it (`VAULTWARDEN_PUBLISH`); if it is reachable from the internet, it is behind a TLS reverse proxy — ideally with SSO in front — and your account has two-step login enabled
- [ ] `bw serve` port (8087) is not reachable from outside Docker (`internal: true` network)
- [ ] The `internal-pki` volume (internal CA key) is backed up or treated as regenerable, and not copied elsewhere
- [ ] Every vault item agents use has URIs for exactly the hosts it belongs to, and `enforce_credential_hosts` is `true`
- [ ] `allowed_targets` lists only the internal hosts/ranges agents need; `allow_private_targets` is `false`
- [ ] If a reverse proxy fronts Ferrowarden, `trusted_proxies` is set to its address (and nothing else)
- [ ] The admin UI is disabled (`ui.bind` empty) unless you use it; if enabled, it is served over HTTPS (never `ui.insecure_http`), its port is not reachable from agent networks, and the Vaultwarden account has two-step login. `ferrowarden` mounts `internal-ca-public`, never `internal-pki` (see [admin-ui.md](admin-ui.md))
- [ ] TLS is configured — either Ferrowarden's built-in TLS or a TLS-terminating proxy (Pangolin, Caddy, Nginx). See [docs/tls.md](tls.md) for both options. If TLS is disabled, Ferrowarden and the agent must run on the same host with no network hop.
- [ ] `tls_cert_file` and `tls_key_file` point to valid, non-expired certificates
- [ ] All secret files are `chmod 600` and owned by the deployment user
- [ ] `FERROWARDEN_ADMIN_KEY` is at least 32 random characters
- [ ] `ferrowarden.toml` (if used) is in `.gitignore` and not committed
- [ ] Agent keys are created with meaningful names so the audit log is interpretable
- [ ] Structured log output is being shipped to a persistent sink
- [ ] A process exists to rotate agent keys if they are compromised (see [Operations](operations.md))

---

## Dependency Security

The project uses `cargo audit` to scan for known vulnerabilities in dependencies. Run it regularly:

```sh
cargo audit
```

As of the initial release, there is one warning: `chrono` (the datetime library) is marked as unmaintained. This is not a vulnerability — it is a maintenance notice. There is no current replacement with equivalent functionality. This will be revisited when an alternative stabilizes.

All other dependencies were clean at time of writing. Subscribe to the [RustSec advisory database](https://rustsec.org/) for new advisories.
