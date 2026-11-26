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
| Docker daemon | Full trust | Same host; controls container isolation |

### Who We Do Not Trust

| Actor | Threat | Mitigation |
|---|---|---|
| The AI agent | Exfiltrates credentials through conversation or logs, or by steering the proxy (sending a credential to a host that echoes it back, or calling the vault directly) | Agent API tokens are scoped to the proxy only; credentials are bound to the hosts in their vault item URIs; internal targets (always including the vault endpoint and the notifier hosts) are blocked; every encoding of each substituted value is scrubbed from responses and errors |
| The model provider | Logs prompt content including credentials | Credential values are not placed in the agent conversation by design: the agent only handles placeholders and scrubbed responses |
| Target services | Return credential values or credential-shaped content in responses | Exact substituted values (raw, JSON-escaped, URL-encoded, base64) are scrubbed from body and headers, then common credential patterns |
| A service that logs in and returns a session token | The token reaches the agent, and with it the conversation, a log or an injected request | The agent asks Ferrowarden to capture the token; it is kept in memory, bound to the agent key and the origin, and hidden from every response (property 20) |
| An attacker who compromises the agent process | Reads credential values from agent memory or conversation | Same as AI agent above |
| A network observer between agent and Ferrowarden | Reads credentials in transit | Native TLS (rustls) is enabled by default; TLS can be disabled only when both agent and Ferrowarden run on the same host |
| Another container or process on the internal Docker network | Reads decrypted credential values off the wire between the vault component and Ferrowarden | There are none: the only traffic to Vaultwarden is the login and the encrypted vault, over verified HTTPS, and a value is decrypted inside Ferrowarden only for the request that needs it |

### Out of Scope

The following threats are explicitly out of scope. Mitigation requires infrastructure choices beyond Ferrowarden's responsibility:

- **Host-level compromise**: If an attacker gains code execution on the Ferrowarden host, they can read Ferrowarden's memory or the secret files. This is a physical/OS security problem.
- **Vaultwarden vulnerabilities**: Ferrowarden depends on Vaultwarden's security. Keep Vaultwarden updated.
- **Credential theft at the target service**: Once Ferrowarden forwards a request, the credential is in the target's logs and memory. This is the same risk as any HTTP client.
- **Agent key theft**: If the agent key is compromised, an attacker can use Ferrowarden to make API calls to any service whose credentials are in the vault. Rotate keys immediately if compromised (see [Operations](operations.md)).

---

## Security Properties

### 1. Credential Values Stay Out of the Agent's Context

The agent sends `{{vault:name}}` placeholders. The substituted values are built in Ferrowarden's memory, used for one outbound HTTP request, and zeroed. Four controls stop the agent from getting a value back:

1. **Credential host binding** (property 13) — a credential is only sent to the hosts listed in its vault item's URIs, so the agent cannot send it to a service that reflects it.
2. **Outbound target policy** (property 14) — the vault endpoint, cloud metadata and other internal addresses cannot be used as targets.
3. **Exact-value scrubbing** (property 8) — every substituted value is removed from the response body, response headers, and error messages, in its raw, JSON-escaped, URL-encoded and base64 forms.
4. **URL-free errors** — forward errors never include the target URL, which contains substituted values.

**What this means:** Credential values are not part of the agent's request or response, so a model provider logging the conversation does not see them, and an agent that echoes back its context does not echo a value. This holds while the controls above are in place and the credential is bound only to services that do not transform and return it (see below).

**What this does not mean:** It does not prevent the agent from learning that a credential exists (it can list credential names). A target that is *bound* to a credential could still transform it into an unrecognisable form (e.g. reversed, or base64 inside a larger string) and return it — only bind credentials to the services they belong to. It does not prevent the agent from making API calls that would indirectly expose data.

### 2. Memory Zeroing on Drop

With the native backend a credential value is **decrypted on demand**: only the requested field, for the one request that needs it, into a `Zeroizing<String>` (from the `zeroize` crate). The vault itself stays ciphertext in memory. When the value is dropped — at the end of the substitution step — the crate overwrites the memory location with zeros. The vault keys are `Zeroizing` buffers too.

**Why this matters:** In a garbage-collected language, there is no guarantee of when memory is freed or whether it is overwritten. With `Zeroizing`, the zeroing is explicit, deterministic, and happens as part of normal ownership semantics.

**Limitation:** Buffers inside the HTTP stack (the login form with the API key secret, the bearer token header) and serde's scratch space while parsing the token response cannot be wiped from Rust. The decrypted value never passes through an HTTP response, so unlike the deprecated bw-serve backend (where it arrived in reqwest's response buffer, which we could not zero) there is no copy of it outside our own buffers.

### 3. Admin Key Never Comes From a Config File

The `admin_key` field in the `Config` struct is marked `#[serde(skip)]`. It cannot be set from `ferrowarden.toml`. It comes from the environment variable `FERROWARDEN_ADMIN_KEY` or, in a container, from the file named by `FERROWARDEN_ADMIN_KEY_FILE` (a Docker secret). Ferrowarden reads that file itself, into `Zeroizing` memory, and never exports the value into its own environment. The notifier tokens and the unlock password file follow the same rules.

**Why this matters:** A config file is easier to accidentally commit to version control, share, or leave world-readable. A secret file is handled by the deployment system and is not part of the application artifact. Reading the file in the binary, rather than in an entrypoint script that exports it, keeps the key out of `/proc/<pid>/environ`, where anything running as the same user (or anyone who can read the process environment) could take it, and out of `docker inspect`. CI checks this on every run by reading the container's `/proc/<pid>/environ` and confirming it does not contain the key.

**Limit:** the key is in Ferrowarden's memory for as long as it runs (it is compared with every admin request), so an attacker with code execution in the process, or a memory dump, still gets it.

**The 32-character minimum is enforced at startup.** A short key expands the brute-force search space to an attackable range. 32 random alphanumeric characters provides ~190 bits of entropy — well beyond any feasible attack.

### 4. Constant-Time Token Comparison

Both agent token authentication and admin key authentication use a constant-time comparison function (XOR-fold over all bytes, running in O(length) regardless of where a mismatch occurs).

**Why this matters:** A naive string comparison (`==` or `strcmp`) returns early on the first mismatched byte. An attacker who can measure response time can determine how many bytes of their guess were correct, iterating toward the full key. Constant-time comparison eliminates this timing channel.

### 5. Credential Name Validation Before Vault Calls

Before fetching any credential value, Ferrowarden validates all placeholder names against the in-memory cache. If any name is unknown, the entire request is rejected immediately.

**Why this matters:** This is a fail-fast design. An agent cannot probe the vault by guessing names, observe which guesses cause slow responses (due to vault lookups), and use timing to enumerate credentials. All unknown names are rejected without a vault call.

The cache is populated at unlock time and refreshed every `refresh_interval_secs` (default 300 seconds): Ferrowarden checks Vaultwarden's revision, syncs the encrypted vault when it changed, then reloads item names, ids and URIs. A credential added in Vaultwarden becomes usable within one refresh interval, without a restart.

Values are decrypted by **item id**, not by name, so a name search can never return a different item than the one validated. If two login items share a name, the name is rejected as ambiguous (`409`) rather than guessing.

### 6. No Decrypted Values on the Network

In the default deployment no component serves decrypted credentials over a network. Ferrowarden holds the vault as ciphertext and decrypts a field inside its own process; the connection to Vaultwarden (on the `internal: true` `vault-internal` network) carries the login and the encrypted vault only. Nothing on that network, and nothing that can reach it, can read a credential value from the wire.

This is a deliberate change from 0.1.0, where `bw serve` held the whole vault decrypted and answered `GET /object/password/<id>` to anyone on the network. 0.2.0 replaced it with the native backend and 0.3.0 removed `bw serve`, which took Node.js, the Bitwarden CLI and its npm dependency tree out of the trust base along with one container from the deployment.

### 6b. The Vaultwarden Web Vault Is User-Facing

Vaultwarden is the user's password manager, so its web vault is published (`127.0.0.1:8443` by default, configurable via `.env`). This is the same exposure as any self-hosted Vaultwarden: vault data is end-to-end encrypted with the master password, and the server never sees plaintext. Signups are off except while creating the first account, and the `/admin` panel is disabled because no `ADMIN_TOKEN` is set.

What is *not* exposed: Ferrowarden, which holds the vault keys, stays off the web vault's network. The web vault is on a separate `vault-web` network that ferrowarden does not join.

Ferrowarden's target policy treats the web vault like any other internal service: an agent cannot reach `https://vaultwarden` (internal address) unless `allowed_targets` permits it, and even if it could, it would only see end-to-end-encrypted data without the master password. Do not bind a credential to the vault's own URL.

### 6a. Internal TLS Between Ferrowarden and Vaultwarden

Ferrowarden refuses plain-HTTP vault URLs, so Vaultwarden serves HTTPS on the `vault-internal` network. A one-shot `internal-certs` service creates a private CA (10 years) and a certificate for `vaultwarden` (825 days, re-issued automatically within 30 days of expiry) in the `internal-pki` volume. Vaultwarden mounts it read-only; Ferrowarden trusts only that CA for the internal hop, through `vault.ca_file`, which points at the public copy in `internal-ca-public`. The CA private key never leaves the `internal-pki` volume, which Ferrowarden does not mount. `internal-certs` is `ferrowarden internal-certs`: a one-shot run of the same audited, static binary as the proxy, from the same image. The default deployment has no Node.js, no shell and no openssl for this job. It runs with no network (`network_mode: none`), a read-only root filesystem, all capabilities dropped and `no-new-privileges`, as root only because the existing `internal-pki` volume is root-owned (without capabilities, root cannot read or change files it does not own). Its keys are ECDSA P-256 in PKCS#8, created with mode 0600 and written atomically, and nothing it logs contains key material. An existing CA, including one made by an earlier release with openssl, is reused. See [tls.md](tls.md#the-internal-ca-how-it-is-made).

This hop carries Vaultwarden's end-to-end-encrypted vault data and the API-key authentication, and has transport encryption and server authentication too.

### 7. No Redirect Following

Ferrowarden's HTTP client is configured with `redirect::Policy::none()`, so it does not follow HTTP redirects.

**Why this matters:** A target service could respond with a redirect to an attacker-controlled URL. If Ferrowarden followed the redirect, the credential value in the original request's Authorization header could be forwarded to that URL. With redirect following disabled, this attack does not apply — the agent receives the redirect response and decides whether to follow it.

### 8. Response Scrubbing

First, every credential value substituted into the request is removed from the response body, every response header value, and any error message — in its raw form and its JSON-escaped, URL-encoded, and base64 (standard and URL-safe, padded and unpadded) encodings. Values shorter than 4 characters are not exact-matched (they would shred ordinary text). The URL-encoded form is matched with upper and lower case hex. If a UTF-8 body is JSON and a decoded string still holds a value (the target escaped it in a way the text match does not know: PHP's `\/`, Go's `\u0026`, every character as `\uXXXX`), the body is scrubbed string by string and re-serialized, so its formatting may change in that case only. Matches are replaced longest first across all values. Non-UTF-8 bodies are scrubbed byte-wise and returned base64-encoded.

The same exact-value pass also removes every value in the calling key's [captured sessions](sessions.md), replaced with `[CAPTURED:name]` (property 20).

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

Items with **master password re-prompt** enabled are refused (`403`) — Vaultwarden's API does not enforce re-prompt itself, so Ferrowarden treats it as "never hand this to an agent". Human approval (property 21) is a different feature: it is how an item that may be used with a person's consent is marked.

**What is scrubbed:** passwords, notes and text/hidden custom fields. Usernames, TOTP codes and boolean fields are **not** treated as secret and are not scrubbed from responses — redacting values such as `admin`, `true` or six-digit numbers would corrupt ordinary output.

Placeholders may not appear in the URL's scheme, host, or port: the host is fixed before substitution, and the request is refused if substitution would change it. This prevents a credential leaking through a DNS lookup of `{{vault:x}}.attacker.example`.

**Why this matters:** Without binding, any agent can send any credential to any host it can reach — including one that simply echoes the request back (`httpbin.org/anything`), defeating every other control.

### 14. Outbound Target Policy (SSRF Protection)

Every address a target resolves to is checked inside Ferrowarden's DNS resolver, so the address checked is the address connected to (no DNS-rebinding gap):

- **Always refused:** the vault endpoint (`vault.url`'s host and port; by host name, and by resolved IP + port), the hosts of the configured [notifier URLs](notifications.md#notifier-hosts-are-off-limits-to-agents) (an agent must not be able to post fake notifications or flood your phone), unspecified, multicast and broadcast addresses.
- **Refused unless allowed:** loopback, RFC 1918 private, CGNAT, link-local (including `169.254.169.254` cloud metadata), IPv6 ULA/link-local, and other non-public ranges. Allow specific ones with `allowed_targets` (CIDRs, IPs, or host names) or all of them with `allow_private_targets = true`.
- **Allowed:** public addresses.

`HTTP_PROXY`/`HTTPS_PROXY` environment variables are ignored for forwarded requests, since a proxy would resolve the target itself and bypass this check.

**Why this matters:** The vault endpoint must never be a forward target: it holds the whole encrypted vault and answers the API-key login. With 0.1.0's `bw serve`, which had no authentication, any agent could otherwise have forwarded `GET http://bw-serve:8087/object/password/<name>` and read every password in plaintext; the rule stayed when that backend went.

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
| A fake Vaultwarden capturing the password | Verified HTTPS to `vault.url`, trusting the stack's CA via a **public-only** copy (`internal-ca-public`). The **CA private key is never mounted into the Ferrowarden container**: with it an attacker could mint a certificate for `vaultwarden`. Certificate verification is never disabled |
| Password guessing, and exhausting Vaultwarden's login budget (every attempt comes from one IP) | Per-IP (5 per 15 min) and global (10 per 15 min) lockouts, checked **before** any key derivation or upstream call. The error text is generic |
| CSRF | Every POST needs a CSRF token (constant-time compare) **and** a same-origin proof (`Sec-Fetch-Site`, else `Origin`; neither is refused). Cookies are `__Host-` `HttpOnly` `Secure` `SameSite=Strict` |
| Session theft | 32-byte random ids; only the SHA-256 is stored; idle (15 min) and absolute (8 h) limits; at most 8 sessions; rotation on every sign-in; server-side logout |
| XSS, clickjacking, leakage | No scripts at all (`default-src 'none'`), auto-escaping templates, `frame-ancestors 'none'`, `no-store`, `no-referrer`, HSTS |
| Secrets in logs and events | The password, hash, codes, tokens, cookies and Vaultwarden's error text are never logged or put in an event (Vaultwarden's message goes to the **debug** log only: a TOTP failure message contains the server time and IP). Tests check responses, events and log output against fake tokens |
| Two-step bypass | WebAuthn, Duo and recovery codes are not accepted: a recovery login deletes the account's two-step providers. A pending sign-in lives 3 minutes, is bound to the client IP and allows 3 wrong codes |

**Residual risk.** (1) Anyone who can read Ferrowarden's process memory can read a password in flight, or the login hash of a pending two-step sign-in; the buffers Ferrowarden owns are wiped, but the HTTP stack's internal buffers and swap are outside its control. (2) The UI trusts `trusted_proxies` for the client IP and `X-Forwarded-Proto`: list only proxies you control. (3) Ten failed guesses lock the password form for everyone for 15 minutes: an attacker who can reach the UI can keep the operator out (never in). (4) The master password is still the single factor unless the account has two-step login: enable it in the web vault. Keep the UI behind your reverse proxy's authentication where you can.

---

### 17. A Minimal, Read-Only Container

The Ferrowarden image is a static binary on `scratch`, run as UID 999 with a read-only root filesystem, no capabilities and `no-new-privileges`; Vaultwarden is the only other service ([Deployment Profiles](deployment-profiles.md)). There is no shell, package manager or `curl` to use, and nothing in the image can be modified at run time.

**Why this matters:** most of what an attacker does after getting code execution depends on tools that are already there. Removing them, and the ability to write new ones, shrinks a code-execution bug. The binary checks its own health (`ferrowarden healthcheck`, which verifies the server's own TLS certificate), which is why the image needs no `curl`.

**Limits:** this is attack-surface reduction, not isolation. A container shares the host kernel, so a kernel or runtime escape is outside what it can stop; the *Hardened* profile (a dedicated VM, optionally gVisor, outbound firewall rules) addresses that. A compromised Ferrowarden process can still use the vault and the destinations it is allowed to reach. The Vaultwarden image is a third-party image with a normal userland: restricted, not minimal.

---

### 18. The Native Vault Backend

`vault.backend = "native"` ([native-vault.md](native-vault.md)) is Ferrowarden's own implementation of the Bitwarden client protocol, and the only vault backend. It replaced `bw serve`, which 0.2.0 deprecated and 0.3.0 removed. What it gives:

- **Decrypted vault:** never. Only metadata is decrypted at sync; **a secret is decrypted for one request** (decrypt-on-demand: only the requested field).
- **A secret on the wire:** never. It does not leave the process until it is substituted into the outbound request.
- **Whole-item fetch:** none.
- **Extra attack surface:** one Rust module (about 1,600 lines of production code, with its own unit tests) and RustCrypto crates. No Bitwarden CLI, no Node.js, no npm dependency tree.
- **Containers:** Vaultwarden and Ferrowarden.

The cost is that the tests no longer have an independent reference implementation, the Bitwarden CLI, to compare Ferrowarden with. [native-vault.md](native-vault.md#how-formats-are-verified) lists what replaces it: known-answer vectors, a capture from a real web vault, fail-closed exclusion counts and two Vaultwarden versions in CI.

#### Native backend: one process holds both secrets

**The trade-off.** In **file unlock mode** one process holds both the Vaultwarden API key and the master password (before 0.2.0, the `bw-serve` container held the API key and the vault session, and Ferrowarden held the password file's value only while unlocking). A memory-disclosure bug in Ferrowarden would expose both. The mitigations are the same ones the rest of Ferrowarden uses, plus process hardening described below. **Manual unlock mode is the hardened option**: the master password is typed once per boot (through `POST /v1/unlock` or the admin UI), held only for the key derivation, and not on disk; if you can accept typing it after each restart, prefer it. To use it, set `FERROWARDEN_UNLOCK_MODE=manual` and remove the `bw_master_password` secret from the `ferrowarden` service.

**Cryptographic rules, as implemented:**

- **EncString allow-list.** Only type 2 (AES-256-CBC with HMAC-SHA256) for symmetric keys and types 3 and 4 (RSA-OAEP, SHA-256 and SHA-1) for RSA keys are accepted. Type 0 (no MAC), 1, 5, 6, 7 and every unknown number are refused *before* the payload is read. There is no code path that decrypts without a MAC, and nothing is guessed from the data's shape.
- **MAC first.** The HMAC-SHA256 over `iv || ciphertext` is verified in constant time before the cipher sees any ciphertext. A test proves that a ciphertext with valid structure and a wrong MAC is rejected with a MAC failure, where the same ciphertext with a correct MAC fails later in the padding check.
- **Exact lengths.** Symmetric keys (user key, organisation keys, per-item keys) must be exactly 64 bytes; IV 16 bytes, MAC 32 bytes, ciphertext a multiple of 16; RSA keys PKCS#8 of 2048 to 4096 bits. Base64 must be canonical.
- **KDF bounds.** The account's KDF parameters come from the server, so they are bounded (the admin UI's rules) before any work is done.
- **Fail closed, per item.** An item whose name, URIs, field names, per-item key or organisation key cannot be read is excluded and counted by reason in the `vault_sync` event (item ids, never names or values). A user key whose MAC fails is an unlock failure.
- **Memory.** Keys are `Zeroizing` buffers (and the AES key schedule is wiped on drop); decrypted values are `Zeroizing<String>`; no key, ciphertext or value appears in `Debug` output, logs or events. Stored items are ciphertext. The exceptions that cannot be wiped from Rust: buffers inside the HTTP stack (the login form with the API key secret, the bearer token header) and serde's scratch space while parsing the token response.
- **Process hardening (Linux).** `PR_SET_DUMPABLE = 0` and `RLIMIT_CORE = 0` at startup: no core dump, no `ptrace` by other unprivileged processes. Failures are logged. `mlock` is not used (keys live in many small heap allocations; a locked arena would need an extra crate and discipline for little gain): disable swap for the container instead (`memswap_limit` equal to `mem_limit`).
- **Lock.** A changed user key or security stamp locks the vault and drops the keys and the credential map.
- **RSA.** `rsa` 0.10 or later only (earlier releases are affected by RUSTSEC-2023-0071). Only the account's own organisation-key ciphertexts are decrypted, at unlock and sync; no attacker-driven decryption oracle is exposed.
- **No Bitwarden SDK.** The code is written from the wire format and published algorithms; see [native-vault.md](native-vault.md).

**Format drift.** New Bitwarden clients may write formats not listed here (V2 accounts use COSE EncStrings, type 7). They are refused, the affected items are excluded and counted, and everything else keeps working. Treat a non-zero `excluded` count in a `vault_sync` event as something to look into.

- **Hidden passwords.** An organisation collection shared with the account as "Hide passwords" makes the server mark its items `viewPassword: false`. Ferrowarden would give such a password to an agent, which the collection's owner meant to keep from this account, so Ferrowarden **leaves those items out by default** (reason `hidden_password` in the `vault_sync` event: a count and item ids, never names or values; also in `ferrowarden_vault_excluded_items`). `vault.allow_hidden_passwords = true` (`FERROWARDEN_VAULT__ALLOW_HIDDEN_PASSWORDS`) is the explicit opt-in: it logs a startup warning and the `startup` event records `vault_allow_hidden_passwords`. ([native-vault.md](native-vault.md#hidden-passwords-collections-that-hide-them)).

**Tested against:** Vaultwarden 1.37.5 with a PBKDF2 account and 1.36.0 with an Argon2id account, both in CI ([cicd.md](cicd.md#vaultwarden-versions-in-ci)).

**Not covered:** V2 (COSE) accounts have not been exercised end to end against a live vault. A vault written by the web vault bundled with Vaultwarden 1.37.5 (Argon2id, organisation, trashed and archived items) is covered by a fixture; extension and mobile clients are not.

---

### 20. Captured Sessions

Some APIs log in first and return a session token (a JWT, a cookie, a ticket). Without help the login works through Ferrowarden, but the token comes back to the agent: a live credential in its context. With `capture` ([sessions.md](sessions.md)) the agent names a value of the login response, Ferrowarden keeps it, and the agent sees `[CAPTURED:name]`. Later requests write `{{session:name}}`.

| Risk | Control |
|---|---|
| The token reaching the agent in the login response | The value is read from the **raw** response, before scrubbing, on any status code, and every encoding of it (raw, JSON-escaped, URL-encoded, four base64 forms) is replaced with `[CAPTURED:name]` in the body and in header values, `Set-Cookie` included |
| The token reaching the agent later, in an echo or an error page | **Every** session value of the calling key is scrubbed from **every** response of that key, whether or not the request used it. A value found at a capture source that could not be stored (`too_long`, `expired`, `limit_reached`) is removed too, as `[REDACTED]` |
| Using a session at a host it did not come from | A session is bound to the origin (scheme, host, port) of the login request and refused anywhere else with `403` before a connection is made |
| One agent key using another's session, or learning that it exists | Sessions are keyed by (agent key, name). Another key's name, an absent name and an expired name give the same `422` (`unknown_session`) |
| A token outliving the access it was captured under | Sessions live in memory only, with a lifetime of at most `sessions.max_ttl_secs`, shortened by the token's own `exp` or the cookie's `Max-Age`/`Expires`. They are cleared when the key is revoked, when its policy changes, when the vault locks, and by a restart. The agent can delete one at any time |
| Token values in events, logs or metrics | Events carry the session name, host and outcome. The store has a `Debug` that prints counts only; values are `Zeroizing` and never serialized. Metrics have no session label. The CI secret gate reads every token the mock login services issued and scans the logs, the event file and a metrics scrape for them |
| A response mentioning the token so the agent can pick it up | Exact-value scrubbing, as above. `too_short` values (under 4 characters) cannot be scrubbed and are not stored |
| An agent filling memory | At most `sessions.max_per_key` live sessions per key (default 32), at most 16 KiB each, at most 8 captures per request |

**What this does not protect against.** It narrows what the agent can *see*, not what it can *do*:

- While a session lives, the agent can use it for any request the key's method policy and the outbound target policy allow to that origin. A prompt-injected agent can act as the logged-in user. Keep TTLs short and policies tight.
- A target that returns a token in a form the scrubber does not know (cut up, hex-encoded, hashed) leaks it. The exact-value scrubber is defense in depth, as for vault credentials (property 8).
- Tokens in the login response that you did not capture (a refresh token, a second cookie) stay visible. Capture each one you do not want the agent to see.
- The URL-encoded cookie form: Proxmox sets the ticket in a cookie URL-encoded. Capture the ticket from the JSON body; its URL-encoded form is scrubbed from `Set-Cookie`. Captured from the cookie, the raw ticket in the JSON body would be a different string and stay visible.
- A process memory dump contains the sessions, as it contains the vault's keys (property 18).
- There is no key-policy field for sessions in this release. A key that may call a login endpoint may capture; `sessions.enabled = false` turns the feature off. The decision, and why every policy change clears the key's sessions, are in [sessions.md](sessions.md#policy).

### 21. Human Approval

A credential can be marked as needing a person's decision before an agent uses it: by a reserved `ferrowarden_approval` field on its vault item, or by a pattern in the agent key's `approval` list ([approvals.md](approvals.md)). Either is enough and neither can switch off the other. The new property: **a value for such an item is never fetched from the vault, and nothing is sent to the target, without a human decision for that key, that item and that target origin.**

| Risk | Control |
|---|---|
| The request being sent, or the value fetched, before anyone decided | The gate is the last check of `/v1/forward`, **before** `fetch_credentials` and before any connection. The request is held (`approval.wait_secs`) and then answered `approval_pending`: it does not proceed on a timeout. Tests assert that the vault was not read and the target saw nothing for pending and denied requests |
| The agent approving its own request | No agent route decides. The decisions are the admin API (the admin key; an agent key is refused with `401`, in any header) and the admin UI, which needs a signed-in session, a sign-in within the last 10 minutes, the CSRF token and a same-origin request. The approval id in a link is unguessable (at least 128 bits) and is **not a capability**: it opens nothing without a session |
| A key policy or a typo switching approval off | The vault field wins: a key's `approval` list can only add. Any value of the field other than `required`, an empty one included, still means required, and is counted as a warning in `vault_sync`. Removing or narrowing a key's `approval` patterns is a **widening**, which the UI asks you to confirm |
| An agent flooding the operator with prompts | Per key: at most `approval.max_pending_per_key` open approvals (3), `approval.max_requests_per_key_per_hour` new prompts in a sliding hour (20) and `approval.max_waiters_per_key` held requests (8); beyond them `429 approval_limit_reached` or an immediate `approval_pending`. These are in addition to the agent rate limiter. A request that waits on an approval that is already open sends no second prompt |
| Re-asking after a denial | A denial stands for `approval.pending_ttl_secs`: the key gets `approval_denied` at once, with no new prompt |
| An approval outliving its authority | Grants and open approvals are in memory only. Revoking the key, changing its policy or locking the vault clears them; a person can revoke a grant; a restart empties them. Each has a time limit chosen by the approver, at most `approval.max_grant_minutes` |
| Values in the prompt, in events or in the page | The prompt and the approval page show what the agent **sent**, with placeholders: nothing has been read from the vault yet, so there is no value to show. Events carry names, host, path (no query), ids and the approver, never a value; the CI secret gate scans them |

**The prompt carries more than other notifications.** Other notifications show the target **host** only. The approval prompt also carries the method, the host's port and the **path** (without the query string, cut to 200 characters), because you cannot decide without them. It never carries the query string, headers, body or a value. The path is chosen by the agent, so treat it as text from the agent. Keep the notifier on a channel you trust ([notifications.md](notifications.md#the-approval-prompt)).

**What this does not protect against.**

- A grant covers the key, the item and the origin for its minutes, **not only the request shown**. A prompt-injected agent can use the window. Use short grants for sensitive items and revoke early.
- The approver decides from what the agent sent. An agent that dresses a destructive request as an innocent one is not stopped by Ferrowarden.
- Approval does not replace host binding, the target policy or scrubbing; after a yes they apply as before.
- The approver identity in events is the vault account signed in to the UI, or `admin_api`. There is one account: the events do not tell two people apart.
- A held request occupies a connection for up to `approval.wait_secs`; a reverse proxy in front of the API needs a read timeout above it ([approvals.md](approvals.md#reverse-proxies-and-timeouts)).

### 19. The Metrics Listener

The optional [Prometheus endpoint](metrics.md) (`metrics.bind`) is a third listener, off by default. It exposes counts and state, not secrets, but it is still an information source about your vault and your agents, so it is built to leak as little as possible and to be hard to misconfigure.

| Risk | Control |
|---|---|
| An agent, or anything on the agent network, reading the metrics | A **separate listener** on its own port. `/metrics` does not exist on the API or UI ports, and nothing of the API or UI exists on the metrics port: it serves `GET /metrics` only (other paths `404`, other methods `405`). Do not put its port on an agent network |
| Anyone who can reach the port reading them | A **bearer token by default** (`FERROWARDEN_METRICS_TOKEN` or `_FILE`, read in Rust into wiped memory like the other secrets, never in the process environment, never in a config file). The check hashes both sides with SHA-256 and compares the digests in constant time, so neither the token nor its length can be probed by timing. Only a digest of the token is kept after start |
| Running open by accident | A bind address that is **not loopback** with no token is **refused at start**, unless `metrics.allow_unauthenticated = true`, which logs a warning and is recorded in the `startup` event (`metrics_auth: "none"`). A token together with that flag is refused too |
| Guessing the token | Every failure is a `401` and is counted (`ferrowarden_auth_failures_total{kind="metrics"}`); a `metrics_auth` event is emitted at most once per source address per minute, so a scan cannot flood the event stream, and it never contains the token or the presented value. Use a random token of at least 16 characters (Ferrowarden enforces the minimum; `openssl rand` makes 40) |
| The token on the wire | With `tls_enabled = true` the listener serves TLS with the API's certificate. Without it the token and the metrics cross the network **in clear text**: Ferrowarden warns, and the port should be internal-only |
| Secrets, URLs or names in the output | Label values come only from fixed enums and from names the administrator chose (agent key names); no URL, host, IP, header name, placeholder or value can reach a label because the label types have no field for them. Credential names are **not** exported unless `metrics.credential_labels = true`, which is capped at 500 names and logged as a warning. Tested with hostile events, against real traffic on both backends, and by the CI secret gate scanning a scrape |
| Metrics slowing or breaking the proxy | The event consumer has its own bounded queue read with `try_send` from `emit`: a full queue only loses metrics (and counts the loss). A scrape reads in-memory state and makes no call to Vaultwarden or any other service |
| Cardinality attacks | Nothing an agent sends becomes a label value, so an agent cannot create series. Key names and credential names are capped (1000 and 500) and overflow to `_other` |

**What the metrics still tell a reader:** how many agents and credentials there are, how much traffic each agent key (by its name) sends and how often it is refused and why, when the vault was last synced and whether it is locked. That is operational intelligence about your setup. Treat the metrics endpoint, Prometheus and Grafana as part of the system you protect, and keep the token out of dashboards and chat.

---

## Security Event Log

Every security-relevant action produces one structured event with a stable schema (see [events.md](events.md)):

- every forwarded request (agent key id and name, method, target URL as the agent sent it, credential names, outcome, a reason code when it failed, the HTTP status, duration);
- failed agent and admin authentication (missing or invalid key), with source IP and request ID;
- credential listings, key creation and revocation, vault unlock/lock/sync, startup (security-relevant settings) and shutdown;
- captured sessions: each capture, each use, each expiry and each deletion, by session name (never the value);
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
- [ ] The `vault-internal` network is `internal: true` (it is in the shipped Compose file), so nothing outside Docker can reach Vaultwarden's internal HTTPS port
- [ ] You chose the unlock mode on purpose: `file` keeps the master password on disk and in the same process as the API key; `manual` is the hardened option (property 18)
- [ ] The `internal-pki` volume (internal CA key) is backed up or treated as regenerable, and not copied elsewhere
- [ ] Every vault item agents use has URIs for exactly the hosts it belongs to, and `enforce_credential_hosts` is `true`
- [ ] `allowed_targets` lists only the internal hosts/ranges agents need; `allow_private_targets` is `false`
- [ ] If a reverse proxy fronts Ferrowarden, `trusted_proxies` is set to its address (and nothing else), and its read timeout for the API is above `approval.wait_secs` (60 seconds by default, 300 at most) if you use [human approval](approvals.md)
- [ ] Credentials that should not be used without a person (root tokens, firewalls) carry a `ferrowarden_approval` field or are listed in the agent key's `approval` patterns, and a notifier delivers the prompt
- [ ] The admin UI is disabled (`ui.bind` empty) unless you use it; if enabled, it is served over HTTPS (never `ui.insecure_http`), its port is not reachable from agent networks, and the Vaultwarden account has two-step login. `ferrowarden` mounts `internal-ca-public`, never `internal-pki` (see [admin-ui.md](admin-ui.md))
- [ ] TLS is configured — either Ferrowarden's built-in TLS or a TLS-terminating proxy (Pangolin, Caddy, Nginx). See [docs/tls.md](tls.md) for both options. If TLS is disabled, Ferrowarden and the agent must run on the same host with no network hop.
- [ ] `tls_cert_file` and `tls_key_file` point to valid, non-expired certificates
- [ ] All secret files are `chmod 600` and owned by the deployment user
- [ ] The admin key (`secrets/ferrowarden_admin_key`) is at least 32 random characters
- [ ] The `ferrowarden` service keeps the shipped hardening (`read_only`, `cap_drop: [ALL]`, `no-new-privileges`); you chose a [deployment profile](deployment-profiles.md) that matches what the vault protects
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
