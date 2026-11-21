# Security Model

This document describes what Ferrowarden protects against, what security properties it provides, the design decisions that achieve those properties, and the limits of its protection.

**Transparency is intentional.** A security tool that cannot be reasoned about cannot be trusted. Every design decision here has a rationale. If something seems like it should be here and is not, that is a gap worth reporting.

---

## Threat Model

### Who We Trust

| Actor | Trust Level | Rationale |
|---|---|---|
| The operator | Full trust | Holds the admin key, master password, and vault |
| The host OS | Full trust | Ferrowarden cannot protect against OS-level compromise |
| Vaultwarden | Full trust | Chosen by the operator; runs on the same host |
| bw serve | Full trust | Official Bitwarden CLI; runs on the same host |
| Docker daemon | Full trust | Same host; controls container isolation |

### Who We Do Not Trust

| Actor | Threat | Mitigation |
|---|---|---|
| The AI agent | Exfiltrates credentials through conversation or logs | Agent API tokens are scoped to the proxy only; values never appear in agent-visible responses |
| The model provider | Logs prompt content including credentials | Values never enter the agent conversation |
| Target services | Return credential-shaped content in responses | Scrubber removes common patterns before returning response to agent |
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

### 1. Credentials Never Reach the Agent

The agent sends `{{vault:name}}` placeholders. The substituted values are built in Ferrowarden's memory, used for one outbound HTTP request, and zeroed. The response body is scrubbed before being returned.

**What this means:** A model provider cannot log a credential from an agent request or response. An agent that echoes back its context cannot expose a credential value.

**What this does not mean:** It does not prevent the agent from learning that a credential exists (it can list credential names). It does not prevent the agent from making API calls that would indirectly expose data.

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

**Tradeoff:** The cache is populated at unlock time. If a credential is added to the vault after unlock, it will not be visible until the next unlock (restart in file mode, or a re-unlock in manual mode). This is an acceptable tradeoff for the security property.

### 6. bw serve Is Not Exposed Externally

The Docker Compose configuration places `bw-serve` on an `internal: true` network. This means no routing exists between the bw serve container and anything outside Docker. Only Ferrowarden, which is also on that network, can reach `bw serve`.

**Why this matters:** `bw serve` has no authentication. Anyone who can reach its port can list credentials and retrieve values. Network isolation is the primary protection layer for `bw serve`.

### 7. No Redirect Following

Ferrowarden's HTTP client is configured with `redirect::Policy::none()`. It never follows HTTP redirects.

**Why this matters:** A target service could respond with a redirect to an attacker-controlled URL. If Ferrowarden followed the redirect, the credential value in the original request's Authorization header could be forwarded to that URL. With redirect following disabled, this attack is not possible — the agent receives the redirect response and decides whether to follow it.

### 8. Response Scrubbing

The response body from every forwarded request is run through a set of regex patterns that redact:

- Bearer tokens (`Bearer <value>`)
- API key/secret/password JSON fields
- Proxmox PVEAPIToken values
- Basic auth credentials in URLs (`https://user:pass@host/`)
- PEM private key blocks

**Why this matters:** A target service might echo back a credential value in its response (e.g., a 401 that includes the rejected token). Without scrubbing, the agent would receive the value and it would enter its context.

**Limitations:** The scrubber is regex-based and cannot catch all possible formats. It is a defense-in-depth measure, not a complete guarantee. Custom credential formats may not be caught. The scrubber errs on the side of false positives (over-redacting) rather than false negatives.

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

### 11. Agent Key Persistence: SHA-256 Hashing, Never Plaintext

When `FERROWARDEN_KEYS_FILE` is configured, agent keys survive container restarts. Only the SHA-256 hash of each token is written to disk — the plaintext token is never stored.

**Why SHA-256 for tokens and not bcrypt/argon2?**  Bcrypt and argon2 exist to protect low-entropy secrets (passwords) against offline brute-force. Agent tokens are 48 random alphanumeric characters (~286 bits of entropy). SHA-256 preimage attacks against 286-bit secrets are computationally infeasible. The deliberate slowness of bcrypt/argon2 would add latency to every authentication request with no security benefit against an attacker who would need to try 2^286 values regardless of hash speed.

**What is stored:** A JSON array of `{ id, name, token_hash, created_at }` entries. The `token_hash` is the hex-encoded SHA-256 of the plaintext token. The plaintext is gone after the create response — it is not stored anywhere, including memory.

**Atomic writes:** The key file is written via a rename (write to `.tmp`, then `rename`). A crash or power loss during a write cannot produce a corrupt key file — the rename is atomic at the OS level. The old file remains until the rename succeeds.

**Key revocation** removes the entry from the file. Revoked keys are not reloaded on restart.

### 12. Hop-by-Hop Header Stripping

The following headers are removed from forwarded responses: `transfer-encoding`, `connection`, `keep-alive`, `proxy-authenticate`, `proxy-authorization`, `te`, `trailer`, `upgrade`.

**Why this matters:** These headers are specific to a single hop and have no meaning when proxied. Including them could confuse the agent's HTTP client or expose internal connection details.

---

## Audit Log

Every proxy request generates an audit entry containing:

- Timestamp
- Agent key ID and name (not the token value)
- HTTP method and target URL
- Credential names used (not values)
- Outcome (success, vault locked, unknown credential, forward failed, unauthorized, internal error)
- Response HTTP status code

Credential values are never recorded in the audit log.

The in-memory ring buffer (default 1000 entries) is accessible via `GET /v1/admin/audit`. The same events are emitted as structured JSON log lines (compatible with Loki/Grafana) so they can be persisted externally.

**Recommendation:** Ship the structured log output to a persistent sink (Loki, Elasticsearch, a log file) so the audit trail survives a restart.

---

## Deployment Security Checklist

Before going to production:

- [ ] Vaultwarden's `SIGNUPS_ALLOWED` is set to `false`
- [ ] Vaultwarden is not exposed on a public port
- [ ] `bw serve` port (8087) is not reachable from outside Docker (`internal: true` network)
- [ ] TLS is enabled (`tls_enabled = true`, which is the default); if disabled, Ferrowarden and the agent must run on the same host with no network hop
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
