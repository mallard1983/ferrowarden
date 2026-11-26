# Architecture

## Overview

Ferrowarden is a source-available credential proxy — a small HTTP service that sits between an AI agent and the services it needs to call. It runs as a sidecar to [Vaultwarden](https://github.com/dani-garcia/vaultwarden) (it is not a fork or replacement, and is not affiliated with Vaultwarden or Bitwarden). By design, the agent is never handed credential values. Instead, it sends requests with named placeholders; Ferrowarden looks up the real values, makes the call on the agent's behalf, and returns the response with known credential values and common credential patterns scrubbed out.

---

## Why This Exists

AI agents that manage infrastructure need credentials to do their job. The obvious approaches all have the same failure mode: the credential value ends up somewhere the LLM can see it.

- **Inject credentials into the system prompt**: The value lives in every request and in provider logs.
- **Pass credentials in tool call arguments**: They appear in the conversation history.
- **Have the agent retrieve credentials itself**: Any retrieval response containing a value can be echoed back.

Ferrowarden reduces this exposure by design: the agent works with the name of a credential and the result of an API call that used it, and is not handed the value. [Security Model](security.md) describes the controls and their limits.

---

## Components

### Vaultwarden

Vaultwarden is a self-hosted, open-source Bitwarden-compatible server written in Rust. It handles:

- Encrypted storage of credentials at rest (AES-256)
- The human-facing web UI for managing credential names and values
- Multi-device sync for the vault operator

Ferrowarden reads credentials from Vaultwarden through one of two **vault backends**, chosen with `vault.backend` (see [Vault backends](#vault-backends) below): the **native** backend (the default), which speaks the Bitwarden client protocol to Vaultwarden itself, or the deprecated Bitwarden CLI (`bw serve`), which is removed in the next release. The optional [admin web UI](admin-ui.md) also sends an operator's sign-in to Vaultwarden to be verified.

**Why Vaultwarden instead of a database?**
Using an existing, widely deployed password manager means we do not have to implement encrypted credential storage ourselves. Vaultwarden is an independent, community-maintained implementation of the Bitwarden server API, and it handles the hard parts: key derivation, encryption, authenticated sync. Building equivalent storage from scratch would introduce far more risk.

### Vault backends

Both backends implement one internal `Vault` interface (unlock and lock, sync into the credential map, status, and one secret value at a time). The proxy, the refresher, the unlock endpoint, the admin UI and the events are the same code for both, and a test suite proves that they behave identically ([native-vault.md](native-vault.md)).

| | `native` (default) | `bw-serve` (deprecated, removed in the next release) |
|---|---|---|
| Who talks to Vaultwarden | Ferrowarden | the `bw` CLI, in its own container |
| Vault in Ferrowarden's reach | ciphertext in Ferrowarden's memory; each value decrypted on request, in process | decrypted, in `bw serve`'s memory; values cross a local HTTP connection |
| Decrypted values on a network | none | every requested value, over plain HTTP on the internal network |
| Unlock | Ferrowarden logs in with the API key, syncs, and derives the keys from the master password | `bw serve` is unlocked with the master password |
| Containers | Ferrowarden | Ferrowarden + `bw-serve` |
| In the trust base | Ferrowarden's own code and RustCrypto crates | adds Node.js, the Bitwarden CLI and its npm tree |

### The native backend (default)

Ferrowarden logs in to Vaultwarden with the account's API key, syncs, and derives the vault keys from the master password (KDF, HKDF, user key, RSA key, organisation keys, per-item keys). It implements the formats from the observed wire format and the published algorithm descriptions, with RustCrypto primitives and **no Bitwarden SDK code** (licence reasons, [native-vault.md](native-vault.md)). There is no `bw serve`, no Node.js and no Bitwarden CLI in the deployment.

- **No decrypted values on the network.** The only traffic between Ferrowarden and Vaultwarden is the login and the encrypted vault sync, over HTTPS on the internal network. Nothing decrypted is ever sent between containers.
- **The vault is held as ciphertext.** At sync, only what the credential map needs is decrypted: names, URIs, field names, the `ferrowarden_uris` value. Which secrets exist is read from the presence of the ciphertext.
- **Decrypt on demand.** A secret is decrypted when a request needs it: only the requested field, one value at a time, into a `Zeroizing<String>`, substituted, then wiped. There is no whole-item fetch and no decrypted copy of the vault.
- Every key is a `Zeroizing` buffer, wiped on drop; the master password is wiped as soon as the user key exists.
- An item that cannot be read safely is **left out**, never read with a weaker method (fail closed, per item), and the sync event says how many and why. This includes items whose collection hides passwords from the account, unless you opt in.
- A change of the account's user key or security stamp locks the vault.
- One fewer container: the `bw-serve` service and its `bw-data` volume are gone from the default stack.

Trade-off: in file unlock mode one process holds both the API key and the master password. [security.md](security.md#native-backend-one-process-holds-both-secrets) covers it, and manual unlock mode as the hardened option.

A one-shot `internal-certs` service (`ferrowarden internal-certs`, the same binary and image as the proxy: no Node.js, no shell, no openssl) issues Vaultwarden's certificate from a private CA kept in the `internal-pki` volume, so the connection between Ferrowarden and Vaultwarden is HTTPS and verified against that CA ([Security Model §6a](security.md#6a-internal-tls-between-ferrowarden-and-vaultwarden)).

### bw serve (deprecated)

`bw serve` (backend `bw-serve`) is the Bitwarden CLI (`bw`) running in server mode. It stays available for 0.2.0 behind `vault.backend = "bw-serve"` and is removed in the next release; see [native-vault.md](native-vault.md#switching). It exposes a local REST API on port 8087 for the locked/unlocked vault:

- `POST /unlock` — unlock the vault session with the master password
- `POST /sync` — pull the latest vault contents from Vaultwarden
- `GET /list/object/items` — list items (Ferrowarden keeps only names, ids and URIs)
- `GET /object/password/:id` — retrieve a credential value by item id

`bw serve` decrypts the vault locally and holds it **decrypted in its memory** for the whole session, and each value Ferrowarden asks for crosses the internal network as plain HTTP (`vault-internal`). That is the exposure the native backend removes. `bw serve` only accepts requests addressed to `localhost` or to the `--hostname` it was started with, so in Docker Compose it runs with `--hostname bw-serve`.

### Ferrowarden

Ferrowarden is the proxy. It manages:

- **Agent authentication**: `X-Agent-Key` header check on every request (constant-time comparison)
- **Admin authentication**: Separate admin key for management operations
- **Vault lock state**: Tracks whether the vault backend is unlocked; rejects requests when locked
- **Credential cache**: Item names, ids, URIs, field names and which values exist (never values), loaded at unlock and refreshed every `refresh_interval_secs` after a sync. The refresher also notices when the vault has locked (the native backend saw the account's keys change, or, with the deprecated bw serve, it restarted) and, in file mode, unlocks it again
- **Target policy**: Checks every address the target resolves to (inside the DNS resolver, so there is no rebinding gap); refuses the vault endpoint (Vaultwarden, or bw serve with the deprecated backend) and, unless allowed, private/internal addresses
- **Substitution**: Finds `{{vault:name}}` placeholders, validates names against the cache (known, unambiguous, bound to the target host via the item's URIs), decrypts the one field each placeholder names, on demand, and substitutes it into the URL, headers, and the parsed JSON body
- **Forwarding**: Sends the substituted request to the target with a configurable timeout (default 30 seconds), no redirect following, no HTTP proxy, and a response size cap
- **Scrubbing**: Removes every encoding of each substituted value from the response body, headers and errors, then runs regex patterns that redact bearer tokens, API key JSON fields, Proxmox tokens, basic auth in URLs, and PEM private key blocks
- **Agent key persistence**: On create, appends a SHA-256 hash of the token to a JSON file (never the plaintext). On startup, re-loads those hashes so keys survive container restarts.
- **Security event log**: Records every security-relevant action (forwards with credential names and outcome, failed authentication, key changes, vault lock/unlock, startup/shutdown) as structured events to stdout, an optional rotating file, optional syslog, and a ring buffer ([events.md](events.md))

---

## Data Flow

```
Agent                    Ferrowarden                Vaultwarden        Target Service
  │                           │                         │                    │
  │ POST /v1/forward          │                         │                    │
  │ {"request": {             │                         │                    │
  │   "url": "https://...",   │                         │                    │
  │   "headers": {            │                         │                    │
  │     "Auth": "Bearer       │                         │                    │
  │       {{vault:my_token}}" │                         │                    │
  │   }                       │                         │                    │
  │ }}                        │                         │                    │
  │──────────────────────────►│                         │                    │
  │                           │ 1. Authenticate agent   │                    │
  │                           │ 2. Check vault locked   │                    │
  │                           │ 3. Extract placeholder  │                    │
  │                           │    names from request   │                    │
  │                           │ 4. Validate names       │                    │
  │                           │    against cache        │                    │
  │                           │ 5. Decrypt that one     │                    │
  │                           │    field from the       │                    │
  │                           │    ciphertext it holds  │                    │
  │                           │    (Zeroizing<String>)  │                    │
  │                           │ 6. Substitute value     │                    │
  │                           │ 7. Forward request      │                    │
  │                           │    (Zeroizing headers)  │ GET https://...    │
  │                           │                         │ Authorization:     │
  │                           │                         │   Bearer sk-real.. │
  │                           │──────────────────────────────────────────► │
  │                           │◄─────────────────────────────────────────── │
  │                           │  Response body          │                    │
  │                           │ 8. Scrub response       │                    │
  │                           │ 9. Record security event│                    │
  │◄──────────────────────────│                         │                    │
  │  {"status":200,           │                         │                    │
  │   "body":"...scrubbed..."}│                         │                    │
```

Vaultwarden is not in the request path. Ferrowarden contacted it earlier (login and sync, then a cheap revision check on every refresh tick), and the only thing it received was ciphertext. Between steps 5 and 8 the credential value exists in Ferrowarden's memory, as a `Zeroizing<String>` that overwrites the memory location when it is dropped at the end of step 7. With the deprecated `bw-serve` backend, step 5 instead asks `bw serve` (`GET /object/password/<id>`) and the decrypted value travels over the internal network.

---

## Credential Lifecycle

1. **At rest**: Encrypted in Vaultwarden (AES-256, key derived from the master password with PBKDF2 or Argon2id).
2. **In transit (Vaultwarden ↔ Ferrowarden)**: The vault as ciphertext, over HTTPS on the internal Docker network, verified against the internal CA. Nothing decrypted is transmitted.
3. **In Ferrowarden's memory, at rest**: Still ciphertext. Only names, URIs and field names are decrypted (the credential map). The vault keys (user key, organisation keys) are `Zeroizing` buffers derived at unlock.
4. **In Ferrowarden's memory, per request**: One field is decrypted on demand into a `Zeroizing<String>`. The `zeroize` crate overwrites the memory location when the binding is dropped, at the end of each proxy request.
5. **In the forwarded request**: Sent as a header or body value to the target service over HTTP/HTTPS. The connection is initiated by Ferrowarden's HTTP client; the value is not stored after the request is sent.
6. **In the response**: The scrubber removes credential-shaped content from the response body before it is returned to the agent.

With the deprecated `bw-serve` backend, the decrypted vault also sits in `bw serve`'s memory for the whole session and each requested value is sent to Ferrowarden over plain HTTP on the internal network (steps 3 and 4 differ).

By design, the agent is not part of steps 1–5.

---

## Why Rust

The language choice was deliberate for a security-sensitive component:

- **Memory safety**: In safe Rust, the ownership model rules out use-after-free, double-free, and buffer overflow classes of bugs at compile time — without a garbage collector that might delay memory clearing.
- **`Zeroizing`**: The `zeroize` crate provides explicit memory zeroing on drop that the compiler is not allowed to optimise away. In garbage-collected languages, there is no equivalent control: the runtime may move objects, delay collection, or leave copies in memory at unpredictable times.
- **No null pointer exceptions, no data races**: The type system enforces these at compile time.
- **Explicit error handling**: `Result<T, E>` forces every error path to be handled. No unchecked exceptions can bypass security checks.
- **Minimal runtime**: No JVM, no interpreter, no runtime that adds its own attack surface.

The tradeoff is longer build times and a steeper learning curve. For a credential proxy, the security properties outweigh the inconvenience.

---

## What Ferrowarden Is Not

- **Not a secrets manager**: Vaultwarden handles storage. Ferrowarden only proxies.
- **Not a firewall**: It does not enforce which target URLs the agent may call. That is the operator's responsibility (network policy, reverse proxy rules).
- **Not a durable audit trail on its own**: The in-memory ring buffer (default 1000 events) is lost on restart. Enable a sink (stdout shipped to Loki, the file sink, or syslog) for a durable trail.
- **Not a firewall for target URLs**: It does not enforce which URLs the agent may call. That is the operator's responsibility (network policy, firewall rules).
- **Not a durable audit trail on its own**: Ship the security events to Loki, Wazuh, a file or syslog for a durable trail.
