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

Ferrowarden reads credentials from Vaultwarden through one of two **vault backends**, chosen with `vault.backend` (see [Vault backends](#vault-backends) below): the Bitwarden CLI (`bw serve`, the default), or the **native** backend, which speaks the Bitwarden client protocol to Vaultwarden itself. The optional [admin web UI](admin-ui.md) also sends an operator's sign-in to Vaultwarden to be verified.

**Why Vaultwarden instead of a database?**
Using an existing, widely deployed password manager means we do not have to implement encrypted credential storage ourselves. Vaultwarden is an independent, community-maintained implementation of the Bitwarden server API, and it handles the hard parts: key derivation, encryption, authenticated sync. Building equivalent storage from scratch would introduce far more risk.

### Vault backends

Both backends implement one internal `Vault` interface (unlock and lock, sync into the credential map, status, and one secret value at a time). The proxy, the refresher, the unlock endpoint, the admin UI and the events are the same code for both, and a test suite proves that they behave identically ([native-vault.md](native-vault.md)).

| | `bw-serve` (default) | `native` |
|---|---|---|
| Who talks to Vaultwarden | the `bw` CLI, in its own container | Ferrowarden |
| Vault in Ferrowarden's reach | decrypted, in `bw serve`'s memory; values cross a local HTTP connection | ciphertext in Ferrowarden's memory; each value decrypted on request, in process |
| Unlock | `bw serve` is unlocked with the master password | Ferrowarden logs in with the API key, syncs, and derives the keys from the master password |
| Containers | Ferrowarden + `bw-serve` | Ferrowarden |

### bw serve

`bw serve` (backend `bw-serve`) is the Bitwarden CLI (`bw`) running in server mode. It exposes a local REST API on port 8087 (default) for the locked/unlocked vault:

- `POST /unlock` — unlock the vault session with the master password
- `POST /sync` — pull the latest vault contents from Vaultwarden
- `GET /list/object/items` — list items (Ferrowarden keeps only names, ids and URIs)
- `GET /object/password/:id` — retrieve a credential value by item id

The key property: `bw serve` performs decryption locally. Credential values are decrypted on the host, in memory; the only network traffic between `bw serve` and Vaultwarden is the encrypted vault sync, which runs over HTTPS on the internal network (current CLI releases refuse plain HTTP). A one-shot `internal-certs` service issues Vaultwarden's certificate from a private CA kept in the `internal-pki` volume; see [Security Model §6a](security.md#6a-internal-tls-between-bw-serve-and-vaultwarden).

Ferrowarden talks to `bw serve` over plain HTTP on the `vault-internal` network. `bw serve` only accepts requests addressed to `localhost` or to the `--hostname` it was started with, so in Docker Compose it runs with `--hostname bw-serve`.

**Why bw serve is still the default.**
Vaultwarden's vault API works with encrypted blobs; decryption requires the master password and client-side cryptography. `bw serve` is the Bitwarden project's own implementation of that logic, so it is the reference behaviour. The native backend implements the same protocol in Rust (see below) and is held to bw serve's behaviour by the equivalence suite; it stays behind the switch until that has run against more vaults and Vaultwarden versions.

### The native backend

With `vault.backend = "native"` there is no `bw serve`: Ferrowarden logs in to Vaultwarden with the account's API key, syncs, and derives the vault keys from the master password (KDF, HKDF, user key, RSA key, organisation keys, per-item keys). It implements the formats from the observed wire format and the published algorithm descriptions, with RustCrypto primitives and **no Bitwarden SDK code** (licence reasons, [native-vault.md](native-vault.md)).

- The vault stays **ciphertext** in memory. At sync, only what the credential map needs is decrypted: names, URIs, field names, the `ferrowarden_uris` value. Which secrets exist is read from the presence of the ciphertext.
- A secret is **decrypted when a request needs it**, one value at a time, into a `Zeroizing<String>`. Nothing decrypted crosses a network, and there is no whole-item fetch.
- Every key is a `Zeroizing` buffer, wiped on drop; the master password is wiped as soon as the user key exists.
- An item that cannot be read safely is **left out**, never read with a weaker method (fail closed, per item), and the sync event says how many and why.
- A change of the account's user key or security stamp locks the vault.

Trade-off: in file unlock mode one process holds both the API key and the master password. [security.md](security.md#18-the-native-vault-backend) covers it, and manual unlock mode as the hardened option.

### Ferrowarden

Ferrowarden is the proxy. It manages:

- **Agent authentication**: `X-Agent-Key` header check on every request (constant-time comparison)
- **Admin authentication**: Separate admin key for management operations
- **Vault lock state**: Tracks whether the vault backend is unlocked; rejects requests when locked
- **Credential cache**: Item names, ids, URIs, field names and which values exist (never values), loaded at unlock and refreshed every `refresh_interval_secs` after a sync. The refresher also notices when the vault has locked (bw serve restarted, or the native backend saw the account's keys change) and, in file mode, unlocks it again
- **Target policy**: Checks every address the target resolves to (inside the DNS resolver, so there is no rebinding gap); refuses the vault endpoint (bw serve, or Vaultwarden in native mode) and, unless allowed, private/internal addresses
- **Substitution**: Finds `{{vault:name}}` placeholders, validates names against the cache (known, unambiguous, bound to the target host via the item's URIs), fetches values by item id, and substitutes them into the URL, headers, and the parsed JSON body
- **Forwarding**: Sends the substituted request to the target with a configurable timeout (default 30 seconds), no redirect following, no HTTP proxy, and a response size cap
- **Scrubbing**: Removes every encoding of each substituted value from the response body, headers and errors, then runs regex patterns that redact bearer tokens, API key JSON fields, Proxmox tokens, basic auth in URLs, and PEM private key blocks
- **Agent key persistence**: On create, appends a SHA-256 hash of the token to a JSON file (never the plaintext). On startup, re-loads those hashes so keys survive container restarts.
- **Security event log**: Records every security-relevant action (forwards with credential names and outcome, failed authentication, key changes, vault lock/unlock, startup/shutdown) as structured events to stdout, an optional rotating file, optional syslog, and a ring buffer ([events.md](events.md))

---

## Data Flow

```
Agent                    Ferrowarden               bw serve          Target Service
  │                           │                       │                    │
  │ POST /v1/forward           │                       │                    │
  │ {"request": {              │                       │                    │
  │   "url": "https://...",   │                       │                    │
  │   "headers": {             │                       │                    │
  │     "Auth": "Bearer       │                       │                    │
  │       {{vault:my_token}}" │                       │                    │
  │   }                        │                       │                    │
  │ }}                         │                       │                    │
  │──────────────────────────►│                       │                    │
  │                           │ 1. Authenticate agent  │                    │
  │                           │ 2. Check vault locked  │                    │
  │                           │ 3. Extract placeholder │                    │
  │                           │    names from request  │                    │
  │                           │ 4. Validate names      │                    │
  │                           │    against cache       │                    │
  │                           │ GET /object/password/  │                    │
  │                           │    my_token            │                    │
  │                           │───────────────────────►│                    │
  │                           │◄───────────────────────│                    │
  │                           │  Zeroizing<String>     │                    │
  │                           │ 5. Substitute value    │                    │
  │                           │ 6. Forward request     │                    │
  │                           │   (Zeroizing headers)  │                    │
  │                           │                        │ GET https://...    │
  │                           │                        │ Authorization:     │
  │                           │                        │   Bearer sk-real.. │
  │                           │──────────────────────────────────────────► │
  │                           │◄─────────────────────────────────────────── │
  │                           │  Response body         │                    │
  │                           │ 7. Scrub response      │                    │
  │                           │ 8. Record security event  │                    │
  │◄──────────────────────────│                        │                    │
  │  {"status":200,           │                        │                    │
  │   "body":"...scrubbed..."}│                        │                    │
```

The credential value exists in Ferrowarden's memory between steps 4 and 7. It is held as `Zeroizing<String>`, which overwrites the memory location when the value is dropped at the end of step 6.

---

## Credential Lifecycle

1. **At rest**: Encrypted in Vaultwarden (AES-256, key derived from master password with PBKDF2).
2. **In transit (Vaultwarden ↔ bw serve)**: Encrypted vault sync over HTTP on the internal Docker network. Only the encrypted blob is transmitted.
3. **In bw serve's memory** (`bw-serve` backend): Decrypted after the `POST /unlock` call. The process holds the decrypted vault in memory for the lifetime of the session. With the **native** backend this step does not exist: Ferrowarden holds the vault as ciphertext and decrypts a single value at step 4.
4. **In Ferrowarden's memory**: Fetched per-request as `Zeroizing<String>` (from bw serve, or decrypted in process by the native backend). The `zeroize` crate overwrites the memory location when the binding is dropped. This happens at the end of each proxy request.
5. **In the forwarded request**: Sent as a header or body value to the target service over HTTP/HTTPS. The connection is initiated by Ferrowarden's HTTP client; the value is not stored after the request is sent.
6. **In the response**: The scrubber removes credential-shaped content from the response body before it is returned to the agent.

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
