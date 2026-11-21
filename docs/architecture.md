# Architecture

## Overview

Ferrowarden is a credential proxy — a small HTTP service that sits between an AI agent and the services it needs to call. The agent never receives credential values. Instead, it sends requests with named placeholders; Ferrowarden looks up the real values, makes the call on the agent's behalf, and returns the response with any credential-shaped content scrubbed out.

---

## Why This Exists

AI agents that manage infrastructure need credentials to do their job. The obvious approaches all have the same failure mode: the credential value ends up somewhere the LLM can see it.

- **Inject credentials into the system prompt**: The value lives in every request and in provider logs.
- **Pass credentials in tool call arguments**: They appear in the conversation history.
- **Have the agent retrieve credentials itself**: Any retrieval response containing a value can be echoed back.

Ferrowarden eliminates the exposure surface by ensuring the agent never receives a value — only the name of a credential and the result of an API call that used it.

---

## Components

### Vaultwarden

Vaultwarden is a self-hosted, open-source Bitwarden-compatible server written in Rust. It handles:

- Encrypted storage of credentials at rest (AES-256)
- The human-facing web UI for managing credential names and values
- Multi-device sync for the vault operator

Ferrowarden never talks directly to Vaultwarden. Only the Bitwarden CLI (`bw serve`) does.

**Why Vaultwarden instead of a database?**
Using an existing, audited password manager means we do not have to implement encrypted credential storage ourselves. Vaultwarden has been in production use since 2018, has an active security community, and handles the hard parts: key derivation, encryption, authenticated sync. Building equivalent storage from scratch would introduce far more risk.

### bw serve

`bw serve` is the official Bitwarden CLI running in server mode. It exposes a local REST API on port 8087 (default) for the locked/unlocked vault:

- `POST /unlock` — unlock the vault session with the master password
- `POST /sync` — pull the latest vault contents from Vaultwarden
- `GET /list/object/items` — list items (Ferrowarden keeps only names, ids and URIs)
- `GET /object/password/:id` — retrieve a credential value by item id

The key property: `bw serve` performs decryption locally. Credential values are decrypted on the host, in memory, and never transmitted over a network connection. The only network traffic between `bw serve` and Vaultwarden is the encrypted vault sync, which runs over HTTPS on the internal network (current CLI releases refuse plain HTTP). A one-shot `internal-certs` service issues Vaultwarden's certificate from a private CA kept in the `internal-pki` volume; see [Security Model §6a](security.md#6a-internal-tls-between-bw-serve-and-vaultwarden).

Ferrowarden talks to `bw serve` over plain HTTP on the `vault-internal` network. `bw serve` only accepts requests addressed to `localhost` or to the `--hostname` it was started with, so in Docker Compose it runs with `--hostname bw-serve`.

**Why bw serve instead of Vaultwarden's HTTP API directly?**
Vaultwarden's vault API works with encrypted blobs. Decryption requires the master password and client-side cryptography. Implementing the full Bitwarden crypto stack (PBKDF2, AES-CBC, RSA) in Ferrowarden would significantly increase code complexity and the risk of cryptographic mistakes. `bw serve` is the officially maintained implementation of that logic.

### Ferrowarden

Ferrowarden is the proxy. It manages:

- **Agent authentication**: `X-Agent-Key` header check on every request (constant-time comparison)
- **Admin authentication**: Separate admin key for management operations
- **Vault lock state**: Tracks whether `bw serve` has been unlocked; rejects requests when locked
- **Credential cache**: Login item names, ids and URIs (never values), loaded at unlock and refreshed every `refresh_interval_secs` after a `bw serve` sync. The refresher also notices when bw serve has locked (e.g. after a restart) and, in file mode, re-unlocks it
- **Target policy**: Checks every address the target resolves to (inside the DNS resolver, so there is no rebinding gap); refuses bw serve and, unless allowed, private/internal addresses
- **Substitution**: Finds `{{vault:name}}` placeholders, validates names against the cache (known, unambiguous, bound to the target host via the item's URIs), fetches values by item id, and substitutes them into the URL, headers, and the parsed JSON body
- **Forwarding**: Sends the substituted request to the target with a configurable timeout (default 30 seconds), no redirect following, no HTTP proxy, and a response size cap
- **Scrubbing**: Removes every encoding of each substituted value from the response body, headers and errors, then runs regex patterns that redact bearer tokens, API key JSON fields, Proxmox tokens, basic auth in URLs, and PEM private key blocks
- **Agent key persistence**: On create, appends a SHA-256 hash of the token to a JSON file (never the plaintext). On startup, re-loads those hashes so keys survive container restarts.
- **Audit log**: Records every proxy request (credential names, outcome, response status) to a ring buffer and to structured log output

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
  │                           │ 8. Record audit entry  │                    │
  │◄──────────────────────────│                        │                    │
  │  {"status":200,           │                        │                    │
  │   "body":"...scrubbed..."}│                        │                    │
```

The credential value exists in Ferrowarden's memory between steps 4 and 7. It is held as `Zeroizing<String>`, which overwrites the memory location when the value is dropped at the end of step 6.

---

## Credential Lifecycle

1. **At rest**: Encrypted in Vaultwarden (AES-256, key derived from master password with PBKDF2).
2. **In transit (Vaultwarden ↔ bw serve)**: Encrypted vault sync over HTTP on the internal Docker network. Only the encrypted blob is transmitted.
3. **In bw serve's memory**: Decrypted after the `POST /unlock` call. The process holds the decrypted vault in memory for the lifetime of the session.
4. **In Ferrowarden's memory**: Fetched per-request as `Zeroizing<String>`. The `zeroize` crate overwrites the memory location when the binding is dropped. This happens at the end of each proxy request.
5. **In the forwarded request**: Sent as a header or body value to the target service over HTTP/HTTPS. The connection is initiated by Ferrowarden's HTTP client; the value is not stored after the request is sent.
6. **In the response**: The scrubber removes credential-shaped content from the response body before it is returned to the agent.

The agent never touches steps 1–5.

---

## Why Rust

The language choice was deliberate for a security-sensitive component:

- **Memory safety**: Rust's ownership model eliminates use-after-free, double-free, and buffer overflow classes of bugs at compile time — without a garbage collector that might delay memory clearing.
- **`Zeroizing`**: The `zeroize` crate provides guaranteed memory zeroing on drop. In garbage-collected languages, there is no equivalent guarantee: the runtime may move objects, delay collection, or leave copies in memory at unpredictable times.
- **No null pointer exceptions, no data races**: The type system enforces these at compile time.
- **Explicit error handling**: `Result<T, E>` forces every error path to be handled. No unchecked exceptions can bypass security checks.
- **Minimal runtime**: No JVM, no interpreter, no runtime that adds its own attack surface.

The tradeoff is longer build times and a steeper learning curve. For a credential proxy, the security properties outweigh the inconvenience.

---

## What Ferrowarden Is Not

- **Not a secrets manager**: Vaultwarden handles storage. Ferrowarden only proxies.
- **Not a firewall**: It does not enforce which target URLs the agent may call. That is the operator's responsibility (network policy, reverse proxy rules).
- **Not a full audit trail**: The in-memory ring buffer (default 1000 entries) is lost on restart. Persist the structured log output (Loki, Elasticsearch, etc.) for a durable audit trail.
- **Not a firewall for target URLs**: It does not enforce which URLs the agent may call. That is the operator's responsibility (network policy, firewall rules).
- **Not a full audit trail on its own**: The in-memory ring buffer is lost on restart. Ship the structured JSON log output to Loki, Elasticsearch, or a log file for a durable audit trail.
