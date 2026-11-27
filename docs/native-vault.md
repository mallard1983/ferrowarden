# The native vault backend

Ferrowarden reads the vault itself: it speaks the Bitwarden client protocol to Vaultwarden and does the cryptography in Rust. This is the only vault backend (`vault.backend = "native"`, the default). The Bitwarden CLI's `bw serve`, which 0.1.0 used and 0.2.0 deprecated, was removed in 0.3.0: see [Upgrading from bw-serve](#upgrading-from-bw-serve).

- No extra containers: no Bitwarden CLI and no Node.js.
- Secrets are decrypted in Ferrowarden, one value at a time, on request. Nothing decrypted crosses a network.
- The vault is held in memory as ciphertext. Only metadata (names, URIs, field names) is decrypted.
- It can also **write**, in one place only: a login item in the [managed collection](#the-write-path-and-the-managed-collection), when an agent asks for a credential and a human approves ([managed-credentials.md](managed-credentials.md)). Everything else it does is read-only.

The code that reads the vault sits behind an internal `Vault` interface, and everything else (placeholders, host binding, policy, scrubbing, events, the admin UI) uses only that. The interface stays so that another backend can be added later; the native one is its only implementation.

## Settings

```toml
[vault]
url     = "https://vaultwarden"    # FERROWARDEN_VAULT__URL (this is the default)
ca_file = "/ca-public/ca.crt"      # FERROWARDEN_VAULT__CA_FILE (extra CA, PEM; optional)
```

and the Vaultwarden **personal API key** (web vault: Settings, Security, Keys, View API key), as secrets:

```sh
FERROWARDEN_VAULT_CLIENT_ID_FILE=/run/secrets/bw_client_id          # user.<uuid>
FERROWARDEN_VAULT_CLIENT_SECRET_FILE=/run/secrets/bw_client_secret
```

(`FERROWARDEN_VAULT_CLIENT_ID` and `FERROWARDEN_VAULT_CLIENT_SECRET` also work; a direct variable wins over its `_FILE`.) The secret files keep the names `bw_client_id` and `bw_client_secret` from earlier releases, so an existing `secrets/` directory works unchanged. The values never come from `ferrowarden.toml`. If either is missing, startup fails with a message that names both variables and `vault.url`.

- `unlock_mode` and `unlock_file` work exactly as before: **file mode** logs in, syncs and unlocks at startup and again when the vault locks; **manual mode** waits for `POST /v1/unlock` (or the admin UI) to supply the master password.
- `vault.backend` accepts `native` only. `vault.backend = "bw-serve"` (or `FERROWARDEN_VAULT__BACKEND=bw-serve`) is a **startup error**, never a silent fallback. A leftover `bw_serve_url` (or `FERROWARDEN_BW_SERVE_URL`) is ignored, with a warning at startup.
- `vault.url` and `vault.ca_file` are *the* setting for how Ferrowarden reaches Vaultwarden. They replace `ui.vaultwarden_url` and `ui.vaultwarden_ca_file`, which still work as deprecated aliases (a warning is logged; if both are set and differ, `vault.*` wins). `vault.url` must be `https://` (plain `http://` only for loopback hosts, for tests). Certificate verification is never switched off.
- `vault.allow_hidden_passwords` (`FERROWARDEN_VAULT__ALLOW_HIDDEN_PASSWORDS`, default `false`): see [Hidden passwords](#hidden-passwords-collections-that-hide-them).
- `vault.managed.collection` (`FERROWARDEN_VAULT__MANAGED__COLLECTION`, default unset): the one collection Ferrowarden may create items in, by id or by name. Unset, Ferrowarden never writes. See [The write path](#the-write-path-and-the-managed-collection).
- The startup event, `GET /v1/admin/status`, the `ferrowarden_build_info` metric and the admin UI's status page report the backend as `vault_backend`. The value is always `native` now; the field stays so that dashboards and SIEM rules keep working.
- In file unlock mode one process holds both the API key and the master password. Manual unlock is the hardened option: see [security.md](security.md#native-backend-one-process-holds-both-secrets).

## Upgrading from bw-serve

0.3.0 removes the `bw-serve` backend, its Compose override and the `bw_serve_url` setting. If you moved to the native backend with 0.2.0 (the default there), there is nothing to do.

If you were still on `bw-serve` in 0.2.0 (you used `docker-compose.bw-serve.yml`, or set `vault.backend = "bw-serve"`):

1. **Move to native on 0.2.0 first.** Follow the 0.2.0 upgrade steps ([release-notes/v0.2.0.md](release-notes/v0.2.0.md#upgrading)): stop using the override file, `chown 999:999` the API key files (`secrets/bw_client_id`, `secrets/bw_client_secret`), and set `vault.url` if Vaultwarden is not at `https://vaultwarden` (that is, you run outside the bundled Compose file). Check that the vault loads and your agents work.
2. **Then upgrade to 0.3.0.** Remove `vault.backend = "bw-serve"` from `ferrowarden.toml` and `FERROWARDEN_VAULT__BACKEND` from the environment (or set it to `native`), and delete `bw_serve_url` / `FERROWARDEN_BW_SERVE_URL`.
3. **Remove the `bw-data` volume** once nothing uses it: `docker volume rm <project>_bw-data` (list the volumes with `docker volume ls`). It held only the Bitwarden CLI's local login state, which nothing reads any more. Take the same care as with any volume: do not remove `vaultwarden-data`, which is your vault. Neither back end stores anything else between runs, so there is nothing to migrate.

Starting 0.3.0 with `vault.backend = "bw-serve"` set fails with an error that points here; it does not fall back to native.

## How it works

1. **Login.** `POST /identity/connect/token` with `grant_type=client_credentials`, `scope=api`, a fixed per-key `device_identifier` (UUID v5 of a constant and `ferrowarden-vault:<client_id>`, so Vaultwarden keeps one device row), and `Bitwarden-Client-Name` / `Bitwarden-Client-Version` headers. The version, `2024.12.0`, is the **protocol version Ferrowarden implements**, not a claim to be that client: Vaultwarden includes SSH-key items in the sync only from that version on, which keeps the item list the same as the CLI's. API-key login returns no refresh token, so Ferrowarden logs in again shortly before `expires_in` and when a request gets a 401.
2. **Sync.** `GET /api/sync?excludeDomains=true` returns the account's keys and every item as ciphertext. Ferrowarden keeps the items exactly as received.
3. **Unlock.** The master password goes through the account's KDF (PBKDF2 or Argon2id, with the same bounds as the admin UI: a hostile server cannot make Ferrowarden burn minutes of CPU or gigabytes of memory), on a blocking thread. HKDF-Expand stretches the master key into an `enc` and a `mac` key, which decrypt the **user key** (`profile.key`). The user key decrypts the **RSA private key**, which unwraps each **organisation key**. The master password and master key are wiped as soon as the user key exists; they are not kept.
4. **Metadata.** For each login or secure note, Ferrowarden decrypts only what the credential map needs: the name, the URIs (and their match types), custom field names and kinds, and the values of the two reserved fields, `ferrowarden_uris` and `ferrowarden_approval`. Which secrets exist (password, username, TOTP, notes) is read from the presence of the ciphertext, not from decrypting it.
5. **Values on demand.** When a request needs a secret, Ferrowarden decrypts that one value into a `Zeroizing<String>`, substitutes it, and drops (wipes) it. TOTP codes are computed from the stored secret at that moment. There is no "fetch the whole item and wipe the rest" step.
6. **Refresh.** On every refresh tick: log in again if the token is about to expire, ask `GET /api/accounts/revision-date`, and fetch the full vault only when the revision changed (plus a periodic safety sync every ten ticks, at least every five minutes). If Vaultwarden is unreachable, Ferrowarden keeps serving the copy in memory and emits the usual `vault_sync` failure event.
7. **Lock.** A changed user key (`profile.key`) or `securityStamp` means the password was changed or the keys rotated: the keys in memory no longer match the account, so the vault locks (cause `vault_key_changed` or `security_stamp_changed`), dropping every key and the credential map; in file mode Ferrowarden then unlocks again from the password file.

## Reserved custom fields

Three custom fields are Ferrowarden's own, not offered as fields (a placeholder cannot name them, and they are not in the credential listing):

| Field | Value | Effect |
|---|---|---|
| `ferrowarden_uris` | URIs, comma- or newline-separated | The item's host bindings; overrides a login's URIs and gives secure notes a binding |
| `ferrowarden_approval` | `required` | A person has to approve use of the item ([approvals.md](approvals.md)). **Any other value, empty included, also means required**: a typo can only make the item stricter. Items whose value is not `required` are counted in the `vault_sync` event (`warnings.approval_field_invalid`) |
| `ferrowarden_created_by` | the name of an agent key | Written by Ferrowarden on an item it created ([managed-credentials.md](managed-credentials.md)): which key asked for it. A plain text field. Ferrowarden never reads it as a setting; it is reserved so that nobody names a field of their own that way |

## The write path and the managed collection

Ferrowarden writes in exactly one situation: an agent key asked to **create a credential** and a human approved that one operation ([managed-credentials.md](managed-credentials.md)). The code is small and kept apart (`src/vault/native/write.rs`, with the encryption in `enc.rs`); nothing else in the backend writes, rotates, edits or deletes.

**Where.** `vault.managed.collection` names one organisation collection. On every unlock and sync Ferrowarden reads the account's `collections` from `/api/sync` (id, organisation, name, and the account's own `readOnly` and `hidePasswords` flags; each item's `collectionIds` are read too, to count the items in it) and decides whether the collection is **usable**: it exists, `readOnly` is `false`, `hidePasswords` is `false` (a flag the server did not send counts against it) and the organisation key is available. Names are decrypted with the organisation key; a name that matches more than one collection is an error (use the id). The request for a write takes its target from this evaluated state and from nothing the agent sent, so it cannot name another collection. When the collection is not usable, nothing is written: no fallback to another collection or to the personal vault.

**What is written.** A Login (type 1) with its **own 64-byte item key**, from the operating system's random generator. Every encrypted field uses the item key (name, username, password, each URI and its checksum, each custom field's name and value). The item key is wrapped (EncString type 2) under the **organisation key** of the collection's organisation. The URI checksum is `base64(SHA-256(uri))`, encrypted like the URI, as web vaults write it. The item has `notes: null`, `favorite: false`, `reprompt: 0`, no TOTP, `ferrowarden_created_by`, and `ferrowarden_approval` when asked. It is sent as `POST /api/ciphers/create` with `{ cipher, collectionIds: [<the managed collection>] }` and the session's bearer token. A rejected token (`401`) is retried once with a fresh login; a timeout or a server error is not retried, because it may have been applied.

**Encryption.** EncString type 2 is the only format Ferrowarden writes: a fresh random 16-byte IV for every value, AES-256-CBC with PKCS#7 padding, and HMAC-SHA256 over `iv || ciphertext` with the MAC key, written `2.<base64 iv>|<base64 ct>|<base64 mac>`. Keys are 64 bytes, wiped when dropped. Plaintext buffers are wiped too. The generated password is a `Zeroizing<String>` that moves into the encryption and is dropped there.

**How it is verified.**

- **Known answers.** The type 2 encryption reproduces, byte for byte, the vectors `testdata/vectors.json` holds for fixed keys and IVs (empty, ASCII, an exact multiple of the block size, one over, multi-byte UTF-8 and a long value), which were generated with Node's `crypto` module. Encrypting and decrypting round-trips for the same shapes.
- **The shape.** A unit test builds an item and decrypts every field back with the item key, the item key with the organisation key, and checks the URI checksums and that nothing readable is in the body. The mock-server tests check the request: the path, the one collection in `collectionIds`, the bearer token, the single retry.
- **Cross-reading.** The integration suite creates an item through Ferrowarden against a real Vaultwarden, then an **independent reader** (`docker/bw-read-item.js`: Node's `crypto` and `docker/bw-lib.js`, no Rust) logs in as the account, finds the item in `/api/sync`, decrypts it, and prints the username, the URIs, whether the checksums verify and the field names. The test gives it the value the target service received on stdin, and the reader says only whether the stored password is the same (a constant-time comparison); the password is never printed or hashed. This runs against both Vaultwarden versions in CI.
- **Provenance.** Written from the item format and the primitives, as the reading side is. No Bitwarden SDK or client code is used or copied; `docker/bw-seed.js`, a Node writer of the same format for the test stack, was read to understand the wire format and the Rust was written independently.

**Trust.** The write path asks for one thing it did not need before: the Ferrowarden account has **edit rights on the managed collection** (an organisation owner or admin, or a member with "Can edit" on it). See [security.md](security.md#22-generated-credentials-and-the-managed-collection).

## Fail closed, per item

An item is **left out** of the credential map, with a counted reason, if anything needed to read it cannot be read safely. It is never read with a weaker method.

| Reason code | Cause |
|---|---|
| `unsupported_encstring_type` | An EncString of a type outside the allow-list (below) |
| `malformed_encstring` | Bad layout, bad or non-canonical base64, wrong IV/MAC/ciphertext length |
| `mac_failure` | The MAC does not verify: altered data or the wrong key |
| `bad_key_length` | A per-item key that is not exactly 64 bytes |
| `missing_org_key` | The item belongs to an organisation whose key could not be unwrapped |
| `item_key_undecryptable` | The item's own key could not be unwrapped |
| `invalid_utf8` | Decrypted text that is not UTF-8 |
| `hidden_password` | The item's collection hides passwords from this account and `vault.allow_hidden_passwords` is off ([below](#hidden-passwords-collections-that-hide-them)) |
| `decrypt_failure`, `missing_name`, `malformed_item` | Padding failure, no name, an unreadable structure |

One `vault_sync` event per sync carries the counts by reason and up to 20 item **ids** (random UUIDs: never names or values). A user key whose MAC fails is not an item problem: it is an unlock failure (`vault_unlock` with reason `unlock_failed`), because it means the wrong password or an altered key.

## Hidden passwords: collections that hide them

An organisation collection can be shared with a member as **"Hide passwords"**: the member can use the item but is not meant to see its password. Vaultwarden then marks the item `viewPassword: false` in that member's sync. Ferrowarden holds the account's keys and would hand the password to an agent, which the collection's owner chose to keep from this account. So the default is to refuse:

- An item with `viewPassword: false` is **left out** (reason `hidden_password` in the `vault_sync` event, with the count and the item ids, never a name or a value; also counted in `ferrowarden_vault_excluded_items`). It is not listed by `/v1/credentials`, the MCP server or the policy preview, and a placeholder naming it fails like an unknown item. Only an explicit `false` counts: an item without the field (an older server) is not affected.
- **`vault.allow_hidden_passwords = true`** (`FERROWARDEN_VAULT__ALLOW_HIDDEN_PASSWORDS`, default `false`) is the opt-in for operators who want the account's agents to use such items anyway. Ferrowarden logs a warning at startup, and the `startup` event records `vault_allow_hidden_passwords`.

## Supported formats

| EncString type | Algorithm | Accepted |
|---|---|---|
| 2 | AES-256-CBC with PKCS#7, HMAC-SHA256 MAC (checked, in constant time, **before** decrypting) | yes: every value and key encrypted with a symmetric key |
| 3 | RSA-OAEP, SHA-256 | yes, for RSA-encrypted keys only |
| 4 | RSA-OAEP, SHA-1 | yes, for RSA-encrypted keys only (what clients write for organisation keys) |
| 0 | AES-256-CBC, no MAC | **never**: unauthenticated |
| 1, 5, 6 | removed or deprecated | refused |
| 7 and newer | COSE (XChaCha20-Poly1305, "V2" accounts) | refused (not implemented) |

The type number decides the algorithm; nothing is guessed from the shape of the data. Keys must be exactly 64 bytes (32 for AES, 32 for HMAC): a 32-byte legacy key is refused. The RSA key must be PKCS#8, 2048 to 4096 bits.

| Item type | Offered | Notes |
|---|---|---|
| Login (1) | yes | username, password, TOTP, notes, custom fields |
| Secure note (2) | yes | notes, custom fields, bindings through `ferrowarden_uris` |
| Card (3), identity (4), SSH key (5) | no | parsed enough to know they exist |
| In the trash (`deletedDate`) | no | |
| Archived (`archivedDate`) | no | |
| Organisation items, with or without a per-item key | yes | except items whose collection hides passwords from the account (`viewPassword = false`): left out unless `vault.allow_hidden_passwords` is on, see below |

**Format drift.** A client format Ferrowarden does not know is not guessed at: the affected items are excluded and counted in the `vault_sync` event, so a newer client writing a new format shows up as a number to investigate rather than as a silent failure or a weaker decryption. Every other item keeps working.

TOTP: RFC 6238 with SHA-1, SHA-256 or SHA-512; `otpauth://` URIs (`algorithm`, `digits` 1 to 10, `period` above 0), bare base32 secrets (case-insensitive; spaces and `=` ignored) and `steam://`. A specification that cannot produce a code behaves like a missing TOTP (the placeholder fails with "not found").

## How formats are verified

The native backend implements the protocol itself, so nothing else vouches for what it reads. Four checks stand in for an independent reference implementation:

- **Known-answer vectors.** `src/vault/native/testdata/vectors.json` holds vectors for the key hierarchy and EncStrings, generated independently with Node's `crypto` module (`tests/native-vectors/gen.js`), and the unit tests check the Rust code against them. TOTP is checked against the RFC 6238 test vectors.
- **A vault written by a real web vault.** `src/vault/native/testdata/webvault/` is a capture from the web vault bundled with Vaultwarden, covering formats our own seeder does not write (see [below](#a-vault-written-by-the-web-vault)). **Recapture it on each Vaultwarden minor release**: create a throwaway account in the web vault that release bundles, add one of each item type, and save the prelogin, token and sync responses (the capture steps are in the [README](../src/vault/native/testdata/README.md)). If the new release writes something Ferrowarden does not read, the unit test that unlocks the capture fails by item name.
- **Fail-closed exclusion counts.** An item Ferrowarden cannot read safely is left out and counted per reason ([above](#fail-closed-per-item)), never read with a weaker method, so a format that drifts shows up as a number in the `vault_sync` event and in `ferrowarden_vault_excluded_items`, not as a wrong value.
- **Two Vaultwarden versions in CI.** The whole integration suite runs against the current release and the previous minor ([below](#tested-vaultwarden-versions)), with a PBKDF2 and an Argon2id account.

The integration suite also checks the seeded fixture vault end to end. The fixtures (`tests/seed/credentials.json`, written by `docker/bw-seed.js` with Node's `crypto`) cover per-item keys, an organisation with a collection, organisation items with and without per-item keys, card/identity/SSH items, a custom-field mix of every kind, URI match types, TOTP in all three shapes (SHA-256 with 8 digits and a 60 second period, Steam, a bare secret with spaces), and edge cases: a whitespace-only password, an empty-string username, an item without URIs, Unicode and very long values, and an archived item. Two tests compare Ferrowarden with what the fixture files define, with no second implementation involved:

1. `GET /v1/credentials?detail=true` matches the seed data: names, kinds, placeholders, bindings and unavailable reasons.
2. **Every** placeholder the listing offers, forwarded to the mock API, delivers exactly the seeded value (a TOTP placeholder, the code for the seeded secret), and a set of deliberately bad placeholders fails the way it should. Values are compared in memory and never printed; a mismatch is reported by placeholder label only.

The fixture vault also has the **hidden-password** case: `docker/bw-seed-hidden.js` registers a second account that owns a second organisation, and shares one item (`tests/seed/hidden.json`) with the test account as an ordinary member whose collection has "Hide passwords" (owners and admins always see passwords, so the test account cannot be the owner). The suite asserts that the item is left out, counted in the metric and the sync event, and that its password is never released.

## Tested Vaultwarden versions

The native backend implements the protocol itself, so the Vaultwarden release matters. CI runs the whole stack (the integration suite, the MCP suite and the secret gate) against **two** releases ([cicd.md](cicd.md#vaultwarden-versions-in-ci)):

| Vaultwarden | Test account KDF |
|---|---|
| 1.37.5 (current) | PBKDF2-SHA256, 600 000 iterations |
| 1.36.0 (previous minor) | Argon2id, 64 MiB, 3 iterations, parallelism 4 |

The statement of support is: the current and the previous minor release. A newer Vaultwarden that changes the formats is first run against the stack, and the web-vault capture is recaptured.

## A vault written by the web vault

The fixtures above are written by our own seeder, so a format that only real clients write would not show up in them. `src/vault/native/testdata/webvault/` closes that gap: a throwaway account created **by hand in the web vault bundled with Vaultwarden 1.37.5**, with Argon2id (32 MiB, 6 iterations, parallelism 4), a login with TOTP and a custom field of every kind (text, hidden, checkbox, linked), an otpauth TOTP, a login bound elsewhere, a secure note bound through `ferrowarden_uris`, a card, an identity, an SSH key, an organisation with a collection holding a login and a note, a trashed item and an archived item. The token and `/api/sync` responses are kept verbatim (ciphertext only), and the expected values were read from the same account when it was captured (with the Bitwarden CLI 2026.11.0, run once by hand: no CLI is part of Ferrowarden or its CI). A unit test unlocks the capture with the native backend and checks every name, binding and value against that reference, and that cards, identities, SSH keys, trashed and archived items are not offered.

What the capture showed:

- Only EncString types 2 (items) and 4 (the organisation key). No type 7 (COSE) and no V2 key material. A second test fails by name if a future capture brings either.
- **Every** item has a per-item key, including organisation items.
- An emptied notes field is stored as `""`; Ferrowarden treats an empty value as absent (nothing to substitute).

`testdata/webvault-hidden/` is the same organisation seen by a second account that is an ordinary member of the collection with **"Hide passwords"**. Vaultwarden marks the items `viewPassword: false` but **still sends the password's ciphertext**: hiding is enforced by clients only, which is why the native backend refuses these items itself by default. Tests check that both items are left out by default (no value of any kind is released) and are usable, with the owner's values, when `vault.allow_hidden_passwords` is on.

Changing the KDF from the bundled web vault (Settings, Security, Keys) left two test accounts unable to sign in with their password afterwards; avoid doing that on a Vaultwarden 1.37.5 account you depend on until the cause is known.

## Provenance and licence

Ferrowarden is licensed under FSL-1.1-ALv2. The native backend is **implemented from the observed wire format** (what Vaultwarden sends and accepts) **and the published descriptions of the algorithms** (AES-CBC, HMAC, HKDF RFC 5869, RSA-OAEP, TOTP RFC 6238). It uses **no Bitwarden SDK crate and no code ported from one**: those are GPL-3.0 or under the Bitwarden SDK License, which is not compatible with Ferrowarden's licence. The known-answer test vectors were generated for this project with Node's `crypto` module (`tests/native-vectors/gen.js`), not taken from the SDK's tests. The cryptography uses RustCrypto crates, all MIT OR Apache-2.0:

| Crate | Use |
|---|---|
| `aes` 0.9, `cbc` 0.2 | AES-256-CBC |
| `hmac` 0.13, `sha2` 0.11, `sha1` 0.11 | MAC, HKDF, OAEP, TOTP |
| `hkdf` 0.13 | HKDF-Expand |
| `rsa` 0.10 | RSA-OAEP (0.10 or later: earlier releases carry RUSTSEC-2023-0071, the Marvin timing side channel) |
| `libc` 0.2 (Linux) | `PR_SET_DUMPABLE`, `RLIMIT_CORE` |

All are pure Rust (except the two `libc` calls) and build for the static musl image. See [security.md](security.md) for the security trade-offs of this back end.
